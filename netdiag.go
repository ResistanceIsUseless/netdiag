// netdiag - Home network diagnostic tool for DNS rate limiting and CDN blacklisting.
//
// Detects two primary issues:
//   1. ISP DNS rate limiting: compares your configured resolver's behavior under
//      burst load against public resolvers (Cloudflare, Google, Quad9).
//   2. CDN blacklisting: probes major CDN edges (Akamai, Cloudflare, Fastly, AWS)
//      for anomalous responses (403/429, TCP resets, TLS handshake failures) that
//      indicate your egress IP has been flagged.
//
// Usage:
//   go run netdiag.go                  # run all checks
//   go run netdiag.go -dns-only        # DNS checks only
//   go run netdiag.go -cdn-only        # CDN checks only
//   go run netdiag.go -burst 100       # override burst size for DNS rate-limit test
//   go run netdiag.go -verbose         # show per-query details
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- Configuration ----------

// Public resolvers used as the control group. If these behave fine under load
// but your ISP's resolver degrades, that's strong evidence of ISP-side limiting.
var publicResolvers = []resolver{
	{"Cloudflare", "1.1.1.1:53"},
	{"Google", "8.8.8.8:53"},
	{"Quad9", "9.9.9.9:53"},
}

// CDN probe targets. Each target hits a known host on a specific CDN so a
// 403/429/reset can be attributed to that CDN's reputation system rather than
// the origin. Hosts chosen because they're stable and don't require auth.
var cdnProbes = []cdnProbe{
	{"Akamai (BA)", "https://www.britishairways.com/", "akamai"}, // real-world Akamai customer
	{"Akamai (IBM)", "https://www.ibm.com/", "akamai"},           // IBM fronts via Akamai
	{"Cloudflare", "https://www.cloudflare.com/", "cloudflare"},
	{"Cloudflare (DC)", "https://www.discord.com/", "cloudflare"},   // Discord behind CF WAF
	{"Cloudflare (CEx)", "https://www.coinbase.com/", "cloudflare"}, // Coinbase behind CF WAF
	{"Fastly", "https://www.fastly.com/", "fastly"},
	{"AWS CloudFront", "https://aws.amazon.com/", "cloudfront"},
	{"Google", "https://www.google.com/", "google"},
}

// TCP latency probe targets. Mix of geographic regions and services to show
// network path quality. Port 443 is used because it's universally open and
// represents real browsing traffic paths.
var latencyTargets = []latencyTarget{
	{"Cloudflare", "1.1.1.1:443"},
	{"Google", "8.8.8.8:443"},
	{"AWS us-east-1", "ec2.us-east-1.amazonaws.com:443"},
	{"AWS eu-west-1", "ec2.eu-west-1.amazonaws.com:443"},
	{"AWS ap-south-1", "ec2.ap-southeast-1.amazonaws.com:443"},
	{"Microsoft", "outlook.office365.com:443"},
	{"Akamai", "a248.e.akamai.net:443"},
}

const latencySamples = 5 // TCP connects per target

// Domains used for DNS burst testing. Mix of popular + less-common to avoid
// pure cache-hit skew. Randomized subdomains would be more rigorous but also
// more likely to trip abuse heuristics on public resolvers — keep it polite.
var dnsTestDomains = []string{
	"google.com", "cloudflare.com", "amazon.com", "github.com",
	"wikipedia.org", "netflix.com", "apple.com", "microsoft.com",
}

// ---------- Types ----------

type resolver struct {
	name    string
	address string // host:port
}

type cdnProbe struct {
	name   string
	url    string
	vendor string
}

type latencyTarget struct {
	name    string
	address string // host:port
}

// dnsResult captures per-resolver outcomes from the burst test.
type dnsResult struct {
	name        string
	address     string
	successes   int
	failures    int
	totalLat    time.Duration
	maxLat      time.Duration
	errSamples  []string // first few error messages for diagnostic context
	rateLimited bool     // heuristic determination
}

// cdnResult captures the outcome of a single CDN probe.
type cdnResult struct {
	name       string
	vendor     string
	url        string
	statusCode int
	latency    time.Duration
	err        error
	suspicious bool   // flagged as likely blacklist/challenge
	reason     string // human-readable reason for suspicious flag
}

// ---------- Main ----------

func main() {
	var (
		dnsOnly     = flag.Bool("dns-only", false, "run DNS checks only")
		cdnOnly     = flag.Bool("cdn-only", false, "run CDN checks only")
		latencyOnly = flag.Bool("latency-only", false, "run latency checks only")
		burst       = flag.Int("burst", 50, "DNS queries per resolver in burst test")
		verbose     = flag.Bool("verbose", false, "show per-query detail")
		timeout     = flag.Duration("timeout", 5*time.Second, "per-request timeout")
	)
	flag.Parse()

	fmt.Println("netdiag - home network diagnostic")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Run time: %s\n\n", time.Now().Format(time.RFC3339))

	// Detect the system resolver up front so we can include it in DNS tests
	// and so the user sees what's actually being used.
	systemResolver := detectSystemResolver()
	fmt.Printf("System resolver (from OS): %s\n\n", systemResolver)

	only := *dnsOnly || *cdnOnly || *latencyOnly

	if !only || *dnsOnly {
		runDNSChecks(systemResolver, *burst, *timeout, *verbose)
		fmt.Println()
	}

	if !only || *cdnOnly {
		runCDNChecks(*timeout, *verbose)
		fmt.Println()
	}

	if !only || *latencyOnly {
		runLatencyChecks(*timeout, *verbose)
		fmt.Println()
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Done. See any flagged (!) items above for follow-up.")
}

// ---------- DNS Checks ----------

// runDNSChecks performs a burst of lookups against the system resolver and
// each public resolver in parallel, then compares error/latency profiles.
func runDNSChecks(systemResolver string, burst int, timeout time.Duration, verbose bool) {
	fmt.Println("[DNS] Rate-limit detection")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Burst size: %d queries per resolver\n\n", burst)

	// Assemble the full resolver list: system first, then public controls.
	resolvers := []resolver{{"System (ISP)", systemResolver}}
	resolvers = append(resolvers, publicResolvers...)

	results := make([]dnsResult, len(resolvers))
	var wg sync.WaitGroup

	// Run each resolver test concurrently — but serialize queries within a
	// single resolver so we're actually bursting *that* resolver rather than
	// hammering all of them in parallel with full concurrency.
	for i, r := range resolvers {
		wg.Add(1)
		go func(idx int, res resolver) {
			defer wg.Done()
			results[idx] = burstTestResolver(res, burst, timeout, verbose)
		}(i, r)
	}
	wg.Wait()

	// Apply rate-limit heuristics: flag the system resolver if it has
	// materially worse failure rate or latency than the public controls.
	applyRateLimitHeuristics(results)

	printDNSResults(results)
}

// burstTestResolver fires `burst` lookups against a single resolver,
// rotating through dnsTestDomains. Returns aggregate stats.
func burstTestResolver(r resolver, burst int, timeout time.Duration, verbose bool) dnsResult {
	// Build a net.Resolver that forces traffic through the specified server
	// rather than using the OS default. PreferGo=true ensures Go's resolver
	// is used (the cgo resolver won't honor our Dial override reliably).
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", r.address)
		},
	}

	out := dnsResult{name: r.name, address: r.address}

	for i := 0; i < burst; i++ {
		domain := dnsTestDomains[i%len(dnsTestDomains)]
		ctx, cancel := context.WithTimeout(context.Background(), timeout)

		start := time.Now()
		_, err := res.LookupHost(ctx, domain)
		lat := time.Since(start)
		cancel()

		if err != nil {
			out.failures++
			if len(out.errSamples) < 3 {
				out.errSamples = append(out.errSamples, fmt.Sprintf("%s: %v", domain, err))
			}
			if verbose {
				fmt.Printf("  [%s] %s -> ERR %v (%v)\n", r.name, domain, err, lat)
			}
		} else {
			out.successes++
			out.totalLat += lat
			if lat > out.maxLat {
				out.maxLat = lat
			}
			if verbose {
				fmt.Printf("  [%s] %s -> ok (%v)\n", r.name, domain, lat)
			}
		}
	}

	return out
}

// applyRateLimitHeuristics flags the system resolver as rate-limited if it
// performs materially worse than the public controls. We avoid false positives
// by requiring BOTH elevated failure rate AND degraded latency relative to the
// median public resolver.
func applyRateLimitHeuristics(results []dnsResult) {
	if len(results) < 2 {
		return
	}

	// First result is always the system resolver (see runDNSChecks).
	sys := &results[0]
	controls := results[1:]

	// Compute median control failure rate and average latency.
	var controlFailRates []float64
	var controlAvgLats []time.Duration
	for _, c := range controls {
		total := c.successes + c.failures
		if total == 0 {
			continue
		}
		controlFailRates = append(controlFailRates, float64(c.failures)/float64(total))
		if c.successes > 0 {
			controlAvgLats = append(controlAvgLats, c.totalLat/time.Duration(c.successes))
		}
	}
	if len(controlFailRates) == 0 {
		// Can't compare — probably no internet at all.
		return
	}

	sort.Float64s(controlFailRates)
	medianCtrlFail := controlFailRates[len(controlFailRates)/2]

	sort.Slice(controlAvgLats, func(i, j int) bool { return controlAvgLats[i] < controlAvgLats[j] })
	var medianCtrlLat time.Duration
	if len(controlAvgLats) > 0 {
		medianCtrlLat = controlAvgLats[len(controlAvgLats)/2]
	}

	sysTotal := sys.successes + sys.failures
	if sysTotal == 0 {
		return
	}
	sysFailRate := float64(sys.failures) / float64(sysTotal)
	var sysAvgLat time.Duration
	if sys.successes > 0 {
		sysAvgLat = sys.totalLat / time.Duration(sys.successes)
	}

	// Heuristic: system failures are 3x+ the public median AND >5% absolute,
	// OR system average latency is 3x+ the public median (and public median
	// was meaningful, i.e. >10ms). Tunable if you get false positives.
	failFlag := sysFailRate > 0.05 && sysFailRate > 3*medianCtrlFail
	latFlag := medianCtrlLat > 10*time.Millisecond && sysAvgLat > 3*medianCtrlLat

	sys.rateLimited = failFlag || latFlag
}

func printDNSResults(results []dnsResult) {
	fmt.Printf("%-20s %-22s %8s %8s %10s %10s %s\n",
		"Resolver", "Address", "OK", "Fail", "AvgLat", "MaxLat", "Flag")
	fmt.Println(strings.Repeat("-", 100))

	for _, r := range results {
		var avg time.Duration
		if r.successes > 0 {
			avg = r.totalLat / time.Duration(r.successes)
		}
		flag := ""
		if r.rateLimited {
			flag = "! POSSIBLE RATE LIMIT"
		}
		fmt.Printf("%-20s %-22s %8d %8d %10s %10s %s\n",
			r.name, r.address, r.successes, r.failures,
			truncateDuration(avg), truncateDuration(r.maxLat), flag)
		for _, sample := range r.errSamples {
			fmt.Printf("    err sample: %s\n", sample)
		}
	}

	// Write a plain-language verdict to save the user from interpreting numbers.
	fmt.Println()
	if results[0].rateLimited {
		fmt.Println("VERDICT: Your ISP resolver is behaving materially worse than public resolvers.")
		fmt.Println("         This is consistent with DNS rate limiting or resolver overload.")
		fmt.Println("         Workaround: configure 1.1.1.1 or 8.8.8.8 as your DNS server.")
	} else {
		fmt.Println("VERDICT: No obvious DNS rate limiting detected.")
	}
}

// ---------- CDN Checks ----------

// runCDNChecks probes each CDN target and flags suspicious responses that
// commonly indicate IP reputation blocks (403 Forbidden, 429 Too Many Requests,
// TCP resets, and certain challenge-page signatures).
func runCDNChecks(timeout time.Duration, verbose bool) {
	fmt.Println("[CDN] Blacklist / reputation probe")
	fmt.Println(strings.Repeat("-", 60))

	// Report egress IP first — a lot of CDN reputation is IP-scoped, and
	// knowing the IP makes remediation (e.g., filing unblock requests) possible.
	egressIP := fetchEgressIP(timeout)
	fmt.Printf("Egress IP (as seen by internet): %s\n\n", egressIP)

	results := make([]cdnResult, len(cdnProbes))
	var wg sync.WaitGroup

	// Probe CDNs concurrently — independent targets, no interference.
	for i, p := range cdnProbes {
		wg.Add(1)
		go func(idx int, probe cdnProbe) {
			defer wg.Done()
			results[idx] = probeCDN(probe, timeout, verbose)
		}(i, p)
	}
	wg.Wait()

	printCDNResults(results)
}

// probeCDN performs a GET on the given URL and classifies the response.
// We deliberately use a realistic User-Agent — a default Go UA gets more
// challenges from WAFs and would produce false positives.
func probeCDN(p cdnProbe, timeout time.Duration, verbose bool) cdnResult {
	out := cdnResult{name: p.name, vendor: p.vendor, url: p.url}

	// Dedicated transport so one probe's connection reuse doesn't mask another's
	// TCP reset. TLS config left at defaults — we want to see real failures.
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Don't follow redirects — a 301 to an error page would mask the
		// original status code we care about.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", p.url, nil)
	if err != nil {
		out.err = err
		return out
	}
	// Realistic browser UA to avoid bot-detection false positives.
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	start := time.Now()
	resp, err := client.Do(req)
	out.latency = time.Since(start)

	if err != nil {
		out.err = err
		// Classify connection-level failures. Resets and handshake failures
		// against major CDNs are unusual and worth flagging.
		msg := err.Error()
		switch {
		case strings.Contains(msg, "connection reset"):
			out.suspicious = true
			out.reason = "TCP reset (possible IP block)"
		case strings.Contains(msg, "tls:"):
			out.suspicious = true
			out.reason = "TLS handshake failure"
		case strings.Contains(msg, "timeout"):
			// Timeouts alone aren't definitive — could be local network issue.
			out.reason = "timeout (inconclusive)"
		}
		return out
	}
	defer resp.Body.Close()

	out.statusCode = resp.StatusCode

	// Read a small sample of the body for challenge-page signature detection.
	// 8KB is enough to catch Cloudflare/Akamai/Fastly challenge markers without
	// pulling an entire homepage.
	bodySample, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := strings.ToLower(string(bodySample))

	// Classify suspicious responses.
	switch {
	case resp.StatusCode == 403:
		out.suspicious = true
		out.reason = "403 Forbidden (reputation block likely)"
	case resp.StatusCode == 429:
		out.suspicious = true
		out.reason = "429 Too Many Requests (rate limited)"
	case resp.StatusCode >= 500 && resp.StatusCode < 600:
		// 5xx on a CDN edge isn't usually a reputation issue but is worth noting.
		out.reason = fmt.Sprintf("%d (CDN/origin error)", resp.StatusCode)
	case strings.Contains(bodyStr, "access denied") ||
		strings.Contains(bodyStr, "reference #") && strings.Contains(bodyStr, "akamai"),
		strings.Contains(bodyStr, "cf-error-details"),
		strings.Contains(bodyStr, "cloudflare") && strings.Contains(bodyStr, "blocked"),
		strings.Contains(bodyStr, "attention required"):
		out.suspicious = true
		out.reason = "challenge/block page in body"
	}

	return out
}

// fetchEgressIP hits a well-known IP echo service. Used only for informational
// display so the user can check their IP against blacklists themselves.
func fetchEgressIP(timeout time.Duration) string {
	client := &http.Client{Timeout: timeout}
	// Cloudflare's trace endpoint — returns plain text k=v lines, no parsing deps.
	resp, err := client.Get("https://1.1.1.1/cdn-cgi/trace")
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if err != nil {
		return "unknown (read failed)"
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimPrefix(line, "ip=")
		}
	}
	return "unknown (no ip field)"
}

func printCDNResults(results []cdnResult) {
	fmt.Printf("%-18s %-10s %8s %10s %s\n", "Target", "Vendor", "Status", "Latency", "Notes")
	fmt.Println(strings.Repeat("-", 90))

	suspicious := 0
	akamaiFlagged := false
	cloudflareFlagged := false
	for _, r := range results {
		status := fmt.Sprintf("%d", r.statusCode)
		if r.statusCode == 0 {
			status = "—"
		}
		note := r.reason
		if r.err != nil && note == "" {
			note = r.err.Error()
		}
		flag := ""
		if r.suspicious {
			flag = "! "
			suspicious++
			switch r.vendor {
			case "akamai":
				akamaiFlagged = true
			case "cloudflare":
				cloudflareFlagged = true
			}
		}
		fmt.Printf("%s%-17s %-10s %8s %10s %s\n",
			flag, r.name, r.vendor, status, truncateDuration(r.latency), note)
	}

	// Plain-language verdict — more useful than just numbers for triage.
	fmt.Println()
	switch {
	case akamaiFlagged && cloudflareFlagged:
		fmt.Println("VERDICT: Both Akamai and Cloudflare-fronted sites returned suspicious responses.")
		fmt.Println("         Your egress IP likely has broad reputation issues across multiple CDNs.")
		fmt.Println("         Remediation: contact your ISP to request a new IP, or use a VPN")
		fmt.Println("         as a quick test.")
	case akamaiFlagged:
		fmt.Println("VERDICT: Akamai-fronted site returned a suspicious response.")
		fmt.Println("         Your egress IP may be on an Akamai reputation list.")
		fmt.Println("         Remediation: contact your ISP to request a new IP, or use a VPN")
		fmt.Println("         as a quick test. Akamai does not offer direct unblock requests.")
	case cloudflareFlagged:
		fmt.Println("VERDICT: Cloudflare-fronted site returned a suspicious response.")
		fmt.Println("         Your egress IP may be flagged by Cloudflare's WAF/bot management.")
		fmt.Println("         Remediation: try a VPN to confirm it's IP-based. Cloudflare blocks")
		fmt.Println("         are per-site (configured by the site owner), not always global.")
	case suspicious > 0:
		fmt.Printf("VERDICT: %d CDN probe(s) flagged. Your IP may have reputation issues.\n", suspicious)
		fmt.Println("         Check the notes column for specifics.")
	default:
		fmt.Println("VERDICT: No CDN blacklisting detected. All probes returned normal responses.")
	}
}

// ---------- Latency Checks ----------

// latencyResult captures TCP connect timing for a single target.
type latencyResult struct {
	name    string
	address string
	samples []time.Duration
	err     error
}

func (r latencyResult) min() time.Duration {
	if len(r.samples) == 0 {
		return 0
	}
	m := r.samples[0]
	for _, s := range r.samples[1:] {
		if s < m {
			m = s
		}
	}
	return m
}

func (r latencyResult) max() time.Duration {
	var m time.Duration
	for _, s := range r.samples {
		if s > m {
			m = s
		}
	}
	return m
}

func (r latencyResult) avg() time.Duration {
	if len(r.samples) == 0 {
		return 0
	}
	var total time.Duration
	for _, s := range r.samples {
		total += s
	}
	return total / time.Duration(len(r.samples))
}

func (r latencyResult) jitter() time.Duration {
	if len(r.samples) < 2 {
		return 0
	}
	return r.max() - r.min()
}

// runLatencyChecks performs multiple TCP connect probes to each target and
// reports min/avg/max/jitter to characterize network path quality.
func runLatencyChecks(timeout time.Duration, verbose bool) {
	fmt.Println("[LATENCY] TCP connect probe")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Samples per target: %d\n\n", latencySamples)

	results := make([]latencyResult, len(latencyTargets))
	var wg sync.WaitGroup

	for i, t := range latencyTargets {
		wg.Add(1)
		go func(idx int, target latencyTarget) {
			defer wg.Done()
			results[idx] = probeLatency(target, timeout, verbose)
		}(i, t)
	}
	wg.Wait()

	printLatencyResults(results)
}

// probeLatency performs latencySamples sequential TCP connects to the target,
// measuring only the handshake time (SYN -> SYN-ACK).
func probeLatency(t latencyTarget, timeout time.Duration, verbose bool) latencyResult {
	out := latencyResult{name: t.name, address: t.address}

	for i := 0; i < latencySamples; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", t.address, timeout)
		elapsed := time.Since(start)

		if err != nil {
			if i == 0 {
				// If the first attempt fails, record the error and bail —
				// no point retrying a host that's unreachable.
				out.err = err
				return out
			}
			if verbose {
				fmt.Printf("  [%s] sample %d -> ERR %v\n", t.name, i+1, err)
			}
			continue
		}
		conn.Close()
		out.samples = append(out.samples, elapsed)

		if verbose {
			fmt.Printf("  [%s] sample %d -> %s\n", t.name, i+1, elapsed.Round(time.Millisecond))
		}

		// Small pause between samples to avoid tripping rate limits.
		if i < latencySamples-1 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	return out
}

func printLatencyResults(results []latencyResult) {
	fmt.Printf("%-20s %-35s %8s %8s %8s %8s\n",
		"Target", "Address", "Min", "Avg", "Max", "Jitter")
	fmt.Println(strings.Repeat("-", 95))

	highJitter := false
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("%-20s %-35s %s\n", r.name, r.address, r.err)
			continue
		}
		if len(r.samples) == 0 {
			fmt.Printf("%-20s %-35s no successful samples\n", r.name, r.address)
			continue
		}
		flag := ""
		if r.jitter() > 50*time.Millisecond {
			flag = " !"
			highJitter = true
		}
		fmt.Printf("%-20s %-35s %8s %8s %8s %8s%s\n",
			r.name, r.address,
			truncateDuration(r.min()),
			truncateDuration(r.avg()),
			truncateDuration(r.max()),
			truncateDuration(r.jitter()),
			flag)
	}

	fmt.Println()
	if highJitter {
		fmt.Println("VERDICT: Some targets show high jitter (>50ms), indicating inconsistent")
		fmt.Println("         network path quality. This can cause buffering and slow page loads.")
	} else {
		fmt.Println("VERDICT: TCP connect latency looks stable across all targets.")
	}
}

// ---------- Helpers ----------

// detectSystemResolver returns the OS-configured nameserver as host:port.
//
// Platform handling:
//   - macOS:   uses `scutil --dns` because /etc/resolv.conf on macOS is often
//              stale or misleading (System Configuration framework is the real
//              source of truth). We parse the first "nameserver[0]" from the
//              primary resolver (resolver #1 in scutil output).
//   - Linux/*BSD: parses /etc/resolv.conf directly.
//   - Windows: STUB — falls through to a sensible default. Would need `netsh`
//              or the IP Helper API (GetAdaptersAddresses) for real detection.
func detectSystemResolver() string {
	if runtime.GOOS == "darwin" {
		if ns := detectSystemResolverDarwin(); ns != "" {
			return ns
		}
		// Fall through to resolv.conf as a backup — sometimes useful, often not.
	}

	// Linux, BSDs, and macOS fallback.
	data, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver ") {
				ns := strings.TrimSpace(strings.TrimPrefix(line, "nameserver"))
				if !strings.Contains(ns, ":") {
					ns += ":53"
				}
				return ns
			}
		}
	}
	// systemd-resolved stub address — harmless fallback on unknown systems.
	return "127.0.0.53:53"
}

// detectSystemResolverDarwin shells out to `scutil --dns` and extracts the
// first nameserver from the primary resolver block. Returns "" on any failure
// so the caller can fall back to resolv.conf parsing.
//
// Sample scutil output (abbreviated):
//   resolver #1
//     nameserver[0] : 192.168.1.1
//     nameserver[1] : 8.8.8.8
//     flags    : Request A records, Request AAAA records
//   resolver #2
//     domain   : local
//     ...
//
// We only care about resolver #1's first nameserver — that's what macOS uses
// for normal hostname lookups.
func detectSystemResolverDarwin() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		return ""
	}

	// Walk the output: track whether we're in resolver #1, and return the
	// first nameserver[N] line we see within it.
	inPrimary := false
	for _, rawLine := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "resolver #") {
			// Enter primary resolver on #1; any other resolver ends our search window.
			inPrimary = (line == "resolver #1")
			continue
		}
		if !inPrimary {
			continue
		}
		// Format: "nameserver[0] : 192.168.1.1"
		if strings.HasPrefix(line, "nameserver[") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			ns := strings.TrimSpace(parts[1])
			if ns == "" {
				continue
			}
			if !strings.Contains(ns, ":") {
				ns += ":53"
			}
			return ns
		}
	}
	return ""
}

// truncateDuration rounds to milliseconds for readable output.
func truncateDuration(d time.Duration) string {
	if d == 0 {
		return "—"
	}
	return d.Round(time.Millisecond).String()
}
