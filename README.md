# netdiag

Single-file Go tool to detect **ISP DNS rate limiting**, **CDN blacklisting** (Akamai, Cloudflare, Fastly, AWS CloudFront), and **network latency issues** affecting a home network.

Standard library only — no dependencies.

## Install

```bash
go install github.com/ResistanceIsUseless/netdiag@latest
```

Or clone and build:

```bash
git clone https://github.com/ResistanceIsUseless/netdiag.git
cd netdiag
go build -o netdiag .
```

Or run directly without installing:

```bash
go run netdiag.go
```

If you don't have Go installed: `brew install go`.

## Usage

```bash
netdiag                   # run all checks (DNS + CDN + latency)
netdiag -dns-only         # DNS rate-limit test only
netdiag -cdn-only         # CDN blacklist probes only
netdiag -latency-only     # TCP connect latency only
netdiag -burst 100        # override DNS burst size
netdiag -verbose          # show per-query details
```

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `-dns-only` | false | Run DNS rate-limit test only |
| `-cdn-only` | false | Run CDN blacklist probes only |
| `-latency-only` | false | Run TCP connect latency test only |
| `-burst N` | 50 | DNS queries per resolver in the burst test |
| `-timeout D` | 5s | Per-request timeout (e.g. `-timeout 10s`) |
| `-verbose` | false | Print every query/probe individually |

## What it detects

### DNS rate limiting

Bursts `-burst` DNS queries against your **system resolver** plus three public controls (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9). Flags your ISP resolver when:

- Failure rate is >5% absolute **and** >3x the median of the public controls, or
- Average latency is >3x the median of the public controls (when control median >10ms)

### CDN blacklisting

Issues `GET` requests to sites fronted by major CDNs with a realistic browser User-Agent. Flags:

- **403 Forbidden** — strongest signal of IP reputation block
- **429 Too Many Requests** — rate limited at edge
- **TCP reset** — hard block at network layer
- **TLS handshake failure** — WAF-level block
- **Challenge/block page signatures** in response body (Cloudflare `cf-error-details`, Akamai reference IDs, `"access denied"`, etc.)

Probed targets:
- **Akamai**: British Airways, IBM
- **Cloudflare**: cloudflare.com, Discord, Coinbase
- **Fastly**: fastly.com
- **AWS CloudFront**: aws.amazon.com
- **Google**: google.com

Also reports your egress IP (via `1.1.1.1/cdn-cgi/trace`) for manual blacklist lookups.

### TCP connect latency

Measures raw TCP handshake time (SYN -> SYN-ACK) to endpoints across multiple regions with 5 samples each. Reports min/avg/max/jitter and flags targets with jitter >50ms.

Targets:
- **Anycast**: Cloudflare (1.1.1.1), Google (8.8.8.8)
- **AWS regions**: us-east-1, eu-west-1, ap-southeast-1
- **Other**: Microsoft (Office 365), Akamai

## Sample output

```
netdiag - home network diagnostic
============================================================
Run time: 2026-04-21T10:15:00-07:00

System resolver (from OS): 192.168.1.1:53

[DNS] Rate-limit detection
------------------------------------------------------------
Burst size: 50 queries per resolver

Resolver             Address                      OK     Fail     AvgLat     MaxLat Flag
----------------------------------------------------------------------------------------------------
System (ISP)         192.168.1.1:53               32       18      847ms     4.1s   ! POSSIBLE RATE LIMIT
Cloudflare           1.1.1.1:53                   50        0       11ms      23ms
Google               8.8.8.8:53                   50        0       14ms      29ms
Quad9                9.9.9.9:53                   50        0       18ms      41ms

VERDICT: Your ISP resolver is behaving materially worse than public resolvers.

[CDN] Blacklist / reputation probe
------------------------------------------------------------
Egress IP (as seen by internet): 203.0.113.42

Target             Vendor       Status    Latency Notes
------------------------------------------------------------------------------------------
! Akamai (BA)       akamai          403      307ms 403 Forbidden (reputation block likely)
Cloudflare        cloudflare      200      351ms
...

VERDICT: Akamai-fronted site returned a suspicious response.

[LATENCY] TCP connect probe
------------------------------------------------------------
Samples per target: 5

Target               Address                                  Min      Avg      Max   Jitter
-----------------------------------------------------------------------------------------------
Cloudflare           1.1.1.1:443                             10ms     12ms     16ms      6ms
Google               8.8.8.8:443                              9ms     11ms     16ms      7ms
AWS us-east-1        ec2.us-east-1.amazonaws.com:443         68ms     75ms     95ms     27ms
...

VERDICT: TCP connect latency looks stable across all targets.
```

## Remediation

**DNS rate limiting:**
- Switch to `1.1.1.1` / `8.8.8.8` / `9.9.9.9`
- Consider DoH/DoT to prevent ISP inspection
- For high-volume use, run a local recursive resolver (Unbound, Pi-hole)

**CDN blacklisting:**
- Check your egress IP at abuseipdb.com, spamhaus.org
- Akamai: no public unblock portal — contact ISP for a new IP
- Cloudflare: blocks are per-site (configured by site owner), not always global
- Quick test: run through a VPN — if flags clear, it's IP-specific

**High latency/jitter:**
- Compare VPN vs direct to isolate ISP vs last-mile issues
- Check for bufferbloat with a speed test under load
- Jitter >50ms typically indicates congestion or unstable routing

## Limitations

- **macOS resolver detection** uses `scutil --dns` (correct source — `/etc/resolv.conf` is often stale on macOS)
- **Windows resolver detection is a stub** — falls back to `127.0.0.53:53`
- **No IPv6-specific path** — probes use whatever the OS picks
- **Not a blacklist database checker** — detects CDN-level blocks, prints your IP for manual RBL lookups
- **Polite burst size** — default 50 queries won't trigger abuse flags on public resolvers
