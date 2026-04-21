# netdiag

Single-file Go tool to detect **ISP DNS rate limiting** and **CDN blacklisting** (Akamai, Cloudflare, Fastly, AWS CloudFront) affecting a home network.

Standard library only — no dependencies.

## Build & run

On macOS (Apple Silicon or Intel):

```bash
go build -o netdiag netdiag.go
./netdiag
```

Or run directly without building:

```bash
go run netdiag.go
```

If you don't have Go installed: `brew install go`.

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `-dns-only` | false | Skip CDN probes, run DNS rate-limit test only |
| `-cdn-only` | false | Skip DNS burst, run CDN probes only |
| `-burst N` | 50 | DNS queries per resolver in the burst test |
| `-timeout D` | 5s | Per-request timeout (e.g. `-timeout 10s`) |
| `-verbose` | false | Print every DNS query and CDN probe individually |

## What it actually detects

### DNS rate limiting
Runs a burst of `-burst` DNS queries in parallel against four resolvers — your **system resolver** (read from `/etc/resolv.conf`) plus three public controls: **Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9**.

The heuristic flags your ISP resolver when **either**:
- Failure rate is >5% absolute **and** >3× the median of the public controls, or
- Average latency is >3× the median of the public controls (only when the control median is meaningful, >10ms).

Both conditions require the public resolvers to be healthy — if everything fails, the tool reports that rather than a false positive.

### CDN blacklisting
Issues one `GET` per CDN target with a realistic browser User-Agent (default Go UA triggers too many bot challenges). Flags:

- **403 Forbidden** — strongest signal of reputation block
- **429 Too Many Requests** — rate limited at edge
- **TCP reset on connection** — hard block at network layer
- **TLS handshake failure** — less common but happens with some WAFs
- **Challenge/block page signatures** in the response body (`"access denied"`, Cloudflare `cf-error-details`, Akamai reference IDs, etc.)

Also fetches your egress IP from `1.1.1.1/cdn-cgi/trace` so you can check it against third-party blacklist databases (Spamhaus, AbuseIPDB, Project Honeypot).

## Sample output structure

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
         This is consistent with DNS rate limiting or resolver overload.
         Workaround: configure 1.1.1.1 or 8.8.8.8 as your DNS server.
```

## Remediation guidance

**If DNS rate limiting is confirmed:**
- Switch your router or devices to `1.1.1.1` / `8.8.8.8` / `9.9.9.9`
- Consider DoH/DoT to prevent ISP-level inspection or meddling
- For high-volume use, run a local recursive resolver (Unbound, Pi-hole)

**If CDN blacklisting is detected:**
- Your egress IP is printed at the top of the CDN section — feed it into `abuseipdb.com`, `spamhaus.org`, and the CDN's own lookup if available
- Akamai: no public unblock portal — contact your ISP for a new IP assignment
- Cloudflare: some blocks are origin-configured, not reputation; try other Cloudflare sites
- If multiple CDNs flag the same IP, reputation issue is upstream (ISP or prior tenant)
- Quick test: run the tool through a VPN — if all flags clear, it's IP-specific

## Scope limitations (called out explicitly)

- **macOS resolver detection** uses `scutil --dns` (the correct source on macOS — `/etc/resolv.conf` is often stale there). Requires `scutil` to be on PATH, which it is by default on every macOS install.
- **Windows resolver detection is a stub.** Code falls back to `127.0.0.53:53` and still runs public-resolver comparisons, but won't identify the actual Windows-configured resolver. Adding this would require `netsh` shell-out or the IP Helper API.
- **No IPv6-specific path.** Probes use whatever the OS picks. If you want explicit v4 vs v6 comparison, that's a future extension.
- **Not a blacklist checker.** The tool tells you *whether* you're being treated as blocked by a given CDN — it does not query RBLs directly. The egress IP is printed so you can do that lookup yourself.
- **Polite burst size.** Default 50 queries is low enough that public resolvers won't flag you as abusive. If you want to be more aggressive, `-burst 500` is fine against your own ISP but not recommended against the public controls.

## Files

- `netdiag.go` — the entire tool, single file
- `README.md` — this document
