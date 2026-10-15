# DNS tracing

Podtrace captures DNS two ways, and uses both together:

1. **Packet capture (`cgroup_skb`)** — the primary, libc-independent path. podtrace
   attaches a `cgroup_skb` program to the traced pod's cgroup and parses DNS
   directly off the UDP packets (port 53). Because it reads the wire, it works
   regardless of how the workload resolves names:
   - glibc, musl, **statically-linked Go (the `netgo` resolver)**, distroless/scratch
   - IPv4 and IPv6
   This is what makes DNS visible for workloads the libc uprobe can never see
   (e.g. a static Go binary that never calls `getaddrinfo`).

2. **libc `getaddrinfo` uprobe** — a complementary "intent" source for glibc
   apps. Retained alongside packet capture.

The query is emitted as soon as it's seen on egress (event `DNS_QUERY`), so the
looked-up **name is captured even if the response is never matched** (sparse or
near-idle pods). The response (`DNS`) then enriches it with rcode, latency, and
resolved addresses. Lookups are counted from queries; they are not double-counted.

## What is captured

| Field | Source | Notes |
|---|---|---|
| Query name (QNAME) | egress query | the looked-up name |
| Query type (QTYPE) | egress query | A, AAAA, CNAME, SRV, PTR, TXT, … |
| Transport | egress | UDP or TCP |
| Upstream server | egress query | destination IP of the query (IPv4 or IPv6) |
| Response code (RCODE) | ingress response | `NOERROR` / **`NXDOMAIN`** / `SERVFAIL` / `REFUSED` / … |
| Resolution latency | query→response | the signal for "why is startup slow" |
| Timeout | userspace sweep | query with no response within 5s → `timed out` |
| Resolved addresses | ingress answers | A/AAAA records; also fed to connect correlation |
| CNAME | ingress answers | alias target for CNAME-only answers (truncated if compressed) |
| Connect correlation | TCP connect | a connect to a resolved IP is annotated with the name it came from |
| Encrypted DNS (DoT) | egress :853 | payload unparseable; reported as `encrypted (DoT)` |
| Encrypted DNS (DoH) | egress :443 | only flagged for known public DoH resolver IPs, v4 and v6 |
| Drops | metric | `podtrace_dns_drops_total` — in-flight map / ring buffer full (never silent) |

## How it shows up

```
[DNS] A example.com -> 93.184.216.34 (2.41ms)
[DNS] A doesnotexist.invalid failed: NXDOMAIN (1.10ms)
[DNS] encrypted query (DoT) to 10.0.0.10:853
[NET] connect to 93.184.216.34:443 (example.com)        # connect correlation
```

## Scope & limitations

- Attached **per traced pod cgroup**, so it only sees that pod's DNS (no node-wide noise).
- **No BTF or specific libc required** — packet bytes aren't kernel RAM, so the
  programs load with the committed stub `vmlinux.h` and are expected to work even
  under Talos `lockdown=confidentiality` (where most probes are denied).
- **UDP and TCP** on port 53 are parsed. TCP DNS is handled for single-segment
  messages; a DNS response split across TCP segments may be partially parsed.
- **EDNS(0)** larger responses are parsed up to ~2 KB into the packet.
- **IPv4 and IPv6 are at parity**: query names, rcode, AAAA-resolved addresses,
  the upstream-server field, resolved-IP↔connect correlation, and DoT/DoH
  detection all work over both. IPv6 extension headers (hop-by-hop, routing,
  fragment, dest-opts) are walked to find the L4 header; deeper/unusual chains
  beyond a few extension headers fall back to no-parse rather than guessing.
- **DoH (DNS-over-HTTPS, :443)** is flagged **only for well-known public DoH
  resolver IPs** (Cloudflare/Google/Quad9). General DoH is indistinguishable
  from HTTPS at the packet layer, so arbitrary :443 traffic is never labelled
  DNS (that would mislabel normal traffic).

## Configuration

- Packet capture is **on by default**. Set `PODTRACE_DNS_PACKET_CAPTURE=false`
  (or `TracerConfig.spec.agent.dnsPacketCapture: false`) to disable it and fall
  back to the libc uprobe only.
- Query names can be sensitive. They flow through the standard redaction rules;
  to redact the **name itself** (it would otherwise reach exporters), set
  `PODTRACE_REDACT_DNS_NAMES=true` — DNS events then show `[redacted]`, and so
  does the server name (SNI) of HTTP/3 connection events.
- Data loss is never silent: a full in-flight map or ring buffer increments
  `podtrace_dns_drops_total`.
