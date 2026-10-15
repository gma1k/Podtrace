# HTTP/3 (QUIC) tracing

podtrace traces HTTP/3 at two layers:

1. **Connection layer (all stacks).** A `cgroup_skb` program captures the
   client's first Initial packets (up to 3 per flow) on egress and ingress.
   Userspace derives the Initial keys from the Destination Connection ID
   (RFC 9001 / RFC 9369), decrypts them, and reassembles the ClientHello
   across packets — necessary because quic-go deliberately splits it mid-SNI
   across two Initials as an anti-DPI measure — yielding the peer address,
   **SNI**, and **ALPN** for every QUIC v1 and v2 connection, regardless of
   the application's HTTP/3 library.
2. **Transaction layer (library adapters).** Method, path, status, latency,
   traceparent, and allowlisted headers require hooks inside the HTTP/3
   library, because passive QPACK decode is impossible (encrypted transport +
   connection-scoped dynamic table). podtrace ships adapters for **quic-go**
   (full, paired transactions), **nghttp3**, and **quiche (C FFI)** (both
   experimental, unpaired events).

## Coverage matrix

| Stack | Connection + SNI/ALPN | Method/path/status | Latency | traceparent | Header allowlist |
|---|---|---|---|---|---|
| quic-go via `net/http` | yes | yes | yes | yes (both directions) | yes |
| quic-go `http3.Transport` / `http3.ClientConn` direct | yes | yes | yes | yes | yes |
| quic-go `http3.Server` handlers | yes | yes | yes | yes (inbound) | yes |
| nghttp3 (curl, ngtcp2 ecosystem) | yes | requests: method/path · responses: status | yes (TTFB pairing) | requests only | yes |
| quiche via C FFI (nginx-quiche builds, FFI consumers) | yes | requests: method/path · responses: status | yes (TTFB pairing) | requests only | yes |
| nginx (own stack), Chrome, quiche (Rust crate), msquic, Envoy | yes | no | no | no | no |

Notes:

- **quic-go client hook** attaches to `http3.(*ClientConn).RoundTrip` (falling
  back to `SingleDestinationRoundTripper`/`Transport` for older quic-go), so
  direct users of the quic-go APIs are captured, including 0-RTT requests
  (`http3.MethodGet0RTT`). Only the raw `RequestStream` API
  (`SendRequestHeader`/`ReadResponse`) bypasses L7 capture.
- **nghttp3 adapter** hooks `nghttp3_conn_submit_request` /
  `nghttp3_conn_submit_response` / `nghttp3_conn_read_stream`; the **quiche
  adapter** hooks `quiche_h3_send_request` / `quiche_h3_send_response` /
  `quiche_h3_conn_poll` (C FFI only). Header contents of the opposite
  direction arrive via application callbacks uprobes cannot observe, but the
  public inbound entry points pair streams by time: client transactions
  carry time-to-first-byte latency (without a response status), and server
  responses carry request-arrival-to-response latency (without the request's
  method/path).
- **msquic has no HTTP/3 layer to hook**: it is a QUIC-only library with a
  function-table API; HTTP/3 framing lives in its callers (e.g. .NET managed
  code), so only connection-layer visibility is possible.
- **Symbol resolution** for quic-go uses `.gopclntab` (works on stripped
  binaries); struct field offsets and the peer walk (below) prefer DWARF with
  a build-id / `.gnu_debuglink` debug-file fallback.

## L7 peer attribution

HTTP/3 transaction events carry the connection's remote address, read by
walking DWARF-resolved struct offsets from the hooked receiver to quic-go's
`net.UDPAddr`. This feeds the same "L7 peers" report section as HTTP/1.x and
HTTP/2 (which fuse the 4-tuple from the kernel socket instead — impossible for
QUIC, where one UDP socket multiplexes many connections in userspace). If the
binary has no DWARF and no debug file, or uses an unsupported quic-go layout,
transactions still flow — only the peer fields stay empty.

Per-pid BPF maps (field offsets, peer paths) are keyed with pids as the agent
sees them and translated in BPF via the task's pid-namespace chain, so this
works on nested nodes (kind, container-in-container runtimes) where
init-namespace pids differ from the node's.

## Header allowlist capture

`TracerConfig.spec.capture.headers` (or `PODTRACE_CAPTURE_HEADERS`, comma
separated) names up to 4 headers (names ≤ 32 chars, values truncated at 64
bytes) whose values are appended to HTTP/2 and HTTP/3 event `Details`, one
`name: value` line each. HTTP/1.x is not supported (its in-kernel scan window
is too narrow). Captured values pass through the PII redaction engine when
`spec.redaction` is enabled — enable redaction before capturing headers that
may carry user data.

```yaml
apiVersion: podtrace.io/v1alpha1
kind: TracerConfig
spec:
  capture:
    headers: ["content-type", "x-request-id"]
  redaction:
    enabled: true
```

## Interim responses, trailers, and other protocol corners

- **1xx interim responses** (100 Continue, 103 Early Hints) are recognized on
  HTTP/1.x, HTTP/2, and HTTP/3 and do not consume the pending request; the
  final status is reported. Interim responses themselves are not emitted as
  events.
- **gRPC over HTTP/2** is one response event per call. A gRPC call's response
  is its HEADERS and then its trailers, and the outcome is in the trailers'
  `grpc-status`, so the HEADERS are held until the trailers arrive and the
  call is emitted once: the HTTP status from the HEADERS, the `grpc-status`
  from the trailers, and the latency up to the trailers. A non-zero
  `grpc-status` marks the call as an error, as it does for a Trailers-Only
  response. A call whose trailers never come, because it was reset or its
  connection closed, is still emitted once, without an outcome. For gRPC-Go,
  the grpc-go uprobes also see each call; while the HTTP/2 decoder is seeing a
  process's gRPC calls, the uprobe events for that process are dropped so the
  call is not counted twice, and they are kept for a process whose
  connections the decoder cannot read.
- **Server push** is not supported and will not be: Chrome removed support,
  and quic-go never implemented HTTP/3 push.
- **0-RTT** needs no special handling: the Initial packet (and so SNI/ALPN
  capture) is still sent on session resumption, and 0-RTT requests flow
  through the same hooked functions.
- **QUIC versions**: v1 (RFC 9000) and v2 (RFC 9369) Initials are decrypted;
  other versions produce no connection event.

## Aborted server transactions

A return probe on quic-go's server request handler acts as a backstop: if the
handler returns while its request is still stashed, it panicked, or the
stream was taken over via `HTTPStream()` (WebTransport), the transaction is
emitted with `aborted` in place of a status code, and its latency is the
handler's run time. Aborted transactions are excluded from the status-code
report but appear in request/endpoint counts.

## Inbound header decoding

The nghttp3 adapter decodes inbound headers — the direction its callbacks
never expose (response status on clients, request method/path on servers),
without touching any hidden library internals: the probe on the public
`nghttp3_conn_read_stream` entry point ships each stream's first bytes to
userspace, where a spec-complete QPACK decoder (RFC 9204: dynamic table,
encoder stream, insert counts anchored on the capacity the peer's encoder
sets, blocked-section retry) reassembles the peer's field sections and fills
them into the paired transaction: status codes for client requests,
method/path/traceparent for server responses. The inbound control stream's
SETTINGS are the peer's own decoder limits, which bound the other direction,
so they are not used. A long-lived connection keeps decoding however many
requests it carries (finished streams free their slot), and a probe on
`nghttp3_conn_del` resets the state when the library frees a connection, so
a new connection allocated at the same address starts clean.

Capture is bounded on purpose: the first 512 bytes of each stream segment
and 4 KB per stream, so bodies are never copied. A field section beyond
those caps, or a stream that loses a segment under ringbuf pressure,
degrades to the previous behavior: latency pairing without inbound header
contents, never a wrong decode.
