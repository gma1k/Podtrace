# Podtrace Binary Event Schema

This document describes the binary wire format for events emitted by the BPF ring buffer
and consumed by the Go parser (`internal/ebpf/parser/parser.go`).

---

## Detection Algorithm

The parser infers the schema version from the size of the data record:

```
len(data) >= sizeof(rawEventV4)  →  parse as V4
len(data) >= sizeof(rawEventV3)  →  parse as V3
len(data) >= sizeof(rawEventV2)  →  parse as V2
len(data) >= sizeof(rawEventV1)  →  parse as V1
otherwise                         →  discard (return nil)
```

All multi-byte fields are **little-endian**.

---

## Struct Layouts

### V1 — Base (≈ 312 bytes)

| Offset | Size | Type     | Field        | Notes |
|--------|------|----------|--------------|-------|
| 0      | 8    | uint64   | Timestamp    | `bpf_ktime_get_ns()` |
| 8      | 4    | uint32   | PID          | Process ID |
| 12     | 4    | uint32   | Type         | `event_type` enum (see below) |
| 16     | 8    | uint64   | LatencyNS    | Duration in nanoseconds |
| 24     | 4    | int32    | Error        | errno (negative) or 0 |
| 28     | 4    | uint32   | _pad1        | Alignment padding |
| 32     | 8    | uint64   | Bytes        | Byte count or file descriptor |
| 40     | 4    | uint32   | TCPState     | TCP state (see TCP states below) |
| 44     | 4    | uint32   | _pad2        | Alignment padding |
| 48     | 8    | uint64   | StackKey     | Key into stack_traces map |
| 56     | 128  | char[128]| Target       | NUL-terminated string (IP:port, path, hostname) |
| 184    | 128  | char[128]| Details      | NUL-terminated auxiliary string |

**Total V1 size: 312 bytes**

### V2 — + CgroupID (≈ 320 bytes)

Extends V1 by inserting `CgroupID` before `Target`:

| Offset | Size | Type     | Field     | Notes |
|--------|------|----------|-----------|-------|
| 0–55   | 56   | —        | (V1 base) | same as V1 |
| 56     | 8    | uint64   | CgroupID  | BPF cgroup ID of the task |
| 64     | 128  | char[128]| Target    | |
| 192    | 128  | char[128]| Details   | |

**Total V2 size: 320 bytes**

### V3 — + Comm (≈ 336 bytes)

Extends V2 by inserting `Comm[16]` between `CgroupID` and `Target`:

| Offset | Size | Type      | Field    | Notes |
|--------|------|-----------|----------|-------|
| 0–63   | 64   | —         | (V2 base without Target/Details) | |
| 64     | 16   | char[16]  | Comm     | Process name from `bpf_get_current_comm()` |
| 80     | 128  | char[128] | Target   | |
| 208    | 128  | char[128] | Details  | |

**Total V3 size: 336 bytes**

### V4 — + NetNsID (≈ 344 bytes)

The current production schema. Adds the network namespace inode number at the end.

| Offset | Size | Type      | Field    | Notes |
|--------|------|-----------|----------|-------|
| 0      | 8    | uint64    | Timestamp | |
| 8      | 4    | uint32    | PID       | |
| 12     | 4    | uint32    | Type      | |
| 16     | 8    | uint64    | LatencyNS | |
| 24     | 4    | int32     | Error     | |
| 28     | 4    | uint32    | _pad1     | |
| 32     | 8    | uint64    | Bytes     | |
| 40     | 4    | uint32    | TCPState  | |
| 44     | 4    | uint32    | _pad2     | |
| 48     | 8    | uint64    | StackKey  | |
| 56     | 8    | uint64    | CgroupID  | |
| 64     | 16   | char[16]  | Comm      | |
| 80     | 128  | char[128] | Target    | |
| 208    | 128  | char[128] | Details   | |
| 336    | 4    | uint32    | NetNsID   | Network namespace inum; 0 if BTF unavailable |
| 340    | 4    | uint32    | _pad3     | Explicit alignment padding |

**Total V4 size: 344 bytes**

> **Note:** `NetNsID` is only populated when the BPF object is compiled with
> the running kernel exposing BTF, which CO-RE needs to walk
> `task_struct -> nsproxy -> net_ns`. Otherwise it remains 0.

---

## Event Type Enum

| Value | C Constant          | Go Constant          | Category |
|-------|---------------------|----------------------|----------|
| 0     | EVENT_DNS           | EventDNS             | NET      |
| 1     | EVENT_CONNECT       | EventConnect         | NET      |
| 2     | EVENT_TCP_SEND      | EventTCPSend         | NET      |
| 3     | EVENT_TCP_RECV      | EventTCPRecv         | NET      |
| 4     | EVENT_WRITE         | EventWrite           | FS       |
| 5     | EVENT_READ          | EventRead            | FS       |
| 6     | EVENT_FSYNC         | EventFsync           | FS       |
| 7     | EVENT_SCHED_SWITCH  | EventSchedSwitch     | CPU      |
| 8     | EVENT_TCP_STATE     | EventTCPState        | NET      |
| 9     | EVENT_PAGE_FAULT    | EventPageFault       | MEM      |
| 10    | EVENT_OOM_KILL      | EventOOMKill         | MEM      |
| 11    | EVENT_UDP_SEND      | EventUDPSend         | NET      |
| 12    | EVENT_UDP_RECV      | EventUDPRecv         | NET      |
| 13    | EVENT_HTTP_REQ      | EventHTTPReq         | HTTP     |
| 14    | EVENT_HTTP_RESP     | EventHTTPResp        | HTTP     |
| 15    | EVENT_LOCK_CONTENTION | EventLockContention | LOCK    |
| 16    | EVENT_TCP_RETRANS   | EventTCPRetrans      | NET      |
| 17    | EVENT_NET_DEV_ERROR | EventNetDevError     | NET      |
| 18    | EVENT_DB_QUERY      | EventDBQuery         | DB       |
| 19    | EVENT_EXEC          | EventExec            | PROC     |
| 20    | EVENT_FORK          | EventFork            | PROC     |
| 21    | EVENT_OPEN          | EventOpen            | PROC     |
| 22    | EVENT_CLOSE         | EventClose           | PROC     |
| 23    | EVENT_TLS_HANDSHAKE | EventTLSHandshake    | TLS      |
| 24    | EVENT_TLS_ERROR     | EventTLSError        | TLS      |
| 25    | EVENT_RESOURCE_LIMIT| EventResourceLimit   | RESOURCE |
| 26    | EVENT_POOL_ACQUIRE  | EventPoolAcquire     | POOL     |
| 27    | EVENT_POOL_RELEASE  | EventPoolRelease     | POOL     |
| 28    | EVENT_POOL_EXHAUSTED| EventPoolExhausted   | POOL     |
| 29    | EVENT_UNLINK        | EventUnlink          | FS       |
| 30    | EVENT_RENAME        | EventRename          | FS       |

---

## TCP State Values

Used in the `TCPState` field of `EventTCPState` records.

| Value | State |
|-------|-------|
| 1  | ESTABLISHED |
| 2  | SYN_SENT    |
| 3  | SYN_RECV    |
| 4  | FIN_WAIT1   |
| 5  | FIN_WAIT2   |
| 6  | TIME_WAIT   |
| 7  | CLOSE       |
| 8  | CLOSE_WAIT  |
| 9  | LAST_ACK    |
| 10 | LISTEN      |
| 11 | CLOSING     |
| 12 | NEW_SYN_RECV|

---

## Field Semantics

### Target field encoding

| Event type | Target content |
|------------|----------------|
| DNS        | Hostname being resolved |
| Connect    | `ip:port` or `[ipv6]:port` of remote |
| TCPSend/Recv | empty (connection tracked via socket map) |
| Write/Read/Fsync | File path basename (or empty if BTF unavailable) |
| Unlink     | Path of deleted file |
| Rename     | `old_path>new_path` (separator `>`) |
| DBQuery    | SQL query string |
| Exec       | Command path |
| Fork       | Child process name |
| Open       | File path |
| TLS*       | Library name |
| OOMKill    | Process name killed |

### Bytes field reuse

The `Bytes` field is overloaded depending on event type:

| Event type | Meaning |
|------------|---------|
| TCPSend/Recv, UDPSend/Recv, Write, Read, HTTPResp | Byte count transferred |
| Open, Close | File descriptor number (signed; negative = invalid) |
| OOMKill     | Memory freed (bytes) |
| PoolAcquire | Pool connection ID |

### Error field

`Error` is the negated errno value reported by the kernel function. For
example, `EAGAIN` (errno 11) appears as `-11`. `0` means success.

`EVENT_LOCK_CONTENTION` follows the same convention for both of its sources:
the `pthread_mutex_lock` return is negated to match a `futex` return. A
positive value is the number of waiters a `FUTEX_WAKE` woke. The ways a wait
normally ends, `-EAGAIN`, `-ETIMEDOUT`, `-EINTR` and the kernel-internal
`-ERESTART*` codes (512-516), are not counted as errors.

### DNS event field encoding

`EVENT_DNS` (response) and `EVENT_DNS_QUERY` (egress query) events produced by
the packet-based capture (`bpf/dns.c`, `cgroup_skb`) mostly reuse existing
fields, plus the dedicated DNS fields added in V5/V6:

| Field | DNS meaning |
|-------|-------------|
| `Target` | Query name (QNAME) |
| `TCPState` | Query type (QTYPE): 1=A, 28=AAAA, 5=CNAME, 33=SRV, 12=PTR, 16=TXT, … |
| `Error` | Response code (RCODE): 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED |
| `LatencyNS` | Resolution latency (query→response) |
| `Bytes` | Answer record count |
| `Details` | First resolved address (A or AAAA); or `timeout`; or `encrypted (DoT)`/`encrypted (DoH)` |
| `DNSServerIP` | Upstream resolver IPv4 (V5; 0 when the server is IPv6 or unknown) |
| `DNSTransport` | 0=UDP, 1=TCP (V5) |
| `DNSServerIP6` | Upstream resolver IPv6 (V6; all-zero when the server is IPv4). Preferred over `DNSServerIP` when set |

IPv4 and IPv6 are at parity: AAAA answers are resolved and correlated, the
upstream-server field is captured for both families, and DoT/DoH detection
covers known IPv6 resolver prefixes.

For `EVENT_CONNECT`, `Details` carries the DNS name the destination IP was
resolved from (correlation, IPv4 and IPv6), rendered as `ip:port (name)`. See
[dns-tracing.md](dns-tracing.md).

---

## Version History

| Version | Added field | BPF constant |
|---------|-------------|--------------|
| V1      | Base schema | — |
| V2      | `CgroupID`  | `bpf_get_current_cgroup_id()` always available |
| V3      | `Comm[16]`  | `bpf_get_current_comm()` always available |
| V4      | `NetNsID`   | Requires the running kernel to expose BTF, for CO-RE |
| V5      | `DNSServerIP`, `DNSTransport` | Packet DNS: upstream IPv4 resolver + UDP/TCP |
| V6      | `DNSServerIP6` | Packet DNS: upstream IPv6 resolver (IPv4/IPv6 parity) |

---

## Adding a V5

1. Append new fields to `struct event` in `bpf/events.h` (keep 8-byte alignment).
2. Add a corresponding `rawEventV5` struct in `internal/ebpf/parser/parser.go`.
3. Add a `len(data) >= expectedV5` branch at the top of `ParseEvent()`.
4. Copy the new fields into `events.Event` and update `PutEvent()` to clear them.
5. Add the field to `events.Event` in `internal/events/events.go`.
6. Update this document with the new offset table.
