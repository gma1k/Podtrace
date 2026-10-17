# eBPF Internals

## Overview

Podtrace uses eBPF (extended Berkeley Packet Filter) to trace system calls and kernel events at the kernel level, providing low-overhead observability without modifying application code.

## eBPF Program Structure

### Maps

eBPF maps are used for communication between kernel and user space:

1. **Ring Buffer (`events`)**
   - Type: `BPF_MAP_TYPE_RINGBUF`
   - Size: 2 MB (2048 KB)
   - Purpose: Transfer event data from kernel to user space
   - One-way: Kernel writes, user space reads

2. **Start Times (`start_times`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 1024 entries
   - Purpose: Store timestamps for latency calculation
   - Key: `(pid << 32) | tid` (process and thread ID)
   - Value: Start timestamp in nanoseconds

3. **DNS Targets (`dns_targets`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 1024 entries
   - Purpose: Store DNS query targets
   - Key: `(pid << 32) | tid`
   - Value: DNS target string (max 128 chars)

4. **Socket Connections (`socket_conns`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 1024 entries
   - Purpose: Store socket connection information
   - Key: `(pid << 32) | tid`
   - Value: Connection string (IP:port or URL)

5. **File Inodes (`file_inodes`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 1024 entries
   - Purpose: Store inode+device ID for filesystem operations
   - Key: `(pid << 32) | tid`
   - Value: `(device_id << 32) | inode_number` (packed as u64)
   - Note: Path resolution happens in userspace by correlating with `open()` events

6. **TCP Sockets (`tcp_sockets`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 1024 entries
   - Purpose: Store TCP socket information
   - Key: `(pid << 32) | tid`
   - Value: Socket identifier

7. **Stack Traces (`stack_traces`)**
   - Type: `BPF_MAP_TYPE_HASH`
   - Size: 2048 entries
   - Purpose: Store user-space stack traces
   - Key: Unique stack trace identifier
   - Value: Stack trace structure with instruction pointers

8. **Event Buffer (`event_buf`)**
   - Type: `BPF_MAP_TYPE_ARRAY`
   - Size: 1 entry (per-CPU)
   - Purpose: Temporary storage for event structures (avoids stack overflow)
   - Key: `u32` (always 0)
   - Value: `struct event`

9. **Stack Buffer (`stack_buf`)**
   - Type: `BPF_MAP_TYPE_ARRAY`
   - Size: 1 entry (per-CPU)
   - Purpose: Temporary storage for stack traces (avoids stack overflow)
   - Key: `u32` (always 0)
   - Value: `struct stack_trace_t`

10. **Lock Targets (`lock_targets`)**
    - Type: `BPF_MAP_TYPE_HASH`
    - Size: 1024 entries
    - Purpose: Store lock identifiers for contention tracking
    - Key: `(pid << 32) | tid`
    - Value: Lock identifier string

11. **Database Queries (`db_queries`)**
    - Type: `BPF_MAP_TYPE_HASH`
    - Size: 1024 entries
    - Purpose: Store sanitized database query patterns
    - Key: `(pid << 32) | tid`
    - Value: Query pattern string (first token only, sanitized)

12. **Syscall Paths (`syscall_paths`)**
    - Type: `BPF_MAP_TYPE_HASH`
    - Size: 1024 entries
    - Purpose: Store file paths for syscall operations (exec, open)
    - Key: `(pid << 32) | tid`
    - Value: File path string (max 128 chars)

## Event Types

```c
enum event_type {
    EVENT_DNS,            // DNS lookups
    EVENT_CONNECT,        // TCP connections (IPv4/IPv6)
    EVENT_TCP_SEND,       // TCP send operations
    EVENT_TCP_RECV,       // TCP receive operations
    EVENT_WRITE,          // File write operations
    EVENT_READ,           // File read operations
    EVENT_FSYNC,          // File sync operations
    EVENT_SCHED_SWITCH,   // CPU scheduling events
    EVENT_TCP_STATE,      // TCP connection state transitions
    EVENT_PAGE_FAULT,     // Page fault events
    EVENT_OOM_KILL,       // Out-of-memory kill events
    EVENT_UDP_SEND,       // UDP send operations
    EVENT_UDP_RECV,       // UDP receive operations
    EVENT_HTTP_REQ,       // HTTP request events
    EVENT_HTTP_RESP,      // HTTP response events
    EVENT_LOCK_CONTENTION, // Lock contention events
    EVENT_TCP_RETRANS,    // TCP retransmission events
    EVENT_NET_DEV_ERROR,  // Network device error events
    EVENT_DB_QUERY,       // Database query events
    EVENT_EXEC,           // Process execution (execve)
    EVENT_FORK,           // Process/thread creation
    EVENT_OPEN,           // File open operations
    EVENT_CLOSE           // File close operations
};
```

## Event Structure

```c
struct event {
    u64 timestamp;      // Event timestamp (nanoseconds)
    u32 pid;            // Process ID
    u32 type;           // Event type
    u64 latency_ns;     // Operation latency (nanoseconds)
    s32 error;          // Error code (0 = success)
    u64 bytes;          // Bytes transferred (for I/O operations)
    u32 tcp_state;      // TCP state (for TCP state events)
    u64 stack_key;      // Reference to stack trace in stack_traces map
    char target[128];   // Target (IP:port, hostname, filename, query pattern)
    char details[128];  // Additional details
};
```

## Tracing Mechanisms

### Kprobes

Kprobes attach to kernel functions:

**Network Tracing:**
- `tcp_v4_connect` / `tcp_v6_connect`: Entry and return probes
  - Entry: Record start time, extract destination IP:port
  - Return: Calculate latency, record error code

- `tcp_sendmsg` / `tcp_recvmsg`: Entry and return probes
  - Entry: Record start time
  - Return: Calculate RTT/latency

**Return probes on functions a task waits in:** `tcp_recvmsg`,
`tcp_sendmsg`, `udp_recvmsg`, `udp_sendmsg`, `unix_stream_recvmsg` and
`do_futex` return through fexit where the kernel can load it (5.17+ with
BTF: it needs `bpf_get_func_ret`), and through a kretprobe otherwise; the
agent logs each one that falls back, and why. A kretprobe keeps one instance per task inside the
function, from a pool of about twice the CPU count, and every thread blocked
in a read or parked on a lock holds one. On a busy node the pool runs dry and
returns are dropped without a trace, so a request that began is never seen
to end. An fexit trampoline has no pool. Each of these return probes is
built twice from one body, so both report the same thing.

**File System Tracing:**
- `vfs_read` / `vfs_write`: fentry/fexit where the kernel supports them
  (5.11+ with BTF), kprobe/kretprobe otherwise; the agent logs which.
  - Entry: skip a task in an untargeted cgroup and any file that is not a
    regular file (pipes, sockets, eventfds, ttys), then record the start in
    task-local storage (fentry) or a hash keyed by thread (kprobe)
  - Return: count the operation in kernel aggregation; one that took 1ms or
    longer also becomes an event, its file name read only then
- `fsync` / `fdatasync`: the `syscalls:sys_enter_*`/`sys_exit_*`
  tracepoints, the fd resolved to its file through the task's descriptor
  table. Current kernels inline the work into `do_fsync`, so a probe on
  `vfs_fsync` never runs for `fsync(2)`.
- `do_sys_openat2`, `vfs_unlink`, `vfs_rename`: entry and return probes,
  untargeted cgroups skipped on entry, counted in kernel aggregation
- `file_close_fd` (Linux 6.7+), else `close_fd`: a regular file's close
- Without kernel aggregation (a diagnose session), the operations under 1ms
  are counted in `fs_fast_ops`, which the session drains into its report

### Uprobes

Uprobes attach to user-space functions:

**DNS Tracing:**
- `getaddrinfo`, `gethostbyname_r` and `gethostbyname2_r` (libc): Entry and
  return probes. glibc's `gethostbyname` and `gethostbyname2` run the same
  code as the `_r` forms, so these see all four.
  - Entry: Extract hostname from arguments, store in map; for the `_r` forms
    also where the call writes its result and `h_errno` (the seventh argument
    of `gethostbyname2_r` is read off the stack on x86-64). A call nested in
    another on the same thread, as musl's `gethostbyname_r` calls
    `gethostbyname2_r`, only deepens the outer one.
  - Return: Calculate latency, record the result as an `EAI_*` code; an
    `ERANGE` return is glibc asking for a bigger buffer, not a finished lookup
- `dns_egress` / `dns_ingress` (`cgroup_skb`): every query and answer on port 53
  over UDP or TCP, read from the packets
  - Egress: a query waits in `dns_inflight` under its cgroup and id; a
    retransmission under the same id keeps the first send as the start and
    moves only `last_ns`
  - Ingress: the answer pairs with its query, and its rcode becomes the
    answer class in the aggregation variant (NOERROR, NXDOMAIN, SERVFAIL,
    REFUSED, other), with the error bit for every class but NOERROR and
    NXDOMAIN
  - A query still unanswered five seconds after `last_ns` is swept from
    userspace into a `timeout` lookup
- Each `EVENT_DNS` carries its source in `dns_transport`: UDP, TCP, an
  encrypted resolver (DoT/DoH, no answer to read), or libc. With packet
  capture on, the metrics count the packets and leave the libc call out, since
  it is the same lookup.

#### How uprobes are attached

On Linux 6.6 and later every uprobe is attached as a `uprobe_multi` link;
older kernels, and fleets with `agent.uprobeMulti: false`, use classic
perf-event uprobes. The behaviour traced is the same either way; what changes
is how fast an agent lets go of its probes.

A classic uprobe link is a perf event. Closing one unregisters the uprobe and
waits out an RCU grace period while the kernel holds its global
`event_mutex`, so an agent's uprobes detach one at a time, about 90ms each,
however many are closed in parallel. A `uprobe_multi` link releases its
uprobes without that lock, so a stopping agent's links detach together.
Measured on kind with Linux 7.1, an agent holding 692 links (544 of them
uprobes) shut down in 50s with classic uprobes and in about 1s with
`uprobe_multi`. Other probe types are not affected: kprobes, tracepoints and
the rest detach in well under a second.

How the mode is chosen:

- At load, the tracer asks the kernel whether it can create `uprobe_multi`
  links (`PODTRACE_UPROBE_MULTI`, set from `agent.uprobeMulti`, can switch it
  off). If it can, every `uprobe*` and `uretprobe*` program is loaded with the
  `uprobe_multi` attach type, since the kernel binds a program to its attach
  type at load. A collection that fails to load that way is loaded again with
  classic uprobes, so a kernel that refuses the programs still gets an agent.
- At attach, each site gets a link of its own, at the same address, with the
  same reference-counter offset (USDT semaphores), cookie and PID filter it
  would have had as a classic uprobe. Sites are still shared between holders
  of the same file, and reference-counted, exactly as before.
- The agent logs which path it took: `Uprobe attach mode` with
  `uprobe_multi: true|false`.

The agent's termination grace period is 120s, so even classic uprobes
always finish detaching before the kubelet's SIGKILL, which would leave the
kernel to release the rest one by one as the process exits.

### Tracepoints

Tracepoints are kernel instrumentation points:

**CPU Scheduling:**
- `sched_switch`: Triggered on context switches
  - Records thread blocking time
  - Tracks CPU scheduling events

**On-CPU sampling:**
- `perf_event_oncpu_sample`: a `perf_event` program on a cpu-clock event at 99 Hz per CPU
  - Records the running task's user stack with `bpf_get_stackid` into the `oncpu_stacks` STACK_TRACE map
  - Counts samples per (cgroup, pid, stack, request) in `oncpu_counts`, drained by the agent every 5 s
  - Tags a sample with the HTTP/1.x request its thread is serving (`oncpu_thread_requests`); replies record latency in `oncpu_requests_done`

## Stack Traces

Podtrace captures user-space stack traces for slow operations to help identify exact code paths causing performance issues.

### Stack Trace Capture

Stack traces are captured using the `bpf_get_stack()` helper with `BPF_F_USER_STACK` flag:

```c
static inline void capture_user_stack(void *ctx, u32 pid, u32 tid, struct event *e) {
    u32 zero = 0;
    struct stack_trace_t *trace = bpf_map_lookup_elem(&stack_buf, &zero);
    if (!trace) {
        e->stack_key = 0;
        return;
    }
    trace->nr = 0;
    int sz = bpf_get_stack(ctx, trace->ips, sizeof(trace->ips), BPF_F_USER_STACK);
    if (sz <= 0) {
        e->stack_key = 0;
        return;
    }
    trace->nr = sz / sizeof(u64);
    u64 key = build_stack_key(pid, tid, e->timestamp);
    bpf_map_update_elem(&stack_traces, &key, trace, BPF_ANY);
    e->stack_key = key;
}
```

### Stack Trace Storage

- **Temporary Buffer**: `stack_buf` (ARRAY map) stores stack trace during capture to avoid stack overflow
- **Persistent Storage**: `stack_traces` (HASH map) stores completed stack traces
- **Event Reference**: Each event contains a `stack_key` that references its stack trace
- **User Space Resolution**: Stack traces are resolved to symbols using `addr2line` in user space

### When Stack Traces Are Captured

Stack traces are captured for operations exceeding performance thresholds:
- Slow regular-file I/O operations (read/write/fsync of 1ms or more)
- Slow DNS lookups
- Slow network operations (TCP send/receive with high latency)
- Lock contention events (futex/pthread mutex waits > 1ms)
- Process execution (execve)
- Database query operations
- Network errors and TCP retransmissions

### Stack Trace Structure

```c
struct stack_trace_t {
    u64 ips[MAX_STACK_DEPTH];
    u32 nr;                     // Number of frames captured
};
```

## Latency Calculation

Latency is calculated using the start time stored in the hash map:

```c
static inline u64 calc_latency(u64 start) {
    u64 now = bpf_ktime_get_ns();
    return now > start ? now - start : 0;
}
```

1. Entry probe: Store `bpf_ktime_get_ns()` in map with key `(pid << 32) | tid`
2. Return probe: Read start time from map, calculate `now - start`
3. Clean up: Remove entry from map

## IP Address Formatting

IPv4 addresses are formatted as `A.B.C.D:PORT`:

```c
static inline void format_ip_port(u32 ip, u16 port, char *buf) {
    // Extracts bytes from 32-bit IP
    // Formats as decimal string
    // Appends port number
}
```

## Error Handling

- Error codes are captured from kernel return values
- Negative values indicate errors
- `-11` (EAGAIN) is treated as non-fatal for TCP operations
- Error codes are passed to user space for analysis

## Performance Considerations

### Ring Buffer

- Lockless, high-performance data structure
- 2 MB buffer handles high event rates
- User space must read promptly to avoid drops
- Larger buffer reduces event loss during high-throughput scenarios

### Hash Maps

- Limited to 1024 entries to control memory usage
- LRU-like behavior: old entries are overwritten
- Key collision handling: `(pid << 32) | tid` ensures uniqueness

### Probe Overhead

- Minimal overhead: simple timestamp and map operations
- No blocking operations in eBPF programs
- Fast path: most operations complete in microseconds

## Compilation

The eBPF program is compiled with:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -mcpu=v3 \
      -Ibpf -I. -c bpf/podtrace.bpf.c -o internal/ebpf/embedded/podtrace.amd64.bpf.o
```

Note: The eBPF code is now modular. `podtrace.bpf.c` includes all modules:
- `network.c` - Network probes (TCP, UDP, DNS, HTTP, retransmissions, errors)
- `filesystem.c` - Filesystem probes
- `cpu.c` - CPU/scheduling probes and lock contention
- `memory.c` - Memory probes
- `syscalls.c` - System call probes (exec, fork, open, close)

The header files (`common.h`, `maps.h`, `events.h`, `helpers.h`) provide shared definitions.

Flags:
- `-O2`: Optimize for performance
- `-g`: Include debug information
- `-target bpf`: Compile for eBPF target
- `-D__TARGET_ARCH_x86`: Define target architecture
- `-mcpu=v3`: Use BPF v3 instruction set

## Kernel-side metric aggregation

`bpf/agg.h` folds metric observations into a BPF map instead of shipping one
ring-buffer record per observation, so the continuous metrics plane costs
O(series) rather than O(events). The probes call `agg_from_event()` beside
each `bpf_ringbuf_output()`, and the agent drains the map on an interval.

### Bucket indices are map keys, not offsets

The obvious way to build a histogram in BPF is an array of counters indexed by
bucket, which forces every index to be a compile-time-constant-masked offset
into a map value, the constraint this codebase has hit before. This design
sidesteps it: the bucket is part of the map **key**, so there is no
variable-offset write to mask, and the accumulators live in the map value
rather than on the stack.

### The index is Prometheus schema 3

`agg_bucket()` computes `floor(log2(v) * 8)`: the Prometheus native-histogram
schema a bucket factor of 1.1 resolves to. It is a branchless MSB search
(no loop, so the verifier sees straight-line code) plus seven comparisons
against the normalized sub-boundaries.

Those boundaries are `2^(k/8) * 2^32` for k=1..7 and must be exact. Hand-written
constants were wrong on the first attempt; they are now generated and verified
against Prometheus's own formula — `SearchFloat64s(bounds, frac) + (exp-1)*8`
from `client_golang`, across every value from 1 to 100000 plus every
power-of-two boundary. `kernelagg.BucketIndex()` is the Go mirror.

### Struct layout must be spelled out

`struct agg_key` ends with explicit `u8 pad[6]`. The struct would be padded to
its `u64` alignment anyway, but Go's `encoding/binary` adds no implicit
trailing padding, so an implicitly-padded struct decodes short. That failure
mode is quiet in the worst way, a misread key attributes metrics to the wrong
workload — so a test asserts `binary.Size(Key{}) == 24`.

### Reserved records must be released

The ring-buffer bypass skips `bpf_ringbuf_output()` for anything the map
absorbed. Where a probe uses the reserve/submit form instead, `bpf/dns.c` —
the reservation must be **discarded**, not simply skipped, or it leaks and the
ring wedges.

### Arch coverage

Both the BTF and stub builds produce the full program set on amd64 and
arm64. The kernel verifier has been exercised on amd64; arm64 is
compile-verified only, since it needs an arm64 kernel to load against.

## Verification

The kernel verifies eBPF programs before loading:

- **Safety checks**: No infinite loops, bounded memory access
- **Type checking**: Map access validation
- **Resource limits**: Program size, complexity limits
- **Helper functions**: Only allowed kernel helpers

## User Space Integration

The Go application:

1. **Loads** the compiled eBPF object file
2. **Attaches** programs to kernel functions
3. **Reads** events from ring buffer
4. **Filters** events by cgroup (user space)
5. **Processes** events and generates reports

## Limitations

- **Kernel version**: Requires 5.8+ for ring buffer support
- **BTF**: Requires BTF for CO-RE (Compile Once - Run Everywhere)
- **Permissions**: Requires CAP_SYS_ADMIN or CAP_BPF
- **Map size**: Limited by kernel configuration
- **Probe availability**: Some probes may not be available on all systems

## Debugging

To debug eBPF programs:

1. **Check compilation**: Ensure no compilation errors
2. **Verify loading**: Check kernel logs (`dmesg`)
3. **Test probes**: Verify probes attach successfully
4. **Monitor events**: Check ring buffer for events
5. **Kernel logs**: Look for eBPF-related errors

Common issues:
- Probe attachment failures (permissions, missing symbols)
- Map access errors (wrong key/value types)
- Ring buffer drops (user space not reading fast enough)