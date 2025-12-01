# eBPF Internals

## Overview

Podtrace uses eBPF (extended Berkeley Packet Filter) to trace system calls and kernel events at the kernel level, providing low-overhead observability without modifying application code.

## eBPF Program Structure

### Maps

eBPF maps are used for communication between kernel and user space:

1. **Ring Buffer (`events`)**
   - Type: `BPF_MAP_TYPE_RINGBUF`
   - Size: 256 KB
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
   - Value: DNS target string (max 64 chars)

## Event Types

```c
enum event_type {
    EVENT_DNS,        // DNS lookups
    EVENT_CONNECT,    // TCP connections (IPv4/IPv6)
    EVENT_TCP_SEND,   // TCP send operations
    EVENT_TCP_RECV,   // TCP receive operations
    EVENT_WRITE,      // File write operations
    EVENT_READ,       // File read operations
    EVENT_FSYNC,      // File sync operations
    EVENT_SCHED_SWITCH // CPU scheduling events
};
```

## Event Structure

```c
struct event {
    u64 timestamp;      // Event timestamp (nanoseconds)
    u32 pid;           // Process ID
    u32 type;          // Event type
    u64 latency_ns;    // Operation latency (nanoseconds)
    s32 error;         // Error code (0 = success)
    char target[64];   // Target (IP:port, hostname, filename)
    char details[64]; // Additional details
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

**File System Tracing:**
- `vfs_read` / `vfs_write` / `vfs_fsync`: Entry and return probes
  - Entry: Record start time, extract file path
  - Return: Calculate latency

### Uprobes

Uprobes attach to user-space functions:

**DNS Tracing:**
- `getaddrinfo` (libc): Entry and return probes
  - Entry: Extract hostname from arguments, store in map
  - Return: Calculate latency, record error

### Tracepoints

Tracepoints are kernel instrumentation points:

**CPU Scheduling:**
- `sched_switch`: Triggered on context switches
  - Records thread blocking time
  - Tracks CPU scheduling events

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
- 256 KB buffer handles high event rates
- User space must read promptly to avoid drops

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
      -Ibpf -I. -c bpf/podtrace.bpf.c -o bpf/podtrace.bpf.o
```

Note: The eBPF code is now modular. `podtrace.bpf.c` includes all modules:
- `network.c` - Network probes
- `filesystem.c` - Filesystem probes
- `cpu.c` - CPU/scheduling probes
- `memory.c` - Memory probes

The header files (`common.h`, `maps.h`, `events.h`, `helpers.h`) provide shared definitions.

Flags:
- `-O2`: Optimize for performance
- `-g`: Include debug information
- `-target bpf`: Compile for eBPF target
- `-D__TARGET_ARCH_x86`: Define target architecture
- `-mcpu=v3`: Use BPF v3 instruction set

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