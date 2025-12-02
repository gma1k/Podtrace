# Architecture

## Overview

Podtrace is an eBPF-based diagnostic tool for Kubernetes applications. It uses kernel-level tracing to monitor application behavior without requiring code instrumentation or application restarts.

## System Architecture

```
┌───────────────────────────────────────────────────────────── ┐
│                    Kubernetes Cluster                        │
│                                                              │
│  ┌──────────────┐         ┌──────────────────────────┐       │
│  │   Podtrace   │────────▶│   Target Pod Container   │       │
│  │   (User)     │         │                          │       │
│  └──────┬───────┘         └──────────────────────────┘       │
│         │                                                    │
│         │ eBPF Programs                                      │
│         ▼                                                    │
│  ┌──────────────────────────────────────────────────────┐    │
│  │              Linux Kernel                            │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐            │    │
│  │  │ Kprobes  │  │Uprobes   │  │Tracepoint│            │    │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘            │    │
│  │       │             │             │                  │    │
│  │       └─────────────┴─────────────┘                  │    │
│  │                      │                               │    │
│  │              ┌───────▼────────┐                      │    │
│  │              │  Ring Buffer   │                      │    │
│  │              └───────┬────────┘                      │    │
│  └──────────────────────┼────────────────────────────── ┘    │
│                         │                                    │
└─────────────────────────┼────────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Event Processing    │
              │  - Event Parser       │
              │  - Cgroup Filter      │
              │  - Process Resolver   │
              └───────────┬───────────┘
                          │
        ┌─────────────────┴─────────────────┐
        │                                   │
        ▼                                   ▼
┌───────────────┐                    ┌───────────────┐
│  Real-time    │                    │   Metrics     │
│  Diagnostics  │                    │   Exporter    │
│  (CLI Output) │                    │               │
└───────────────┘                    └───────────────┘
```

## Components

### 1. eBPF Programs (`bpf/`)

The eBPF programs run in the kernel and trace system calls and kernel events. The code is organized into modular files:

- **podtrace.bpf.c**: Main file that includes all modules
- **common.h**: Common definitions and includes
- **maps.h**: BPF map definitions
- **events.h**: Event types and structures
- **helpers.h**: Helper functions
- **network.c**: Network probes (TCP, UDP, DNS, HTTP, TCP retransmissions, network errors)
- **filesystem.c**: Filesystem probes (with optional file path tracking)
- **cpu.c**: CPU/scheduling probes and lock contention tracking
- **memory.c**: Memory probes
- **syscalls.c**: System call probes (execve, fork, open, close)

- **Kprobes**: Attach to kernel functions
  - `tcp_v4_connect` / `tcp_v6_connect` - Network connections
  - `tcp_sendmsg` / `tcp_recvmsg` - TCP send/receive
  - `vfs_read` / `vfs_write` / `vfs_fsync` - File system operations
  - `do_futex` - Lock contention tracking (mutex/semaphore waits)
  - `do_sys_openat2` - File open operations
  - `do_execveat_common` - Process execution

- **Uprobes**: Attach to user-space functions
  - `getaddrinfo` (libc) - DNS lookups
  - `pthread_mutex_lock` (libc) - User-space mutex operations
  - `PQexec` (libpq) - PostgreSQL query execution
  - `mysql_real_query` (libmysqlclient) - MySQL query execution

- **Tracepoints**: Kernel events
  - `sched_switch` - CPU scheduling events
  - `sched_process_fork` - Process/thread creation
  - `tcp_retransmit_skb` - TCP retransmissions
  - `net_dev_xmit` - Network device transmission errors

### 2. Event Collection (`internal/ebpf/`)

- **Tracer**: Main struct managing eBPF program lifecycle
  - Loads and attaches eBPF programs
  - Reads events from ring buffer
  - Coordinates filtering and parsing

- **Loader**: Loads compiled eBPF object file

- **probes/**: Probe attachment logic
  - Attaches kprobes, kretprobes, tracepoints, uprobes

- **parser/**: Event parsing
  - Parses events from ring buffer into Go structs

- **filter/**: Cgroup filtering
  - Filters events by cgroup path
  - Caches PID-to-cgroup mappings

### 3. Kubernetes Integration (`internal/kubernetes/`)

- **PodResolver**: Resolves pod names to container information
  - Queries Kubernetes API
  - Extracts container ID
  - Finds cgroup path

### 4. Event Processing (`internal/events/`)

- **Event Types**: DNS, Connect, TCP Send/Recv, File System, CPU
- **Event Formatting**: Human-readable event messages

### 5. Diagnostics (`internal/diagnose/`)

- **Diagnostician**: Main struct that orchestrates diagnostic analysis
  - Generates comprehensive reports
  - Coordinates analysis across modules

- **analyzer/**: Analysis functions
  - DNS, network, filesystem, CPU analysis
  - Statistics calculation (latency, percentiles, error rates)

- **detector/**: Issue detection
  - Detects performance issues and anomalies

- **profiling/**: Profiling and timeline analysis
  - CPU usage profiling
  - Timeline and burst detection
  - Connection pattern analysis

- **tracker/**: Tracking functionality
  - Connection tracking
  - Process activity tracking

### 6. Metrics Export (`internal/metricsexporter/`)

- **Prometheus Exporter**: Exposes metrics via HTTP
  - RTT and latency histograms
  - DNS query latencies
  - File system operation latencies
  - CPU block times

### 7. Validation (`internal/validation/`)

- Input validation for pod names, namespaces, PIDs, container IDs
- Process name sanitization

## Data Flow

1. **Kernel Events**: System calls trigger eBPF programs
2. **Event Capture**: eBPF programs record event data and timestamps
3. **Ring Buffer**: Events are written to a ring buffer map
4. **User Space Reading**: Go application reads from ring buffer
5. **Cgroup Filtering**: Events are filtered to match target pod's cgroup
6. **Event Processing**: Events are parsed and enriched with process names
7. **Output**: Events are sent to:
   - Real-time diagnostic display (CLI)
   - Metrics exporter (Prometheus)

## Cgroup Filtering

Podtrace uses cgroup-based filtering to isolate events to the target pod:

1. Resolve pod's container ID from Kubernetes API
2. Find cgroup path in `/sys/fs/cgroup`
3. For each event, check if the process PID belongs to the target cgroup
4. Only process events from matching processes

## Security Considerations

- Requires elevated privileges (CAP_SYS_ADMIN or root)
- Can be run with capabilities instead of full root
- Validates all inputs (pod names, PIDs, container IDs)
- Sanitizes process names to prevent injection
- Rate limiting on metrics endpoint
- Security headers on HTTP responses
