# Development Guide

## Project Structure

```
podtrace/
├── bpf/                    # eBPF source code
│   ├── common.h            # Common definitions and includes
│   ├── maps.h              # BPF map definitions
│   ├── events.h            # Event types and structures
│   ├── helpers.h           # Helper functions
│   ├── network.c           # Network probes (TCP, UDP, DNS, HTTP, retransmissions, errors)
│   ├── filesystem.c        # Filesystem probes
│   ├── cpu.c               # CPU/scheduling probes and lock contention
│   ├── memory.c            # Memory probes
│   ├── syscalls.c          # System call probes (exec, fork, open, close)
│   ├── podtrace.bpf.c      # Main eBPF program (includes all modules)
│   └── vmlinux.h           # Kernel types
├── cmd/
│   └── podtrace/
│       └── main.go         # Application entry point
├── internal/
│   ├── diagnose/           # Diagnostic analysis
│   │   ├── analyzer/       # Analysis functions (DNS, network, FS, CPU)
│   │   ├── detector/       # Issue detection
│   │   ├── profiling/      # CPU profiling and timeline analysis
│   │   ├── tracker/        # Connection and process tracking
│   │   └── diagnose.go     # Main Diagnostician struct
│   ├── ebpf/               # eBPF integration
│   │   ├── filter/         # Cgroup filtering
│   │   ├── parser/         # Event parsing
│   │   ├── probes/         # Probe attachment
│   │   └── tracer.go       # Main Tracer struct
│   ├── events/             # Event types and formatting
│   ├── kubernetes/         # K8s pod resolution
│   ├── metricsexporter/    # Prometheus metrics
│   └── validation/         # Input validation
├── scripts/                # Build and setup scripts
├── test/                   # Test utilities
└── doc/                    # Documentation
```

## Building

### Prerequisites

- Go 1.24+ (or 1.21+ with GOTOOLCHAIN=auto)
- Clang and LLVM
- Linux kernel 5.8+ with BTF

### Build Commands

```bash
# Install dependencies
make deps

# Build eBPF and Go binary
make build

# Build and set capabilities
make build-setup

# Clean build artifacts
make clean
```

### Development Workflow

1. **Modify eBPF code** (`bpf/podtrace.bpf.c`)
2. **Rebuild**: `make build`
3. **Test**: Run against a test pod
4. **Iterate**: Repeat as needed

## Code Organization

### eBPF Layer (`bpf/`)

- **podtrace.bpf.c**: Main eBPF program (includes all modules)
- **common.h**: Common definitions, constants, includes
- **maps.h**: All BPF map definitions
- **events.h**: Event type definitions and structures
- **helpers.h**: Helper functions (get_key, calc_latency, format_ip, get_event_buf, capture_user_stack, etc.)
- **network.c**: Network probes (TCP, UDP, DNS, HTTP, connections, retransmissions, errors)
- **filesystem.c**: Filesystem probes (read, write, fsync)
- **cpu.c**: CPU/scheduling probes (sched_switch) and lock contention (futex, pthread)
- **memory.c**: Memory probes (page_fault, oom_kill)
- **syscalls.c**: System call probes (execve, fork, open, close)

### Application Layer (`cmd/` and `internal/`)

- **main.go**: CLI entry point
  - Parses command-line arguments
  - Coordinates components
  - Handles real-time and diagnose modes

- **ebpf/**: eBPF integration
  - `loader.go`: Loads eBPF object file
  - `tracer.go`: Main Tracer struct managing eBPF programs and event collection
  - `filter/`: Cgroup filtering logic
  - `parser/`: Event parsing from ring buffer
  - `probes/`: Probe attachment logic

- **events/**: Event handling
  - Event type definitions
  - Event formatting for display

- **kubernetes/**: K8s integration
  - Pod resolution
  - Container ID extraction
  - Cgroup path finding

- **diagnose/**: Diagnostic analysis
  - `diagnose.go`: Main Diagnostician struct and orchestration
  - `analyzer/`: Analysis functions (DNS, network, filesystem, CPU)
  - `detector/`: Issue detection logic
  - `profiling/`: CPU profiling and timeline analysis
  - `tracker/`: Connection and process tracking

- **metricsexporter/**: Metrics
  - Prometheus metric definitions
  - HTTP server for metrics endpoint

- **validation/**: Input validation
  - Pod name, namespace validation
  - PID, container ID validation
  - Process name sanitization

## Adding New Event Types

### 1. Define Event Type

In `internal/events/events.go`:

```go
const (
    // ... existing types
    EventNewType EventType = iota
)
```

### 2. Add eBPF Probe

In `bpf/podtrace.bpf.c` or appropriate module file:

```c
SEC("kprobe/new_function")
int kprobe_new_function(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 key = get_key(pid, tid);
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/new_function")
int kretprobe_new_function(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 key = get_key(pid, tid);
    u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
    if (!start_ts) {
        return 0;
    }
    
    struct event *e = get_event_buf();
    if (!e) {
        bpf_map_delete_elem(&start_times, &key);
        return 0;
    }
    
    e->timestamp = bpf_ktime_get_ns();
    e->pid = pid;
    e->type = EVENT_NEW_TYPE;
    e->latency_ns = calc_latency(*start_ts);
    e->error = PT_REGS_RC(ctx);
    
    capture_user_stack(ctx, pid, tid, e);
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    bpf_map_delete_elem(&start_times, &key);
    return 0;
}
```

**Important**: Always use `get_event_buf()` instead of stack-allocating `struct event` to avoid BPF stack overflow (512 byte limit). The same applies to stack traces - use `stack_buf` via `capture_user_stack()`.

### 3. Register Probe

In `internal/ebpf/probes/probes.go`, add to `AttachProbes()`:

```go
probes := map[string]string{
    "kprobe_new_function": "new_function",
    "kretprobe_new_function": "new_function",
}
```

### 4. Handle Events

In `internal/events/events.go`, add formatting:

```go
func (e *Event) FormatMessage() string {
    switch e.Type {
    case EventNewType:
        return fmt.Sprintf("[NEW] ...")
    }
}
```

### 5. Add Metrics (Optional)

In `internal/metricsexporter/promexporter.go`:

```go
var newMetric = prometheus.NewHistogramVec(...)

prometheus.MustRegister(newMetric)

case events.EventNewType:
    ExportNewMetric(e)
```

## Testing

### Manual Testing

1. **Create test pod**:
   ```bash
   kubectl run test-pod --image=nginx -n default
   ```

2. **Run podtrace**:
   ```bash
   ./bin/podtrace -n default test-pod --diagnose 10s
   ```

3. **Verify output**: Check diagnostic report

### Test Utilities

The `test/` directory contains:
- Test pod definitions
- Setup/cleanup scripts
- Quick test scripts

## Debugging

### eBPF Program Debugging

1. **Check compilation**:
   ```bash
   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -mcpu=v3 \
         -Ibpf -I. -c bpf/podtrace.bpf.c -o bpf/podtrace.bpf.o
   ```

2. **Check kernel logs**:
   ```bash
   sudo dmesg | tail -20
   ```

3. **Verify probe attachment**:
   ```bash
   sudo bpftool prog list
   ```

### Application Debugging

1. **Enable verbose logging**: Add debug prints
2. **Check event flow**: Verify events are being read
3. **Test cgroup filtering**: Ensure events are filtered correctly

### Common Issues

**Probe not attaching:**
- Check function name exists in kernel
- Verify kernel version compatibility
- Check permissions

**No events:**
- Verify pod is active
- Check cgroup path resolution
- Ensure application makes system calls

**High overhead:**
- Reduce event rate
- Optimize eBPF code
- Check ring buffer size

## Code Style

- **Go**: Follow standard Go formatting (`go fmt`)
- **C**: Follow kernel coding style for eBPF
- **Comments**: Document public functions and complex logic
- **Error handling**: Always handle errors explicitly

## Contributing

1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes
4. **Test** thoroughly
5. **Submit** a pull request

## Dependencies

### Go Modules

Dependencies are managed via `go.mod`:
- `github.com/cilium/ebpf`: eBPF library
- `github.com/spf13/cobra`: CLI framework
- `k8s.io/client-go`: Kubernetes client
- `github.com/prometheus/client_golang`: Prometheus client

### System Dependencies

- Clang/LLVM: For eBPF compilation
- Kernel headers: For BTF support

## Performance Considerations

- **Ring buffer size**: Adjust if seeing drops
- **Map sizes**: Balance memory vs. capacity
- **Event filtering**: Filter early in user space
- **Process name caching**: Reduces /proc reads

## Security

- **Input validation**: Always validate user input
- **Process name sanitization**: Prevent injection
- **Capability requirements**: Document required capabilities
- **Rate limiting**: Protect metrics endpoint