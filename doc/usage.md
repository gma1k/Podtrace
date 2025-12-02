# Usage Guide

## Basic Usage

### Real-time Tracing

Trace a pod in real-time with periodic diagnostic updates:

```bash
./bin/podtrace -n <namespace> <pod-name>
```

Example:
```bash
./bin/podtrace -n production my-app-pod
```

This will:
- Resolve the pod and find its container
- Attach eBPF programs to trace system calls
- Display real-time diagnostic reports every 5 seconds
- Show events as they occur

Press `Ctrl+C` to stop and see the final diagnostic report.

### Diagnose Mode

Collect events for a specified duration and generate a comprehensive report:

```bash
./bin/podtrace -n <namespace> <pod-name> --diagnose <duration>
```

Duration format: `10s`, `5m`, `1h`, etc.

Example:
```bash
./bin/podtrace -n production my-app-pod --diagnose 30s
```

This will:
- Collect events for 30 seconds
- Generate a detailed diagnostic report
- Exit automatically when done

## Command Line Options

```
Usage: ./bin/podtrace -n <namespace> <pod-name> [flags]

Flags:
  -n, --namespace string        Kubernetes namespace (default: "default")
      --diagnose string         Run in diagnose mode for the specified duration (e.g., 10s, 5m)
      --metrics                 Enable Prometheus metrics server
      --export string           Export format for diagnose report (json, csv)
      --filter string           Filter events by type (dns,net,fs,cpu,proc)
      --container string        Container name to trace (default: first container)
      --error-threshold float   Error rate threshold percentage for issue detection (default: 10.0)
      --rtt-threshold float     RTT spike threshold in milliseconds (default: 100.0)
      --fs-threshold float      File system slow operation threshold in milliseconds (default: 10.0)
```

### Event Filtering

Use `--filter` to focus on specific event types:
- `dns`: DNS lookup events
- `net`: Network events (TCP, UDP, connections)
- `fs`: File system events (read, write, fsync)
- `cpu`: CPU scheduling events
- `proc`: Process lifecycle events (exec, fork, open, close)

Examples:
```bash
# Only show network events
./bin/podtrace -n production my-pod --filter net

# Show both network and process events
./bin/podtrace -n production my-pod --filter net,proc
```

## Real-time Mode Output

Real-time mode displays:
- Periodic diagnostic summaries (every 5 seconds)
- Event counts and statistics
- Top processes by activity
- Performance metrics

The display updates in place, showing the latest 5-second window.

## Diagnose Mode Report

The diagnose report includes:

### Summary Statistics
- Total events collected
- Events per second
- Collection period

### TCP Statistics
- Send and receive operation counts
- RTT (Round-Trip Time) analysis
- RTT spikes (>100ms)
- Error rates

### Connection Statistics
- Total connections and rate
- Connection latency (avg, max, percentiles)
- Failed connections and error breakdown
- Top connection targets

### File System Statistics
- Read, write, and fsync operation counts
- Operation latencies (avg, max, percentiles)
- Slow operations (>10ms)
- Top accessed files (if file path tracking is enabled)
- I/O bandwidth metrics (total bytes, average bytes, throughput)

### CPU Statistics
- Thread switch count
- Block time analysis (avg, max, percentiles)

### CPU Usage by Process
- CPU percentage per process
- Top CPU consumers

### Process Activity
- Active processes
- Top processes by event count
- Event distribution per process

### Activity Timeline
- Event distribution over time
- Activity bursts detection

### Connection Patterns
- Connection pattern analysis (steady, bursty, sporadic)
- Average and peak connection rates
- Unique connection targets

### Network I/O Patterns
- Send/receive ratio
- Average and peak throughput

### Process and Syscall Activity
- Process execution tracking (execve events)
- Process/thread creation (fork/clone events)
- File descriptor operations (open/openat and close)
- File descriptor leak detection (opens vs closes)
- Top opened files
- Process lifecycle patterns

### Stack Traces for Slow Operations
- User-space stack traces for operations exceeding thresholds
- Symbol resolution for stack frames
- Grouped by operation type and latency
- Helps pinpoint exact code paths causing performance issues

### Potential Issues
- High error rates
- Performance problems
- RTT spikes
- File descriptor leaks
- Lock contention hotspots

## Examples

### Debug Slow API Responses

```bash
# Trace for 1 minute to see connection patterns
./bin/podtrace -n production api-server --diagnose 1m
```

Look for:
- High connection latency in Connection Statistics
- RTT spikes in TCP Statistics
- DNS lookup delays

### Investigate File I/O Issues

```bash
# Monitor file system operations
./bin/podtrace -n production database-pod --diagnose 30s
```

Check:
- File System Statistics for slow operations
- Top accessed files (if file path tracking is enabled)
- Read/write latency percentiles
- I/O bandwidth and throughput metrics

### Monitor CPU Scheduling

```bash
# Watch CPU scheduling in real-time
./bin/podtrace -n production worker-pod
```

Monitor:
- CPU Statistics for thread blocking
- CPU Usage by Process
- Activity bursts

### Track DNS Performance

```bash
# Analyze DNS lookups
./bin/podtrace -n production web-app --diagnose 20s
```

Review:
- DNS Statistics section
- DNS latency percentiles
- Top DNS targets
- DNS error rates

## Tips

1. **Start with diagnose mode** for initial analysis
2. **Use real-time mode** for ongoing monitoring
3. **Adjust duration** based on your needs (longer = more data)
4. **Check Potential Issues** section for automatic problem detection
5. **Compare percentiles** (P50 vs P95 vs P99) to identify outliers

## Limitations

- Only traces the first container in a pod
- Requires kernel 5.8+ with BTF support
- File path tracking requires kernel 5.6+ with `bpf_d_path` support (disabled by default)
- DNS tracking may be unavailable if libc path cannot be determined
- CPU scheduling tracking requires tracepoint permissions
- Stack trace symbol resolution requires `addr2line` tool and debug symbols
- Database query tracing requires matching database client libraries (libpq, libmysqlclient)
- Some syscall probes may be unavailable on certain kernel versions (e.g., `__close_fd`)

## Troubleshooting

**No events collected:**
- Verify the pod is running and active
- Check that the application is making system calls
- Ensure cgroup path was found correctly

**High CPU usage:**
- This is normal for high-event-rate applications
- Consider filtering or reducing trace duration

**Permission errors:**
- Run with `sudo` or set capabilities
- Check kernel version and BTF support