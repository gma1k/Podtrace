<p align="center">
  <a href="https://github.com/gma1k/podtrace">
    <img src="https://github.com/gma1k/podtrace/blob/main/assets/podtrace-logo.png" width="420" alt="podtrace logo"/>
  </a>
</p>

A lightweight yet powerful eBPF-driven diagnostic tool for Kubernetes applications. Podtrace delivers full-stack observability from kernel events to application-layer behavior, all activated on demand, with no prior configuration or instrumentation. With a single command, it uncovers insights across the entire lifecycle of a pod, including network flows, TCP/UDP performance, file system activity, memory behavior, latency patterns, system calls, and high-level application events such as HTTP, DNS, and database queries.

## Overview

Podtrace attaches eBPF programs directly to the container, allowing it to observe real behavior as it happens at runtime. It automatically correlates low-level kernel activity with high-level application operations, surfacing clear, human-readable diagnostic events that reveal what the pod is experiencing internally.

Instead of assembling data from multiple systems or modifying application code, podtrace provides deep operational visibility in one place, enabling you to understand:

- Why a service is slow  
- Where latency originates  
- How network and I/O resources are being used  
- Which operations block or fail  
- How requests flow through the application  
- What happens inside the pod during incidents  

By combining system-level details, application-layer insights, and real-time event correlation, Podtrace acts as a single on-demand observability lens. This makes it uniquely effective for debugging, performance analysis, and production incident response in Kubernetes environments, especially when time, context, or access is limited.


## Documentation

`podtrace` documentation is available in the [`doc/`](doc/) directory.

## Features

### Network Tracing
- **TCP Connection Monitoring**: Tracks TCP IPv4/IPv6 connection latency and errors
- **TCP RTT Analysis**: Detects RTT spikes and retry patterns
- **TCP State Tracking**: Monitors TCP connection state transitions (SYN, ESTABLISHED, FIN, etc.)
- **TCP Retransmission Tracking**: Detects TCP retransmissions for network quality diagnostics
- **Network Device Errors**: Monitors network interface errors and packet drops
- **UDP Network Tracing**: Tracks UDP send/receive operations with latency and bandwidth metrics
- **I/O Bandwidth Tracking**: Monitors bytes transferred for TCP/UDP send/receive operations

### File System Monitoring
- **File Operations**: Tracks read, write, and fsync operations with latency analysis
- **File Path Tracking**: Captures full file paths using multi-strategy resolution (inode-based correlation with `open()` events)
- **I/O Bandwidth**: Monitors bytes transferred for file read/write operations
- **Throughput Analysis**: Calculates average throughput and peak transfer rates

### Memory & System Events
- **Page Fault Tracking**: Monitors page faults with error code analysis
- **OOM Kill Detection**: Tracks out-of-memory kills with memory usage details

### Application Layer
- **HTTP Tracing**: HTTP request/response tracking via uprobes
- **DNS Tracking**: Monitors DNS lookups with latency and error tracking
- **Database Query Tracing**: Tracks PostgreSQL and MySQL query execution with pattern extraction and latency analysis
- **TLS/SSL Handshake Tracking**: Track TLS handshake latency, errors and failures
- **Connection Pool Monitoring**: Tracks connection pool usage, monitors pool exhaustion, and tracks connection reuse patterns

### System Monitoring
- **CPU/Scheduling Tracking**: Monitors thread blocking and CPU scheduling events
- **CPU Usage per Process**: Shows CPU consumption by process
- **Process Activity Analysis**: Shows which processes are generating events
- **Stack Traces for Slow Operations**: Captures user-space stack traces for slow I/O, DNS, CPU blocks, memory faults, and other operations exceeding thresholds
- **Lock Contention Tracking**: Monitors futex and pthread mutex waits with timing and hot lock identification
- **Syscall Tracing**: Tracks process lifecycle via execve, fork/clone, open/openat, and close syscalls with file descriptor leak detection
- **Network Reliability**: Monitors TCP retransmissions and network device errors for network quality diagnostics
- **Database Query Tracing**: Tracks PostgreSQL and MySQL query execution patterns and latency
- **Resource Limit Monitoring**: Monitor resource usage vs limits
- **Error Correlation with Root Cause Analysis**: Correlates errors with operations and Kubernetes context

### Distributed Tracing
- **Trace Context Extraction**: Automatically extracts trace context from HTTP/HTTP2 headers and gRPC metadata
- **Event Correlation**: Groups events by trace ID to build complete request flows across services
- **Request Flow Graphs**: Builds directed graphs showing service interactions with latency and error metrics
- **Multiple Exporters**: Supports OpenTelemetry (OTLP), Jaeger, and Splunk HEC
- **Sampling Support**: Configurable sampling rates to control export volume

### Diagnostics
- **Diagnose Mode**: Collects events for a specified duration and generates a comprehensive summary report

## Prerequisites

- Linux kernel 5.8+ with BTF support
- Go 1.24+
- Kubernetes cluster access

## Building

```bash
# Install dependencies
make deps

# Build eBPF program and Go binary
make build

# Build and set capabilities
make build-setup
```

## Usage

### Basic Usage

```bash
# Trace a pod in real-time
./bin/podtrace -n production my-pod

# Run in diagnostic mode
./bin/podtrace -n production my-pod --diagnose 20s
```

### Diagnose Report

The diagnose mode generates a comprehensive report including:

- **Summary Statistics**: Total events, events per second, collection period
- **DNS Statistics**: DNS lookup latency, errors, top targets
- **TCP Statistics**: RTT analysis, spikes detection, send/receive operations, bandwidth metrics (total bytes, average bytes, peak bytes, throughput)
- **UDP Statistics**: Send/receive operations, latency analysis, bandwidth metrics, error tracking
- **Connection Statistics**: IPv4/IPv6 connection latency, failures, error breakdown, top targets
- **TCP Connection State Tracking**: State transition analysis, state distribution, connection lifecycle monitoring
- **File System Statistics**: Read, write, and fsync operation latency, slow operations, bandwidth metrics (total bytes, average bytes, throughput)
- **HTTP Statistics**: Request/response counts, latency analysis, bandwidth metrics, top requested URLs
- **Memory Statistics**: Page fault counts and error codes, OOM kill tracking with memory usage details
- **CPU Statistics**: Thread blocking times and scheduling events
- **CPU Usage by Process**: CPU percentage per process
- **Process Activity**: Top active processes by event count
- **Activity Timeline**: Event distribution over time
- **Activity Bursts**: Detection of burst periods
- **Connection Patterns**: Analysis of connection behavior
- **Network I/O Patterns**: Send/receive ratios and throughput analysis
- **Process and Syscall Activity**: Process execution, fork/clone, file operations, and file descriptor leak detection
- **Stack Traces for Slow Operations**: User-space stack traces for operations exceeding thresholds with symbol resolution
- **Lock Contention Analysis**: Futex and pthread mutex wait times and hot lock identification
- **Network Reliability**: TCP retransmission tracking and network device error monitoring
- **Database Query Performance**: Query pattern analysis and execution latency (PostgreSQL, MySQL)
- **Connection Pool Statistics**: Connection pool usage, acquire/release rates, reuse patterns, and exhaustion events
- **Potential Issues**: Automatic detection of high error rates and performance problems
- **Resource Limit Monitoring**: Monitor resource usage vs limits
- **Error Correlation with Root Cause Analysis**: Correlates errors with operations and Kubernetes context

## Running without sudo

After building, set capabilities to run without sudo:

```bash
sudo ./scripts/setup-capabilities.sh
```

---

## Distributed Tracing

`podtrace` supports distributed tracing to correlate events across services in your Kubernetes cluster. Traces are automatically extracted from HTTP headers and exported to popular observability backends.

### Quick Start

```bash
# Enable tracing with OpenTelemetry
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-otlp-endpoint http://otel-collector:4318

# Enable tracing with Jaeger
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-jaeger-endpoint http://jaeger:14268/api/traces

# Enable tracing with Splunk
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-splunk-endpoint https://splunk:8088/services/collector \
  --tracing-splunk-token YOUR_TOKEN
```

### Features

- **Automatic Trace Extraction**: Extracts W3C Trace Context, B3, and Splunk headers
- **Service Correlation**: Groups events by trace ID across multiple services
- **Request Flow Graphs**: Visualizes service interactions
- **Multiple Exporters**: OTLP, Jaeger, and Splunk HEC support
- **Sampling**: Configurable sampling rates (0.0-1.0)

---

## Prometheus & Grafana Integration

`podtrace` exposes runtime metrics for Kubernetes pods using a built-in Prometheus endpoint. These metrics cover networking (TCP/UDP), DNS, CPU scheduling, file system operations, memory events, and HTTP tracing, all labeled per process and event type.

---

Running:

```bash
./bin/podtrace -n production my-pod --metrics
```

launches an HTTP server accessible at:

```bash
http://localhost:3000/metrics
```

## Prometheus Scrape Configuration

In your Prometheus scrape job, set <PODTRACE_HOST> to the address of the pod or host running podtrace.

```bash
scrape_configs:
  - job_name: 'podtrace'
    static_configs:
      - targets: ['<PODTRACE_HOST>:3000']
```

## Available Metrics
All metrics are exported per process and per event type:
| Metric                                   | Description                                     |
| ---------------------------------------- | ----------------------------------------------- |
| `podtrace_rtt_seconds`                   | Histogram of TCP RTTs                           |
| `podtrace_rtt_latest_seconds`            | Most recent TCP RTT                             |
| `podtrace_latency_seconds`               | Histogram of TCP send/receive latency           |
| `podtrace_latency_latest_seconds`        | Most recent TCP latency                         |
| `podtrace_dns_latency_seconds_gauge`     | Latest DNS query latency                        |
| `podtrace_dns_latency_seconds_histogram` | Distribution of DNS query latencies             |
| `podtrace_fs_latency_seconds_gauge`      | Latest file system operation latency            |
| `podtrace_fs_latency_seconds_histogram`  | Distribution of file system operation latencies |
| `podtrace_network_bytes_total`           | Total bytes transferred over network (TCP/UDP)  |
| `podtrace_filesystem_bytes_total`       | Total bytes transferred via filesystem ops      |
| `podtrace_cpu_block_seconds_gauge`       | Latest CPU block time                           |
| `podtrace_cpu_block_seconds_histogram`   | Distribution of CPU block times                 |
| `podtrace_resource_limit_bytes`          | Resource limit in bytes (CPU/Memory/I/O)        |
| `podtrace_resource_usage_bytes`          | Current resource usage in bytes                 |
| `podtrace_resource_utilization_percent`  | Resource utilization percentage                  |
| `podtrace_resource_alert_level`          | Resource alert level (0-3: none/warning/critical/emergency) |
| `podtrace_pool_acquires_total`           | Total connection pool acquires                  |
| `podtrace_pool_releases_total`           | Total connection pool releases                  |
| `podtrace_pool_exhausted_total`          | Total pool exhaustion events                     |
| `podtrace_pool_wait_time_seconds`        | Histogram of pool wait times                     |
| `podtrace_pool_connections`             | Current number of connections in pool            |
| `podtrace_pool_utilization`              | Pool utilization percentage                      |

## Grafana Dashboard

A ready-to-use Grafana dashboard JSON is included in the repository at `podtrace/internal/metricsexporter/dashboard/Podtrace-Dashboard.json`


## Steps to use:

- Open Grafana and go to Dashboards → New → Import.
- Paste the JSON or upload the .json file.
- Select or your Prometheus datasource as the datasource.
- Import. The dashboard will display per-process and per-event-type metrics for RTT, latency, DNS, FS, and CPU block time.
