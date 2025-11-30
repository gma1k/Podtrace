<p align="center">
  <a href="https://github.com/gma1k/podtrace">
    <img src="https://github.com/gma1k/podtrace/blob/main/assets/podtrace-logo.png" width="420" alt="podtrace logo"/>
  </a>
</p>

A simple but powerful eBPF-based diagnostic tool for Kubernetes applications. Provides comprehensive observability including network tracing (TCP/UDP), file system monitoring, memory tracking, HTTP application-layer tracing, and detailed diagnostic reports.

## Overview

`podtrace` attaches eBPF programs to a single Kubernetes pod's container and prints high-level, human-readable events that help diagnose application issues.

## Documentation

`podtrace` documentation is available in the [`doc/`](doc/) directory.

## Features

### Network Tracing
- **TCP Connection Monitoring**: Tracks TCP IPv4/IPv6 connection latency and errors
- **TCP RTT Analysis**: Detects RTT spikes and retry patterns
- **TCP State Tracking**: Monitors TCP connection state transitions (SYN, ESTABLISHED, FIN, etc.)
- **UDP Network Tracing**: Tracks UDP send/receive operations with latency and bandwidth metrics
- **I/O Bandwidth Tracking**: Monitors bytes transferred for TCP/UDP send/receive operations

### File System Monitoring
- **File Operations**: Tracks read, write, and fsync operations with latency analysis
- **I/O Bandwidth**: Monitors bytes transferred for file read/write operations
- **Throughput Analysis**: Calculates average throughput and peak transfer rates

### Memory & System Events
- **Page Fault Tracking**: Monitors page faults with error code analysis
- **OOM Kill Detection**: Tracks out-of-memory kills with memory usage details

### Application Layer
- **HTTP Tracing**: Framework for HTTP request/response tracking via uprobes (requires per-application configuration)
- **DNS Tracking**: Monitors DNS lookups with latency and error tracking

### System Monitoring
- **CPU/Scheduling Tracking**: Monitors thread blocking and CPU scheduling events
- **CPU Usage per Process**: Shows CPU consumption by process
- **Process Activity Analysis**: Shows which processes are generating events

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
- **Potential Issues**: Automatic detection of high error rates and performance problems

## Running without sudo

After building, set capabilities to run without sudo:

```bash
sudo ./scripts/setup-capabilities.sh
```


---

## Podtrace Prometheus & Grafana Integration

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
| `podtrace_cpu_block_seconds_gauge`       | Latest CPU block time                           |
| `podtrace_cpu_block_seconds_histogram`   | Distribution of CPU block times                 |

## Grafana Dashboard

A ready-to-use Grafana dashboard JSON is included in the repository at `podtrace/internal/metricsexporter/dashboard/Podtrace-Dashboard.json`


## Steps to use:

- Open Grafana and go to Dashboards → New → Import.
- Paste the JSON or upload the .json file.
- Select or your Prometheus datasource as the datasource.
- Import. The dashboard will display per-process and per-event-type metrics for RTT, latency, DNS, FS, and CPU block time.
