<img src="https://github.com/gma1k/podtrace/blob/main/assets/podtrace-logo.png" width="360" alt="podtrace logo"/>

A simple but powerful eBPF-based troubleshooting tool for Kubernetes applications.

## Overview

`podtrace` attaches eBPF programs to a single Kubernetes pod's container and prints high-level, human-readable events that help diagnose application issues.

## Features

- **Network Connection Monitoring**: Tracks TCP connection latency and errors
- **TCP RTT Analysis**: Detects RTT spikes and retry patterns
- **File System Monitoring**: Identifies slow disk operations
- **Process Activity Analysis**: Shows which processes are generating events
- **Diagnose Mode**: Collects events for a specified duration and generates a comprehensive summary report

## Prerequisites

- Linux kernel 5.8+ with BTF support
- Go 1.19+
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
# Trace a pod
./bin/podtrace -n production my-pod --diagnose 10s
```

### Diagnose Report

The diagnose mode generates a report including:
- Summary statistics (total events, events per second)
- Process activity (top processes by event count)
- TCP statistics (RTT, spikes, errors)
- Connection statistics (latency, failures, top targets)
- File system statistics (write/fsync latency)
- Connection patterns and network I/O patterns


## Running without sudo

After building, set capabilities to run without sudo:

```bash
sudo ./scripts/setup-capabilities.sh
```
