<p align="center">
  <a href="https://github.com/gma1k/podtrace">
    <img src="https://github.com/gma1k/podtrace/blob/main/assets/podtrace-logo.png" width="420" alt="Podtrace logo"/>
  </a>
</p>

<p align="center">
  <a href="https://artifacthub.io/packages/helm/podtrace/podtrace"><img src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/podtrace" alt="Artifact Hub"/></a>
  <a href="https://ebpf.io/applications/"><img src="https://img.shields.io/badge/eBPF%20Landscape-podtrace-blue" alt="eBPF Landscape"/></a>
  <a href="https://www.bestpractices.dev/projects/12882"><img src="https://www.bestpractices.dev/projects/12882/badge" alt="OpenSSF Best Practices"/></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/gma1k/podtrace"><img src="https://img.shields.io/ossf-scorecard/github.com/gma1k/podtrace?label=openssf%20scorecard" alt="OpenSSF Scorecard"/></a>
  <a href="https://github.com/gma1k/podtrace/blob/main/docs/supply-chain.md"><img src="https://slsa.dev/images/gh-badge-level2.svg" alt="SLSA Build Level 2"/></a>
  <a href="https://pkg.go.dev/github.com/gma1k/podtrace"><img src="https://pkg.go.dev/badge/github.com/gma1k/podtrace.svg" alt="Go Reference"/></a>  
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"/></a>
  <a href="https://opensource.org/licenses/GPL-2.0"><img src="https://img.shields.io/badge/BPF%20License-GPL_2.0-blue.svg" alt="BPF License: GPL 2.0"/></a>
  <a href="https://app.fossa.com/projects/custom%2B62379%2Fgithub.com%2Fgma1k%2Fpodtrace?ref=badge_shield&issueType=license"><img src="https://app.fossa.com/api/projects/custom%2B62379%2Fgithub.com%2Fgma1k%2Fpodtrace.svg?type=shield&issueType=license" alt="FOSSA License Status"/></a>
  <a href="https://app.fossa.com/projects/custom%2B62379%2Fgithub.com%2Fgma1k%2Fpodtrace?ref=badge_shield&issueType=security"><img src="https://app.fossa.com/api/projects/custom%2B62379%2Fgithub.com%2Fgma1k%2Fpodtrace.svg?type=shield&issueType=security" alt="FOSSA Security Status"/></a>
  <a href="https://www.repo-grade.com/report/gma1k/podtrace"><img src="https://www.repo-grade.com/api/badge/gma1k/podtrace" alt="RepoGrade"/></a>
  <a href="https://github.com/gma1k/podtrace/releases/latest"><img src="https://img.shields.io/github/v/release/gma1k/podtrace?sort=semver&display_name=tag&label=version" alt="Version"/></a>
  <a href="https://github.com/gma1k/podtrace/actions/workflows/go-ci.yml?query=branch%3Amain"><img src="https://img.shields.io/github/actions/workflow/status/gma1k/podtrace/go-ci.yml?branch=main&label=build" alt="Build"/></a>
  <a href="https://github.com/gma1k/podtrace/actions/workflows/go-ci.yml?query=branch%3Amain"><img src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/gma1k/5935cb4275b5ae9369b2b8cb097ae0e2/raw/podtrace-go-tests.json" alt="Tests"/></a>
  <a href="https://github.com/gma1k/podtrace/actions/workflows/go-ci.yml?query=branch%3Amain"><img src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/gma1k/5935cb4275b5ae9369b2b8cb097ae0e2/raw/podtrace-go-coverage.json" alt="Coverage"/></a>
</p>

Podtrace is an eBPF-driven observability tool for Kubernetes, with no code changes, no sidecars and no instrumentation. It works in two ways from one agent:

- **Always on.** Every pod on every node reports its golden signals continuously: request rate, errors and latency per workload, plus network, DNS, TLS, filesystem, CPU and connection-pool health. Podtrace watches those signals, raises an issue when something is wrong, names its likely root cause, and can start a deep-dive on the affected pod by itself.
- **On demand.** Point it at a pod, or at a whole application across all its pods, and it records everything they do for as long as you ask: network flows, TCP and UDP performance, file activity, system calls, and application events such as HTTP/1, HTTP/2, HTTP/3, gRPC, DNS and database queries, then explains what it found in a report.

The always-on side tells you *which* workload is unhealthy, cheaply and at low cardinality. The on-demand side tells you *why*, in depth, for the pods you point it at.

## Overview

Podtrace attaches eBPF programs directly to the container, allowing it to observe real behavior as it happens at runtime. It automatically correlates low-level kernel activity with high-level application operations, surfacing clear, human-readable diagnostic events that reveal what the pod is experiencing internally.

Instead of assembling data from multiple systems or modifying application code, Podtrace provides deep operational visibility in one place, enabling you to understand:

- Why a service is slow  
- Where latency originates  
- How network and I/O resources are being used  
- Which operations block or fail  
- How requests flow through the application  
- What happens inside the pod during incidents  

By combining system-level details, application-layer insights, and real-time event correlation, Podtrace is effective for debugging, performance analysis, and production incident response in Kubernetes environments, especially when time, context, or access is limited.

## Continuous APM

Once the operator is installed, the agent on every node measures every pod, with no configuration.

```text
KERNEL     eBPF probes ──┬──► ringbuf ─────────── one event at a time ──────────────┐
                         └──► LRU per-CPU map ─── aggregated in the kernel ─────┐   │
                                                                                │   │
AGENT      tracer engine ◄──────────────────────────────────────────────────────┼───┘
(per node)    │                                                                 │
              ├──► router (per CR, sampled) ──► exporters ──► traces & events   │   on demand
              │                                                                 │
              └──► metrics sink (every pod) ◄───────────────────────────────────┘   continuous
                      ├──► /metrics or OTLP ──► Prometheus, Grafana, any OTLP backend
                      └──► inspections ──► issue ──► Event on the pod ──► deep-dive session

OPERATOR   reads every agent's issues ──► likely root cause, across workloads
```

What you get:

- **Golden signals per workload.** Rate, errors and latency for HTTP, gRPC, databases, caches and messaging, plus network, DNS, TLS, filesystem, CPU and connection-pool metrics, labelled by namespace and workload, so a series survives a rollout. Scraped by Prometheus (a PodMonitor ships with the chart) or pushed over OTLP.
- **OpenTelemetry semantic conventions.** Signals such as `http.server.request.duration` are emitted beside the native `podtrace_*` names, so stock Grafana, Datadog and Honeycomb dashboards work as they are.
- **A service map.** Every call carries both ends of the edge, so the map is a PromQL query, and the bundled Grafana dashboard draws it.
- **Issues, not thresholds.** Rules for error rate, latency, connection failures, RTT spikes, resource and pool saturation, CPU contention, slow and failing DNS, slow storage and TLS handshake failures raise `podtrace_issue_active` and a Kubernetes Event on the affected pod.
- **Likely root causes.** Issues are linked to what likely caused them, on the same workload and through the workloads it calls: front is slow because backend is slow, because backend's connection pool is saturated.
- **From finding to explaining.** A `PodTraceSchedule` with an `Issue` trigger starts a deep-dive session on the affected pod, and its report opens with the issue that started it.
- **`kubectl podtrace status`** shows fleet health, active issues with their likely causes, and the busiest workloads, with no metrics backend.

See [docs/continuous-metrics.md](docs/continuous-metrics.md) for the metrics and
[docs/continuous-inspections.md](docs/continuous-inspections.md) for the issues and
their likely causes.

## Documentation

Podtrace documentation is available in the [`docs/`](docs/) directory.
See [ROADMAP.md](ROADMAP.md) for where the project is heading and
[STABILITY.md](STABILITY.md) for what each version promises.

Podtrace runs privileged and loads eBPF into your kernel, so every release
artifact ships SLSA v1.0 Build L2 provenance you can verify, and enforce at
admission time. See [docs/supply-chain.md](docs/supply-chain.md).

## Usage patterns

Podtrace ships one binary. Pick the workflow that fits:

### 1. Standalone CLI binary

Best for ad-hoc, interactive debugging from a workstation or a
privileged debug pod. Install via signed tarball:

```bash
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_linux_amd64.tar.gz \
  | sudo tar xz -C /usr/local/bin podtrace
```

(`/usr/local/bin` needs `sudo`. To install
without sudo, extract to a user-writable directory on `$PATH` instead, e.g.
`mkdir -p ~/.local/bin && tar xz -C ~/.local/bin podtrace`.)

Or via [krew](https://krew.sigs.k8s.io/):

```bash
kubectl krew install podtrace
kubectl podtrace -n production my-pod
```

Then:

```bash
# Realtime trace
podtrace -n production my-pod

# Bounded diagnose with a JSON report
podtrace -n production my-pod --diagnose 30s --export json > report.json
```

By default the CLI spawns a privileged pod on the target pod's node and
runs eBPF there — works on Talos, EKS, GKE, AKS, OpenShift, and any
cluster where your workstation is not the kubelet host. On kind /
minikube / docker-desktop the workstation **is** the kubelet host, so
add `--local` to skip the spawn and load eBPF on the workstation
directly (faster, no privileged pod needed):

```bash
podtrace --local -n production my-pod
```

For other platforms (linux/arm64, darwin/amd64, darwin/arm64) and
cosign-verifiable installs, see
[docs/installation.md#install-the-cli](docs/installation.md#install-the-cli).
The CLI architecture (when to use `--local`, RBAC needed for the spawn
path, etc.) is documented in
[docs/cli-architecture.md](docs/cli-architecture.md).
Full CLI reference: [docs/usage.md](docs/usage.md).

### 2. Continuous tracing via the `PodTrace` CR

Best for long-running observability: have the operator watch a
selector cluster-wide and stream events through an agent DaemonSet.

```yaml
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata: { name: prod-otlp, namespace: my-app }
spec:
  type: otlp
  otlp: { endpoint: otel-collector.observability:4318, protocol: http, insecure: true }
---
apiVersion: podtrace.io/v1alpha1
kind: PodTrace
metadata: { name: watch-api, namespace: my-app }
spec:
  selector: { matchLabels: { app: api } }
  filters: [dns, net]
  exporterRef: { name: prod-otlp }
```

```bash
kubectl apply -f trace.yaml
kubectl get podtraces.podtrace.io watch-api -n my-app -o yaml
```

Or skip the YAML and let the CLI author the `PodTrace` for you — target a
whole application by label, across every namespace, and it keeps tracing
through pod restarts and rollouts until you delete it:

```bash
# Trace an application everywhere, continuously:
podtrace watch --app api --all-namespaces --exporter prod-otlp

# Or target with any label selector (--label), scoped to one namespace:
podtrace watch --label app=api,tier=web -n my-app --name api-web --exporter prod-otlp

# Render the manifest instead of applying it:
podtrace watch --app api --all-namespaces --print-only
```

The same `--app`/`--label`/`--all-namespaces` targeting also works on the plain
`podtrace` command for **ephemeral** tracing (stream to your terminal, no CR):

```bash
podtrace --app api -n my-app --diagnose 30s --filter dns,net
```

Rule of thumb: `podtrace <targeting>` = look now (terminal);
`podtrace watch <targeting>` = record continuously (exporter);
`podtrace status` = what the always-on agents see across the cluster: fleet
health, active issues and the busiest workloads, with no metrics backend.

Full reference: [docs/crd-podtrace.md](docs/crd-podtrace.md).

### 3. Bounded diagnose via the `PodTraceSession` CR

Best for repeatable, GitOps-driven diagnose runs that produce a
shareable report artifact. Equivalent to the CLI's `--diagnose` mode
but operator-managed and multi-tenant.

```yaml
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: diag-api, namespace: my-app }
spec:
  selector: { matchLabels: { app: api } }
  duration: 30s
  filters: [dns, net]
  exporterRef: { name: prod-otlp }
  reportRef:
    configMap: { name: api-diag-report }
```

```bash
kubectl apply -f session.yaml
kubectl get podtracesession diag-api -n my-app -w   # wait for Completed
kubectl get cm api-diag-report -n my-app -o go-template='{{range $k,$v := .data}}{{$v}}{{end}}' | less
```

This path runs the same eBPF stack the CLI uses, but as a per-node
privileged Job. Results land in three parallel channels:

- `status.summary` — aggregated event counts
- `status.jobs[].totalEvents` — per-node breakdown
- `reportRef.configMap` (or `.secret`) — full human-readable report

Full reference: [docs/crd-podtracesession.md](docs/crd-podtracesession.md).

### 4. Recurring diagnose via the `PodTraceSchedule` CR

Best for nightly diagnose sweeps and on-call probes where you want the
last N runs ready to inspect on demand. The schedule fires a fresh
`PodTraceSession` on every cron tick, owns each child via owner
references, and prunes history per the configured limits.

```yaml
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSchedule
metadata: { name: nightly-diagnose, namespace: my-app }
spec:
  schedule: "0 2 * * *"
  concurrencyPolicy: Forbid
  successfulSessionsHistoryLimit: 7
  sessionTemplate:
    spec:
      selector: { matchLabels: { app: api } }
      duration: 5m
      filters: [dns, net]
      exporterRef: { name: prod-otlp }
```

Manual one-off trigger from the CLI:

```bash
kubectl podtrace schedule trigger nightly-diagnose -n my-app
```

Full reference: [docs/crd-podtraceschedule.md](docs/crd-podtraceschedule.md).

### Install the operator

The fastest path is the **one-shot quickstart manifest** —
operator + CRDs + a sample nginx workload + `PodTraceSession` that reaches `state: Completed` and writes a report to a ConfigMap. Single `kubectl apply`, no Helm, no clone, no
build toolchain:

```bash
kubectl apply -f https://github.com/gma1k/podtrace/releases/latest/download/quickstart.yaml

# Watch the demo session reach Completed (~45-60s end-to-end)
kubectl get podtracesession demo-trace -n podtrace-demo -w

# Read the report
kubectl get cm nginx-trace-report -n podtrace-demo \
  -o go-template='{{range $k,$v := .data}}{{$v}}{{end}}'

# Tear down the demo (operator + sample workload + CRDs)
kubectl delete ns podtrace-system podtrace-demo
kubectl delete crd -l app.kubernetes.io/name=podtrace
```

On OpenShift or any OLM-managed cluster, podtrace is also available
via the [OperatorHub.io community catalog](https://operatorhub.io/operator/podtrace):

```bash
# OpenShift Console: Operators → OperatorHub → search "podtrace" → Install
# Or apply the Subscription manifest directly:
kubectl apply -f - <<EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata: { name: podtrace, namespace: operators }
spec:
  channel: stable
  name: podtrace
  source: operatorhubio-catalog
  sourceNamespace: olm
EOF
```

For production Helm-managed deployments — custom values, validating
webhook, multi-tenant agent config — install via the published OCI
chart in GHCR:

```bash
helm install podtrace oci://ghcr.io/gma1k/charts/podtrace \
  --namespace podtrace-system --create-namespace
```

Verify the image was built by this repository:

```bash
cosign verify ghcr.io/gma1k/podtrace:latest \
  --certificate-identity-regexp 'https://github.com/gma1k/podtrace/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For prerequisites, supported kernels, and per-distro notes see
[docs/installation.md](docs/installation.md) and
[docs/compatibility.md](docs/compatibility.md). For chart values and
operator architecture see [docs/operator.md](docs/operator.md).

Building from source (for contributors or air-gapped clusters) is
covered below under [Building](#building).

### Coming from the CLI

If you're already a CLI user and want a translation table from the CLI
to CRs, see [docs/migration.md](docs/migration.md).

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
- **File Path Tracking**: Captures full file paths
- **I/O Bandwidth**: Monitors bytes transferred for file read/write operations
- **Throughput Analysis**: Calculates average throughput and peak transfer rates

### Memory & System Events
- **Page Fault Tracking**: Monitors page faults with error code analysis
- **OOM Kill Detection**: Tracks out-of-memory kills with memory usage details

### Application Layer
- **HTTP Tracing**: Captures request method and path with response status and latency across HTTP/1.x, HTTP/2, and HTTP/3 over QUIC, for both clients and servers
- **HTTP-over-TLS L7**: Reads plaintext HTTP before encryption / after decryption via uprobes on OpenSSL, BoringSSL and GnuTLS, Go, Node.js, Java over a native TLS provider, and Rust.
- **L7 ↔ L4 Peer Fusion**: Annotates HTTP/1.x and HTTP/2 request/response events with the underlying TCP 4-tuple
- **DNS Tracking**: Monitors DNS lookups with latency and error tracking
- **Database Query Tracing**: Tracks PostgreSQL and MySQL query execution with pattern extraction and latency analysis
- **TLS/SSL Handshake Tracking**: Track TLS handshake latency, errors and failures
- **Connection Pool Monitoring**: Tracks connection pool usage, monitors pool exhaustion, and tracks connection reuse patterns
- **Redis Tracing**: Captures hiredis `redisCommand` / `redisCommandArgv` calls with command name and latency (no application changes required)
- **Memcached Tracing**: Captures libmemcached `get`, `set`, and `delete` operations with key and value size
- **FastCGI / PHP-FPM Tracing**: Tracks FastCGI request URI, method, and end-to-end latency via unix-socket kprobes (BTF-only)
- **gRPC Method Tracing**: Extracts gRPC method paths from HTTP/2 HEADERS frames via a second kprobe on `tcp_sendmsg` (BTF-only)
- **Kafka Tracing**: Tracks librdkafka `rd_kafka_produce` and `rd_kafka_consumer_poll` with topic name, payload size, and latency
- **USDT Auto-Detection**: Scans ELF binaries for `.note.stapsdt` sections and reports available userspace tracepoints
- **Critical Path Reconstruction**: Automatically correlates per-request latency segments by PID and emits a breakdown on HTTP/FastCGI/gRPC response boundaries
- **PII Redaction**: Applies configurable regex rules to scrub passwords, Bearer tokens, email addresses, and credit card numbers from event fields before dispatch

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

### Multi-Pod Tracing
- **Dynamic Multi-Pod Targeting**: Trace multiple pods in one run using explicit pod lists, label selectors, or namespace-wide selection
- **Cross-Namespace Support**: Trace pods across namespaces with `--namespaces` and selector-based targeting
- **Live Target Updates**: Automatically refresh target pod/cgroup filters when pods are added, updated, or deleted

### Distributed Tracing
- **Trace Context Extraction**: Automatically extracts trace context from HTTP/HTTP2 headers and gRPC metadata
- **Event Correlation**: Groups events by trace ID to build complete request flows across services
- **Request Flow Graphs**: Builds directed graphs showing service interactions with latency and error metrics
- **Multiple Exporters**: Supports OpenTelemetry (OTLP), Jaeger, Splunk HEC, Datadog, and Zipkin
- **Sampling Support**: Configurable sampling rates to control export volume

### Performance Profiling
- **pprof & perf Integration**: Discovers and fetches heap, goroutine, and CPU profiles from target pod pprof HTTP endpoints
- **On-demand Profiling Triggers**: Activate profiling via the `/profile/start` management endpoint or automatically when slow events exceed configurable thresholds
- **CPU/Memory Profiling Correlation**: Ties BPF `SchedSwitch` stack traces to slow events, surfacing the exact goroutine and CPU stacks active during high-latency periods
- **BPF ktime ↔ Wall-clock Alignment**: Derives a monotonic offset so kernel timestamps map accurately to wall time for precise correlation
- **Profiling Section in Reports**: Correlation results are appended to both diagnose-mode and normal-mode reports

### Diagnostics
- **Diagnose Mode**: Collects events for a specified duration and generates a comprehensive summary report

### Alerting
- **Real-time Alerts**: Sends immediate notifications when fatal, critical, or warning-level issues are detected
- **Multiple Channels**: Supports webhooks, Slack, and Splunk HEC for alert delivery
- **Smart Deduplication**: Prevents alert storms with configurable deduplication windows
- **Rate Limiting**: Configurable rate limits to prevent overwhelming notification systems

## Prerequisites

- Linux kernel 5.8+ with BTF support
- Go 1.27+ (or any earlier 1.x with `GOTOOLCHAIN=auto`)
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
- **HTTP Statistics**: Request/response counts, latency analysis, bandwidth metrics, top requested + response endpoints (method/path/status) and status-code breakdown
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

## License

Podtrace is dual-licensed:

- **Go code** is licensed under the [Apache License 2.0](LICENSE).
- **eBPF programs** under [`bpf/`](bpf/) are licensed under **GPL-2.0** (declared via `SPDX-License-Identifier: GPL-2.0` headers). The GPL declaration is required for BPF programs to access kernel helpers via the BPF verifier.
