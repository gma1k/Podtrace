# Distributed Tracing with Podtrace

## Overview

`Podtrace` supports distributed tracing, allowing you to correlate events. This feature extracts trace context from HTTP requests, correlates events by trace ID, and exports traces to popular observability backends.

## Features

- **Trace Context Extraction**: Automatically extracts trace context from HTTP headers
- **Event Correlation**: Groups events by trace ID to build complete request flows
- **Request Flow Graphs**: Builds directed graphs showing service interactions
- **Multiple Exporters**: Supports OpenTelemetry (OTLP), Jaeger, Splunk HEC, DataDog, and Zipkin
- **Sampling Support**: Configurable sampling rates to control export volume

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    eBPF Layer                           │
│  Network Probes (tcp_sendmsg, tcp_recvmsg)              │
│  + HTTP Header Parsing                                  │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  Event Parser                           │
│          Parse Events + Trace Context                   │
└─────────────────────────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        │                               │
        ▼                               ▼
┌──────────────────┐         ┌──────────────────┐
│  Event Enricher  │         │ Trace Tracker    │
│  (K8s Context)   │         │  (Correlate)     │
└──────────────────┘         └──────────────────┘
        │                               │
        └───────────────┬───────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│              Trace Graph Builder                        │
│           Build Request Flow Graphs                     │
│             Correlate by Trace ID                       │
└─────────────────────────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┬───────────────┐
        │                               │               │
        ▼                               ▼               ▼
┌──────────────────┐         ┌──────────────────┐  ┌──────────────────┐
│  OTLP Exporter   │         │  Jaeger Exporter │  │ Splunk Exporter  │
└──────────────────┘         └──────────────────┘  └──────────────────┘
```

### Trace Context Extraction

`Podtrace` extracts trace context from HTTP/HTTP2 headers (including gRPC metadata) in the following order:

1. **W3C Trace Context** (preferred)
   - `traceparent`: `00-<trace-id>-<span-id>-<flags>`
   - `tracestate`: Additional trace state

2. **B3 Propagation** (Jaeger/Zipkin)
   - `X-B3-TraceId`: Trace ID
   - `X-B3-SpanId`: Span ID
   - `X-B3-ParentSpanId`: Parent span ID
   - `X-B3-Sampled`: Sampling decision

3. **Splunk Trace Context**
   - `X-Request-ID`: Trace ID
   - `X-Span-ID`: Span ID

### Podtrace observes trace context

Podtrace reads the headers above. It does not add, rewrite or forward
them. When a service receives a request with a `traceparent` and makes its
own call downstream, the application is what carries that context forward.
If the application does not carry it, each hop is recorded as a separate
trace, and podtrace cannot join them.

This is deliberate. An eBPF program that is allowed to see plaintext
(`SSL_write`, `tcp_sendmsg`) cannot grow the payload. The layers that can grow
a packet (tc, XDP) see only ciphertext on a TLS connection, and on plaintext
they would have to rewrite TCP sequence numbers under the stack. A prototype
that inserted a header this way corrupted a plain `GET` (the server answered
`400`).

To get connected traces across services, let the application propagate the
context. The least-effort way is
[OpenTelemetry auto-instrumentation](https://opentelemetry.io/docs/kubernetes/operator/automatic/),
which the OpenTelemetry Operator injects per pod with an annotation and no
code change. From then on, podtrace joins its events to the traces the SDK
starts: every L7 event that carries a `traceparent` gets that trace id, and
the response is joined to its request on the same connection.

### Span synthesis for traffic with no trace context

Traffic that carries no trace context produces no spans by default. Set
`synthesizeSpans: true` on the ExporterConfig (the agent reads it as
`PODTRACE_TRACING_SYNTHESIZE_SPANS`) and podtrace mints a span for each
request it sees that has no context. The trace id and span id are derived
from the request's correlation key, so the request event and its response
event land on the same span:

```yaml
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
spec:
  synthesizeSpans: true
```

A synthesized span is always a root span. It records that one request, its
duration and its status, but it has no parent and no children. Two services
talking to each other still produce two unrelated traces. It is off by default
because a backend would otherwise fill with one-span traces for every request.

### Exemplars and kernel aggregation

The workload latency histograms attach the trace id of a sampled request as an
exemplar, which is how a dashboard jumps from a slow bucket to the trace behind
it. An exemplar needs a per-request event. With
`agent.metrics.kernelAggregation` on (the default), the agent folds requests
into a BPF map and skips the ring buffer while no `PodTrace` exists, so no
request identity reaches userspace and the histograms carry no exemplars.
Exemplars come back while a `PodTrace` keeps the ring buffer open. See
[Continuous Metrics](continuous-metrics.md#interaction-with-kernel-side-aggregation).

### Event Correlation

Events are correlated by:
- **Trace ID**: Groups all events belonging to the same distributed trace
- **Span ID**: Identifies individual operations within a trace
- **Parent Span ID**: Links child spans to their parent spans

### Kubernetes Enrichment

Traces are automatically enriched with:
- Pod name and namespace
- Service name (if available)
- Kubernetes labels
- Target service information

## Usage

### Basic Usage

Enable distributed tracing with the `--tracing` flag:

```bash
./bin/podtrace -n production my-pod --tracing
```

### Configure Exporters

#### OpenTelemetry (OTLP)

Export to an OpenTelemetry Collector or compatible backend:

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-otlp-endpoint http://otel-collector:4318
```

**Environment Variable**:
```bash
export PODTRACE_OTLP_ENDPOINT=http://otel-collector:4318
```

#### Jaeger

Export directly to Jaeger collector:

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-jaeger-endpoint http://jaeger:14268/api/traces
```

**Environment Variable**:
```bash
export PODTRACE_JAEGER_ENDPOINT=http://jaeger:14268/api/traces
```

#### Splunk HEC

Export to Splunk HTTP Event Collector:

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-splunk-endpoint https://splunk:8088/services/collector \
  --tracing-splunk-token YOUR_HEC_TOKEN
```

**Environment Variables**:
```bash
export PODTRACE_SPLUNK_ENDPOINT=https://splunk:8088/services/collector
export PODTRACE_SPLUNK_TOKEN=YOUR_HEC_TOKEN
```

#### DataDog

Export to a DataDog Agent (v0.4 traces API) or directly to the DataDog backend using an API key:

```bash
# Via local DataDog Agent (no API key required)
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-datadog-endpoint http://datadog-agent:8126/v0.4/traces

# Direct to DataDog backend (API key required)
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-datadog-endpoint https://trace.agent.datadoghq.com/v0.4/traces \
  --tracing-datadog-api-key YOUR_DD_API_KEY
```

**Environment Variables**:
```bash
export PODTRACE_DATADOG_ENDPOINT=http://datadog-agent:8126/v0.4/traces
export PODTRACE_DATADOG_API_KEY=YOUR_DD_API_KEY   # optional, agent mode needs no key
```

#### Zipkin

Export to a Zipkin server (v2 JSON API):

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-zipkin-endpoint http://zipkin:9411/api/v2/spans
```

**Environment Variable**:
```bash
export PODTRACE_ZIPKIN_ENDPOINT=http://zipkin:9411/api/v2/spans
```

### Sampling

Control the volume of exported traces with sampling:

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-sample-rate 0.1 \
  --tracing-otlp-endpoint http://otel-collector:4318
```

- `0.0`: No traces exported
- `0.1`: 10% of traces exported
- `1.0`: All traces exported (default)

**Environment Variable**:
```bash
export PODTRACE_TRACING_SAMPLE_RATE=0.1
```

### Multiple Exporters

You can enable multiple exporters simultaneously:

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-otlp-endpoint http://otel-collector:4318 \
  --tracing-jaeger-endpoint http://jaeger:14268/api/traces \
  --tracing-splunk-endpoint https://splunk:8088/services/collector \
  --tracing-splunk-token YOUR_TOKEN \
  --tracing-datadog-endpoint http://datadog-agent:8126/v0.4/traces \
  --tracing-zipkin-endpoint http://zipkin:9411/api/v2/spans \
  --tracing-sample-rate 0.5
```

## Configuration

All tracing configuration can be set via:
- Command-line flags (preferred for one-time use)
- Environment variables (preferred for automation)

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PODTRACE_TRACING_ENABLED` | Enable distributed tracing | `false` |
| `PODTRACE_OTLP_ENDPOINT` | OTLP endpoint (HTTP) | - |
| `PODTRACE_JAEGER_ENDPOINT` | Jaeger collector endpoint | - |
| `PODTRACE_SPLUNK_ENDPOINT` | Splunk HEC endpoint | - |
| `PODTRACE_SPLUNK_TOKEN` | Splunk HEC token | - |
| `PODTRACE_DATADOG_ENDPOINT` | DataDog Agent traces endpoint | `http://localhost:8126/v0.4/traces` |
| `PODTRACE_DATADOG_API_KEY` | DataDog API key (direct ingest only) | - |
| `PODTRACE_ZIPKIN_ENDPOINT` | Zipkin v2 spans endpoint | `http://localhost:9411/api/v2/spans` |
| `PODTRACE_TRACING_SAMPLE_RATE` | Sampling rate (0.0-1.0) | `1.0` |

### Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--tracing` | Enable distributed tracing | `false` |
| `--tracing-otlp-endpoint` | OTLP endpoint | - |
| `--tracing-jaeger-endpoint` | Jaeger endpoint | - |
| `--tracing-splunk-endpoint` | Splunk HEC endpoint | - |
| `--tracing-splunk-token` | Splunk HEC token. Prefer `PODTRACE_SPLUNK_TOKEN`: a flag value is visible in the process list | - |
| `--tracing-datadog-endpoint` | DataDog Agent endpoint | - |
| `--tracing-datadog-api-key` | DataDog API key | - |
| `--tracing-zipkin-endpoint` | Zipkin v2 endpoint | - |
| `--tracing-sample-rate` | Sampling rate (0.0-1.0) | `1.0` |

## Request Flow Graphs

`Podtrace` builds request flow graphs showing service interactions:

- **Nodes**: Services/pods in your cluster
- **Edges**: HTTP requests between services
- **Metadata**: Latency, error counts, request counts per edge

Graphs can be exported in DOT format for visualization with Graphviz.

## Span identity

Spans arrive under the **observed workload's** name, not podtrace's.
`service.name` is the workload, `service.namespace` its namespace, and
podtrace identifies itself as the instrumentation through
`telemetry.sdk.name`. That is what makes a workload appear as itself in
Jaeger's service list rather than every traced pod collapsing into a single
`podtrace` entry.

Mechanically, `service.name` is a Resource attribute and a Resource is bound
to a TracerProvider, so podtrace keeps one lightweight provider per observed
workload. They all share a single span processor, queue and exporter, so the
cost is a map entry per workload rather than a full export pipeline. Idle
providers are dropped after ten minutes; past 256 workloads on one node,
further events fall back to a shared provider rather than evicting live ones.

Events with no resolvable workload — no namespace or no owner — keep the
agent's own identity, because an empty `service.name` is worse than an
honest one.
