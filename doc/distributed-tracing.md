# Distributed Tracing with podtrace

## Overview

`podtrace` supports distributed tracing, allowing you to correlate events. This feature extracts trace context from HTTP requests, correlates events by trace ID, and exports traces to popular observability backends.

## Features

- **Trace Context Extraction**: Automatically extracts trace context from HTTP headers
- **Event Correlation**: Groups events by trace ID to build complete request flows
- **Request Flow Graphs**: Builds directed graphs showing service interactions
- **Multiple Exporters**: Supports OpenTelemetry (OTLP), Jaeger, and Splunk HEC
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

`podtrace` extracts trace context from HTTP/HTTP2 headers (including gRPC metadata) in the following order:

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
export PODTRACE_TRACING_OTLP_ENDPOINT=http://otel-collector:4318
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
export PODTRACE_TRACING_JAEGER_ENDPOINT=http://jaeger:14268/api/traces
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
export PODTRACE_TRACING_SPLUNK_ENDPOINT=https://splunk:8088/services/collector
export PODTRACE_TRACING_SPLUNK_TOKEN=YOUR_HEC_TOKEN
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
| `PODTRACE_TRACING_OTLP_ENDPOINT` | OTLP endpoint (HTTP) | - |
| `PODTRACE_TRACING_JAEGER_ENDPOINT` | Jaeger collector endpoint | - |
| `PODTRACE_TRACING_SPLUNK_ENDPOINT` | Splunk HEC endpoint | - |
| `PODTRACE_TRACING_SPLUNK_TOKEN` | Splunk HEC token | - |
| `PODTRACE_TRACING_SAMPLE_RATE` | Sampling rate (0.0-1.0) | `1.0` |

### Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--tracing` | Enable distributed tracing | `false` |
| `--tracing-otlp-endpoint` | OTLP endpoint | - |
| `--tracing-jaeger-endpoint` | Jaeger endpoint | - |
| `--tracing-splunk-endpoint` | Splunk HEC endpoint | - |
| `--tracing-splunk-token` | Splunk HEC token | - |
| `--tracing-sample-rate` | Sampling rate (0.0-1.0) | `1.0` |

## Request Flow Graphs

`podtrace` builds request flow graphs showing service interactions:

- **Nodes**: Services/pods in your cluster
- **Edges**: HTTP requests between services
- **Metadata**: Latency, error counts, request counts per edge

Graphs can be exported in DOT format for visualization with Graphviz.