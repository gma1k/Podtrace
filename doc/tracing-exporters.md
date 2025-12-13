# Tracing Exporters Setup Guide

This guide provides detailed instructions for setting up and configuring each tracing exporter supported by `Podtrace`.

## Table of Contents

- [OpenTelemetry (OTLP)](#opentelemetry-otlp)
- [Jaeger](#jaeger)
- [Splunk HEC](#splunk-hec)
- [Comparison](#comparison)

## OpenTelemetry (OTLP)

### Overview

OpenTelemetry Protocol (OTLP) is the industry-standard protocol for observability data. `Podtrace` exports traces via OTLP HTTP to any OpenTelemetry-compatible backend.

### Supported Backends

- OpenTelemetry Collector
- Jaeger (via OTLP)
- Grafana Tempo
- Datadog (via OTLP)
- New Relic (via OTLP)
- Any OTLP-compatible backend

### Setup

#### 1. Deploy OpenTelemetry Collector (Recommended)

The OpenTelemetry Collector acts as a central hub for receiving traces and routing them to various backends.

**Kubernetes Deployment Example**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-collector
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: otel-collector
  template:
    metadata:
      labels:
        app: otel-collector
    spec:
      containers:
      - name: otel-collector
        image: otel/opentelemetry-collector:latest
        args:
          - --config=/etc/otel-collector-config.yaml
        volumeMounts:
        - name: otel-collector-config
          mountPath: /etc/otel-collector-config.yaml
          subPath: otel-collector-config.yaml
        ports:
        - containerPort: 4318
          name: otlp-http
        - containerPort: 4317
          name: otlp-grpc
      volumes:
      - name: otel-collector-config
        configMap:
          name: otel-collector-config
---
apiVersion: v1
kind: Service
metadata:
  name: otel-collector
  namespace: monitoring
spec:
  selector:
    app: otel-collector
  ports:
  - name: otlp-http
    port: 4318
    targetPort: 4318
  - name: otlp-grpc
    port: 4317
    targetPort: 4317
```

**Collector Configuration** (`otel-collector-config.yaml`):

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  # Export to Jaeger
  jaeger:
    endpoint: jaeger:14250
    tls:
      insecure: true
  
  # Export to Splunk
  splunk_hec:
    endpoint: https://splunk:8088/services/collector
    token: ${SPLUNK_TOKEN}
    source: podtrace
    sourcetype: otel_trace
  
  # Export to logging (for debugging)
  logging:
    loglevel: debug

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [jaeger, splunk_hec, logging]
```

#### 2. Configure Podtrace

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-otlp-endpoint http://otel-collector.monitoring.svc.cluster.local:4318
```

**Environment Variable**:
```bash
export PODTRACE_TRACING_OTLP_ENDPOINT=http://otel-collector.monitoring.svc.cluster.local:4318
```

### Direct Backend Integration

#### Grafana Tempo

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-otlp-endpoint http://tempo.monitoring.svc.cluster.local:4318
```

#### Datadog

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-otlp-endpoint https://trace-intake.datadoghq.com:4318
```

### Verification

Check OpenTelemetry Collector logs:
```bash
kubectl logs -n monitoring deployment/otel-collector | grep "traces"
```

## Jaeger

### Overview

Jaeger is a popular open-source distributed tracing system. `Podtrace` exports traces directly to Jaeger's HTTP Thrift endpoint.

### Setup

#### 1. Deploy Jaeger

**Kubernetes Deployment (All-in-One)**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jaeger
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: jaeger
  template:
    metadata:
      labels:
        app: jaeger
    spec:
      containers:
      - name: jaeger
        image: jaegertracing/all-in-one:latest
        ports:
        - containerPort: 16686
          name: ui
        - containerPort: 14268
          name: http
        - containerPort: 14250
          name: grpc
        env:
        - name: COLLECTOR_ZIPKIN_HOST_PORT
          value: ":9411"
---
apiVersion: v1
kind: Service
metadata:
  name: jaeger
  namespace: monitoring
spec:
  selector:
    app: jaeger
  ports:
  - name: ui
    port: 16686
    targetPort: 16686
  - name: http
    port: 14268
    targetPort: 14268
  - name: grpc
    port: 14250
    targetPort: 14250
```

#### 2. Configure Podtrace

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-jaeger-endpoint http://jaeger.monitoring.svc.cluster.local:14268/api/traces
```

**Environment Variable**:
```bash
export PODTRACE_TRACING_JAEGER_ENDPOINT=http://jaeger.monitoring.svc.cluster.local:14268/api/traces
```

### Access Jaeger UI

Port-forward to access Jaeger UI:
```bash
kubectl port-forward -n monitoring svc/jaeger 16686:16686
```

Open browser: http://localhost:16686

### Verification

1. Check Jaeger collector logs:
```bash
kubectl logs -n monitoring deployment/jaeger | grep "POST /api/traces"
```

2. Query traces in Jaeger UI:
   - Select service: `Podtrace`
   - Click "Find Traces"

## Splunk HEC

### Overview

Splunk HTTP Event Collector (HEC) is Splunk's API for ingesting events. `Podtrace` exports traces as JSON events to Splunk HEC.

### Setup

#### 1. Configure Splunk HEC Token

1. **Access Splunk Web UI**
2. **Navigate to**: Settings → Data Inputs → HTTP Event Collector
3. **Create New Token**:
   - Name: `Podtrace-tracing`
   - Source type: `Podtrace:trace`
   - Index: `main` (or create dedicated index)
4. **Copy the token**

#### 2. Configure Podtrace

```bash
./bin/podtrace -n production my-pod \
  --tracing \
  --tracing-splunk-endpoint https://splunk.example.com:8088/services/collector \
  --tracing-splunk-token YOUR_HEC_TOKEN
```

**Environment Variables**:
```bash
export PODTRACE_TRACING_SPLUNK_ENDPOINT=https://splunk.example.com:8088/services/collector
export PODTRACE_TRACING_SPLUNK_TOKEN=YOUR_HEC_TOKEN
```

**Using Kubernetes Secret**:
```bash
# Create secret
kubectl create secret generic splunk-hec-token \
  --from-literal=token=YOUR_HEC_TOKEN \
  -n monitoring

# Use in Podtrace (if running as pod)
env:
- name: PODTRACE_TRACING_SPLUNK_TOKEN
  valueFrom:
    secretKeyRef:
      name: splunk-hec-token
      key: token
```

### Splunk Query Examples

#### Find All Traces
```
index=main sourcetype="Podtrace:trace"
```

#### Find Traces by Service
```
index=main sourcetype="Podtrace:trace" service="my-service"
```

#### Find Error Traces
```
index=main sourcetype="Podtrace:trace" error=true
```

### Verification

1. **Check Splunk HEC logs**:
   - Splunk Web UI → Settings → Server Settings → Server Info → Logging
   - Look for HEC ingestion logs

2. **Query Splunk**:
```spl
index=main sourcetype="Podtrace:trace" | head 10
```