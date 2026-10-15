# Metrics and Monitoring

## Overview

Podtrace exposes Prometheus metrics for integration with monitoring systems
like Prometheus and Grafana.

This page documents the **diagnostic** metrics surface: the endpoint the CLI
opens behind `--metrics` for the duration of one tracing run. It is scoped to
the pods that run is targeting, it lives and dies with the process, and its
labels are shaped for reading a single investigation, `process_name` and
`target_pod` are useful over sixty seconds and expensive forever.

The **continuous** surface, exposed by the always-on agent and intended for a
permanent Prometheus scrape, is a separate surface with a different label
model. It is documented in [continuous-metrics.md](continuous-metrics.md)
rather than by extending the tables below, and nothing on this page changes
as it grows.

## Surface stability

Metric names and label keys are a compatibility surface, governed by the same
rule as CLI flags and Helm values: **minor releases may rename or restructure
them, patch releases will not.** See the *Metrics surface* section of
[STABILITY.md](../STABILITY.md) for the full statement, including which parts
carry no promise.

The authoritative inventory is not this page — it is
[`internal/metricsexporter/testdata/metric-surface.txt`](../internal/metricsexporter/testdata/metric-surface.txt),
a committed snapshot of every metric name and its label keys. A change to the
exported surface fails `TestMetricSurfaceMatchesSnapshot` until the snapshot is
regenerated, and `TestDocumentedMetricsMatchSnapshot` fails if this page and
the snapshot disagree. Both exist so that surface drift is caught mechanically
rather than by review.

## Naming

Two naming schemes coexist, deliberately:

- **`podtrace_*`** — the native names. Every metric has one. The names on this
  page are all of this form and none of them are going away.
- **OpenTelemetry semantic conventions** — `http.server.request.duration`,
  `rpc.server.duration`, `db.client.operation.duration` and friends. The
  continuous surface will emit these *in addition to* the native names, so
  that stock Grafana, Datadog and Honeycomb dashboards work against podtrace
  with no configuration.

Dual emission is a deliberate trade: it doubles the series each covered metric
produces, and the continuous surface's cardinality budget is sized for that
from the outset rather than discovering it in production.

Semantic conventions only cover protocols the OpenTelemetry project has
defined conventions for. Podtrace's distinguishing protocol work — HTTP/3 with
QPACK, FastCGI, rustls, Kafka internals — has no convention to follow, so
those metrics are `podtrace_*` only. That is a gap in the conventions, not in
podtrace, and where a convention appears later podtrace adopts it additively.

## Quick Reference

Workload metrics, derived from observed traffic. These are the contractual
surface.

| Metric | Description |
|---|---|
| `podtrace_rtt_seconds` | Histogram of TCP RTTs |
| `podtrace_rtt_latest_seconds` | Most recent TCP RTT |
| `podtrace_latency_seconds` | Histogram of TCP send/receive latency |
| `podtrace_latency_latest_seconds` | Most recent TCP latency |
| `podtrace_dns_latency_seconds_gauge` | Latest DNS query latency |
| `podtrace_dns_latency_seconds_histogram` | Distribution of DNS query latencies |
| `podtrace_fs_latency_seconds_gauge` | Latest file system operation latency |
| `podtrace_fs_latency_seconds_histogram` | Distribution of file system operation latencies |
| `podtrace_network_bytes_total` | Total bytes transferred over network (TCP/UDP) |
| `podtrace_filesystem_bytes_total` | Total bytes transferred via filesystem ops |
| `podtrace_cpu_block_seconds_gauge` | Latest CPU block time |
| `podtrace_cpu_block_seconds_histogram` | Distribution of CPU block times |
| `podtrace_resource_limit_bytes` | Resource limit in bytes (CPU/Memory/I/O) |
| `podtrace_resource_usage_bytes` | Current resource usage in bytes |
| `podtrace_resource_utilization_percent` | Resource utilization percentage |
| `podtrace_resource_alert_level` | Resource alert level (0=none, 1=warning, 2=critical, 3=emergency) |
| `podtrace_pool_acquires_total` | Total connection pool acquires |
| `podtrace_pool_releases_total` | Total connection pool releases |
| `podtrace_pool_exhausted_total` | Total pool exhaustion events |
| `podtrace_pool_wait_seconds` | Histogram of pool wait times |
| `podtrace_redis_latency_seconds` | Distribution of Redis command latencies |
| `podtrace_memcached_latency_seconds` | Distribution of Memcached operation latencies |
| `podtrace_fastcgi_latency_seconds` | Distribution of FastCGI request latencies |
| `podtrace_grpc_latency_seconds` | Distribution of gRPC method call latencies |
| `podtrace_kafka_latency_seconds` | Distribution of Kafka produce/consume latencies |
| `podtrace_kafka_bytes_total` | Total bytes in Kafka produce/consume operations |
| `podtrace_attribution_total` | Process-identity attribution outcome per event, labeled `source` (`event_comm`/`correlator`/`proc_fallback`/`none`) and `event` (`dns`/`quic`/`other`) |
| `podtrace_attribution_pid_reuse_suspected_total` | Attribution lookups rejected on a cgroup mismatch (suspected pid reuse) |

### Agent and collector internals

These describe podtrace's own health, not the workload. They track internal
structure and **carry no compatibility promise** — they may be renamed,
relabelled or removed in any release, including a patch. Alert on them for
operating podtrace, but do not build a product surface on them.

| Metric | Description |
|---|---|
| `podtrace_ring_buffer_drops_total` | Events lost because the BPF ring buffer was full |
| `podtrace_dns_drops_total` | DNS events dropped in the kernel |
| `podtrace_filtered_event_drops_total` | Events discarded by the userspace filter |
| `podtrace_event_tee_aux_drops_total` | Events dropped by the auxiliary tee sink |
| `podtrace_l7_decoder_drops_total` | Records or sections the userspace L7 decoders discarded, labeled `decoder` (`h2`/`h3`) and `reason` (h3 `shutdown` counts transactions still awaiting their inbound headers when the agent stops) |
| `podtrace_l7_decoder_retained_bytes` | Traffic-controlled state an L7 decoder holds, labeled `decoder` |
| `podtrace_event_processing_latency_seconds` | Time to process one event in userspace |
| `podtrace_event_channel_depth` | Current depth of each internal event channel, labeled `channel` |
| `podtrace_bpf_map_utilization_ratio` | Fill ratio per BPF map, labeled `map` |
| `podtrace_errors_total` | Errors seen while processing events, labeled `event_type` and `error_code` |
| `podtrace_process_cache_hits_total` | Process-metadata cache hits |
| `podtrace_process_cache_misses_total` | Process-metadata cache misses |
| `podtrace_pid_cache_hits_total` | PID-lookup cache hits |
| `podtrace_pid_cache_misses_total` | PID-lookup cache misses |

### TLS handshake metrics

| Metric | Description |
|---|---|
| `podtrace_tls_handshakes_total` | TLS handshakes observed, labeled `type` |
| `podtrace_tls_handshake_latency_seconds` | Distribution of TLS handshake durations |
| `podtrace_tls_handshake_latency_latest_seconds` | Most recent TLS handshake duration |

A handshake is counted once, when it ends. A non-blocking server calls the
handshake function several times per connection, and a call that only asks
to be called again (OpenSSL's `SSL_ERROR_WANT_READ`, GnuTLS's `GNUTLS_E_AGAIN`,
mbedTLS's `MBEDTLS_ERR_SSL_WANT_READ`, and the like) is neither a handshake nor
a failure. An OpenSSL handshake that fails with `-1` is told apart from a retry
by the `SSL_get_error` call that follows it, and carries that function's
result, negated, as its error. This is verified against OpenSSL 3.5, LibreSSL
4.1, GnuTLS 3.8 and mbedTLS 3.6 with non-blocking clients; OpenSSL 1.0 is not
verified.

### Profiling metrics

Emitted only when profiling is enabled; see [profiling.md](profiling.md).

| Metric | Description |
|---|---|
| `podtrace_profiling_goroutines` | Goroutine count from the last pprof fetch, labeled `pod_ip` and `state` |
| `podtrace_profiling_auto_triggers_total` | Profile fetches started by an automatic trigger |
| `podtrace_profiling_fetch_errors_total` | Failed pprof fetches, labeled `pod_ip` and `profile_type` |

## Enabling Metrics

Metrics are enabled when you run Podtrace with the `--metrics` flag. By default, the metrics server starts on `127.0.0.1:3000`.

```bash
./bin/podtrace -n production my-pod --metrics
```

Access metrics at (default address):
```
http://localhost:3000/metrics

To change the bind address and port, set the `PODTRACE_METRICS_ADDR` environment variable before running Podtrace, for example:

```bash
PODTRACE_METRICS_ADDR="0.0.0.0:3000" ./bin/podtrace -n production my-pod --metrics
```
```

## Available Metrics

All metrics are labeled with:
- `type`: Event type (NET, DNS, FS, CPU)
- `process_name`: Name of the process generating the event

### RTT Metrics

**`podtrace_rtt_seconds`** (Histogram)
- Description: Distribution of TCP RTT (Round-Trip Time) measurements
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `namespace`, `process_name`, `target_pod`, `target_service`, `type`
- Source: TCP send/receive operations

**`podtrace_rtt_latest_seconds`** (Gauge)
- Description: Most recent TCP RTT measurement
- Labels: `namespace`, `process_name`, `target_pod`, `target_service`, `type`
- Updated: On each TCP send/receive event

### Latency Metrics

**`podtrace_latency_seconds`** (Histogram)
- Description: Distribution of TCP connection and operation latencies
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `namespace`, `process_name`, `target_pod`, `target_service`, `type`
- Source: TCP connections

**`podtrace_latency_latest_seconds`** (Gauge)
- Description: Most recent TCP latency measurement
- Labels: `namespace`, `process_name`, `target_pod`, `target_service`, `type`
- Updated: On each connection event

### DNS Metrics

**`podtrace_dns_latency_seconds_gauge`** (Gauge)
- Description: Latest DNS query latency per process
- Labels: `namespace`, `process_name`, `type`
- Updated: On each DNS lookup

**`podtrace_dns_latency_seconds_histogram`** (Histogram)
- Description: Distribution of DNS query latencies
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `namespace`, `process_name`, `type`
- Source: DNS lookups

### File System Metrics

**`podtrace_fs_latency_seconds_gauge`** (Gauge)
- Description: Latest file system operation latency
- Labels: `namespace`, `process_name`, `type`
- Updated: On each file system operation

**`podtrace_fs_latency_seconds_histogram`** (Histogram)
- Description: Distribution of file system operation latencies
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `namespace`, `process_name`, `type`
- Source: File read/write/fsync operations

### CPU Metrics

**`podtrace_cpu_block_seconds_gauge`** (Gauge)
- Description: Latest CPU block time (thread blocking duration)
- Labels: `namespace`, `process_name`, `type`
- Updated: On each scheduling event

**`podtrace_cpu_block_seconds_histogram`** (Histogram)
- Description: Distribution of CPU block times
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `namespace`, `process_name`, `type`
- Source: CPU scheduling events (sched_switch)

### Connection Pool Metrics

**`podtrace_pool_acquires_total`** (Counter)
- Description: Total number of connection pool acquire attempts
- Labels: `namespace`, `pool_id`, `process_name`

**`podtrace_pool_releases_total`** (Counter)
- Description: Total number of connections returned to the pool
- Labels: `namespace`, `pool_id`, `process_name`

**`podtrace_pool_exhausted_total`** (Counter)
- Description: Total pool exhaustion events (acquire failed — pool full)
- Labels: `namespace`, `pool_id`, `process_name`

**`podtrace_pool_wait_seconds`** (Histogram)
- Description: Time spent waiting to acquire a connection from the pool
- Buckets: Exponential (0.0001s to ~52s)
- Labels: `namespace`, `pool_id`, `process_name`

### Language-Runtime Adapter Metrics

**`podtrace_redis_latency_seconds`** (Histogram)
- Description: Distribution of Redis command latencies (hiredis uprobes)
- Labels: `command`, `namespace`, `process_name`
- Source: `redisCommand` / `redisCommandArgv` uprobes

**`podtrace_memcached_latency_seconds`** (Histogram)
- Description: Distribution of Memcached operation latencies (libmemcached uprobes)
- Labels: `namespace`, `operation`, `process_name`
- Source: `memcached_get`, `memcached_set`, `memcached_delete` uprobes

**`podtrace_fastcgi_latency_seconds`** (Histogram)
- Description: Distribution of FastCGI request latencies (unix-socket kprobes, BTF-only)
- Labels: `method`, `namespace`, `process_name`
- Source: FastCGI request/response kprobes

**`podtrace_grpc_latency_seconds`** (Histogram)
- Description: Distribution of gRPC method call latencies
- Labels: `method`, `namespace`, `process_name`
- Source: `tcp_sendmsg` kprobe filtered by `PODTRACE_GRPC_PORT` (default 50051)

**`podtrace_kafka_latency_seconds`** (Histogram)
- Description: Distribution of Kafka produce and consume latencies (librdkafka uprobes)
- Labels: `namespace`, `operation`, `process_name`, `topic`
- Source: `rd_kafka_produce`, `rd_kafka_consumer_poll` uprobes

**`podtrace_kafka_bytes_total`** (Counter)
- Description: Total bytes in Kafka produce/consume operations
- Labels: `namespace`, `operation`, `process_name`, `topic`
- Use with `rate()` to get bytes/second throughput

## Prometheus Configuration

Add a scrape job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'podtrace'
    static_configs:
      - targets: ['<PODTRACE_HOST>:3000']
        labels:
          instance: 'podtrace'
```

Replace `<PODTRACE_HOST>` with:
- `localhost` if running locally
- Pod IP if running in Kubernetes
- Host IP if running on a node

### Kubernetes Service Discovery

For dynamic discovery in Kubernetes:

```yaml
scrape_configs:
  - job_name: 'podtrace'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        regex: podtrace
        action: keep
      - source_labels: [__meta_kubernetes_pod_ip]
        target_label: __address__
        replacement: '${1}:3000'
```

## Grafana Dashboard

A pre-built Grafana dashboard is included at:
```
internal/metricsexporter/dashboard/PodTrace-Dashboard.json
```

### Importing the Dashboard

1. Open Grafana
2. Go to **Dashboards** → **New** → **Import**
3. Upload `PodTrace-Dashboard.json` or paste its contents
4. Select your Prometheus datasource
5. Click **Import**

### Dashboard Panels

The dashboard includes:

- **RTT Distribution**: Histogram of TCP RTTs
- **Latest RTT**: Current RTT values
- **Connection Latency**: TCP connection latencies
- **DNS Latency**: DNS lookup latencies
- **File System Latency**: FS operation latencies
- **I/O Bandwidth**: Network and filesystem throughput metrics
- **CPU Block Time**: Thread blocking durations
- **Per-Process Metrics**: Breakdown by process name

## Query Examples

### Average RTT by Process

```promql
rate(podtrace_rtt_seconds_sum[5m]) / rate(podtrace_rtt_seconds_count[5m])
```

### P95 DNS Latency

```promql
histogram_quantile(0.95, 
  rate(podtrace_dns_latency_seconds_histogram_bucket[5m])
)
```

### Top Processes by Event Count

```promql
topk(10, 
  sum(rate(podtrace_rtt_seconds_count[5m])) by (process_name)
)
```

### File System Operation Rate

```promql
sum(rate(podtrace_fs_latency_seconds_count[5m])) by (type, process_name)
```

### CPU Block Time P99

```promql
histogram_quantile(0.99,
  rate(podtrace_cpu_block_seconds_histogram_bucket[5m])
)
```

### I/O Bandwidth Metrics

**`podtrace_network_bytes_total`** (Counter)
- Description: Total bytes transferred over network (TCP/UDP send/receive)
- Labels: `direction`, `namespace`, `process_name`, `target_pod`, `target_service`, `type`
- Use with `rate()` to get bytes/second

**`podtrace_filesystem_bytes_total`** (Counter)
- Description: Total bytes transferred via filesystem operations (read/write)
- Labels: `namespace`, `operation`, `process_name`, `type`
- Use with `rate()` to get bytes/second

### I/O Bandwidth Query Examples

#### Network Throughput (bytes/second)

```promql
# Total network throughput
sum(rate(podtrace_network_bytes_total[5m])) by (direction)

# Network throughput by process
sum(rate(podtrace_network_bytes_total[5m])) by (process_name, direction)

# TCP send throughput
sum(rate(podtrace_network_bytes_total{direction="send"}[5m])) by (process_name)
```

#### Filesystem Throughput (bytes/second)

```promql
# Total filesystem throughput
sum(rate(podtrace_filesystem_bytes_total[5m])) by (operation)

# Filesystem throughput by process
sum(rate(podtrace_filesystem_bytes_total[5m])) by (process_name, operation)

# Write throughput
sum(rate(podtrace_filesystem_bytes_total{operation="write"}[5m])) by (process_name)
```

## Security

The metrics endpoint includes:

- **Security Headers**:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`

- **Rate Limiting**: 10 requests per second with burst of 20

- **Localhost Binding**: Only accessible from localhost by default

## Performance

- **Low Overhead**: Metrics collection adds minimal overhead
- **Efficient**: Uses Prometheus client library with efficient data structures
- **Non-Blocking**: Metrics collection doesn't block event processing

## Troubleshooting

**Metrics not appearing:**
- Verify metrics server is running: `curl http://localhost:3000/metrics`
- Check Prometheus can reach the endpoint
- Verify network connectivity

**High cardinality:**
- Process names can create high cardinality
- Consider filtering or aggregating by process name
- Use recording rules for expensive queries

**Rate limiting:**
- If you see "Rate limit exceeded", reduce scrape frequency
- Default: 10 req/s with burst of 20

## Resource Limit Metrics

**`podtrace_resource_limit_bytes`** (Gauge)
- Description: Resource limit in bytes (or CPU quota in microseconds)
- Labels: `namespace`, `resource_type`
- Updated: When resource limits are read from cgroup files

**`podtrace_resource_usage_bytes`** (Gauge)
- Description: Current resource usage in bytes (or CPU time in microseconds)
- Labels: `namespace`, `resource_type`
- Updated: Periodically (every 5 seconds by default)

**`podtrace_resource_utilization_percent`** (Gauge)
- Description: Resource utilization percentage (usage/limit * 100)
- Labels: `namespace`, `resource_type`
- Range: 0-100 (values >100 indicate limit exceeded)
- Updated: Periodically (every 5 seconds by default)

**`podtrace_resource_alert_level`** (Gauge)
- Description: Resource alert level: 0=none, 1=warning (80%), 2=critical (90%), 3=emergency (95%)
- Labels: `namespace`, `resource_type`
- Updated: When utilization crosses thresholds

### Resource Limit Query Examples

#### Current CPU Utilization
```promql
podtrace_resource_utilization_percent{resource_type="cpu"}
```

#### Memory Usage vs Limit
```promql
# Current memory usage
podtrace_resource_usage_bytes{resource_type="memory"}

# Memory limit
podtrace_resource_limit_bytes{resource_type="memory"}

# Memory utilization percentage
podtrace_resource_utilization_percent{resource_type="memory"}
```

#### Alert on High Resource Usage
```promql
# Warning level (80%+)
podtrace_resource_alert_level >= 1

# Critical level (90%+)
podtrace_resource_alert_level >= 2

# Emergency level (95%+)
podtrace_resource_alert_level >= 3
```

#### Resource Usage by Namespace
```promql
# CPU utilization by namespace
sum(podtrace_resource_utilization_percent{resource_type="cpu"}) by (namespace)

# Memory usage by namespace
sum(podtrace_resource_usage_bytes{resource_type="memory"}) by (namespace)
```

#### Resource Limit Exceeded
```promql
# Resources exceeding their limits
podtrace_resource_utilization_percent > 100
```