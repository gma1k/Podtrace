# Podtrace

eBPF-driven APM and diagnostic tool for Kubernetes applications 🐝

Podtrace observes every pod with eBPF, with no code changes, no sidecars and no instrumentation. One agent per node works in two ways:

- **Always on.** Every pod on every node reports its golden signals
  continuously: request rate, errors and latency per workload, plus network, DNS, TLS, filesystem, CPU and connection-pool health. Podtrace watches those signals, raises an issue when something is wrong, names its likely root cause, and can start a deep-dive on the affected pod by itself.
- **On demand.** Point it at a pod, or at a whole application across all its 
  pods, and it records everything they do for as long as you ask: network
  flows, TCP and UDP performance, file activity, system calls, and
  application events such as HTTP/1, HTTP/2, HTTP/3, gRPC, DNS and database queries, then explains what it found in a report.

The always-on side tells you *which* workload is unhealthy, cheaply and at low
cardinality. The on-demand side tells you *why*, in depth.

## TL;DR

```bash
helm install podtrace oci://ghcr.io/gma1k/charts/podtrace \
  --version <chart-version> \
  --namespace podtrace-system --create-namespace
```

That is all continuous APM needs. Once the agents are ready, every node runs one and every pod has golden signals:

```bash
kubectl krew install podtrace
kubectl podtrace status
```

## What a default install runs

- The **podtrace operator** and the CustomResourceDefinitions it reconciles.
- A `default` **TracerConfig**, from which the operator rolls out the
  **podtrace-agent** DaemonSet on every node.
- The **continuous metrics plane** on every agent: per-workload rate, errors
  and latency for HTTP, gRPC, databases, caches and messaging, plus network,
  DNS, TLS, filesystem, CPU and connection-pool metrics, served on
  `:9090/metrics`.
- **Inspections** that turn those metrics into issues: error rate, latency,
  connection failures, RTT spikes, resource and pool saturation, CPU
  contention, slow and failing DNS, slow storage and TLS handshake failures.
  Each issue raises `podtrace_issue_active` and a Kubernetes Event on the
  affected pod, and the operator links it to its likely cause on the same
  workload or a workload it calls.
- A Prometheus Operator **PodMonitor**, rendered only where the
  `monitoring.coreos.com/v1` API exists. The agent pods also carry
  `prometheus.io/scrape` annotations for annotation-based scrapers.

Nothing is exported off the cluster until you add an `ExporterConfig`.

## Continuous APM

- **Golden signals per workload**, labelled by namespace and workload so a
  series survives a rollout. Scraped by Prometheus or pushed over OTLP
  through an `ExporterConfig`.
- **OpenTelemetry semantic conventions** such as
  `http.server.request.duration`, emitted beside the native `podtrace_*`
  names when `agent.metrics.semanticConventions=true`, so stock Grafana,
  Datadog and Honeycomb dashboards work as they are.
- **A service map.** Every call carries both ends of the edge, so the map is a
  PromQL query, and the
  [bundled Grafana dashboard](https://github.com/gma1k/podtrace/blob/main/internal/metricsexporter/dashboard/PodTrace-Dashboard.json)
  draws it as a node graph.
- **From finding to explaining.** A `PodTraceSchedule` with an `Issue`
  trigger starts a deep-dive session on the affected pod, and its report opens
  with the issue that started it.
- **Kernel-side aggregation.** Observations are folded into BPF maps, so the
  plane costs O(series) rather than O(events).

## On-demand tracing and diagnostics

| Resource | Use it to |
| --- | --- |
| `PodTrace` | Trace pods matching a selector continuously and stream events and spans to an exporter |
| `ApplicationTrace` | Trace an application made of several workloads as one, across namespaces |
| `PodTraceSession` | Run a bounded diagnose on the matching pods and write a report to a ConfigMap, Secret or object store |
| `PodTraceSchedule` | Start sessions on a cron schedule, or when an alert or issue fires for a pod |
| `ExporterConfig` | Send spans and metrics to OTLP, Jaeger, Zipkin, Splunk HEC or Datadog |
| `TracerConfig` | Configure an agent fleet: image, node selection, metrics, redaction, alerting |

Cross-namespace targets must consent with the
`podtrace.io/allow-tracing-from` annotation on the target namespace.

## Prerequisites

- **Kubernetes** 1.28 or newer.
- **Linux nodes with kernel 5.8+** and BTF
  (`/sys/kernel/btf/vmlinux`), which most current distributions ship.
- **Pod Security:** the agents and session Jobs need the `privileged` level.
  The chart labels `podtrace-system` accordingly; if you create the namespace
  yourself (`namespace.create=false`), label it the same way. Your own
  workload namespaces stay as they are.
- The validating webhook (`webhook.enabled=true`, off by default) needs a
  serving certificate: cert-manager by default, or your own with
  `webhook.certSource` set to another value, `webhook.caBundle`, and a
  `podtrace-webhook-tls` Secret.

See the [compatibility matrix](https://github.com/gma1k/podtrace/blob/main/docs/compatibility.md)
for supported kernels, distributions and Kubernetes versions.

## Installing

```bash
helm install podtrace oci://ghcr.io/gma1k/charts/podtrace \
  --version <chart-version> \
  --namespace podtrace-system --create-namespace
```

### Verifying the chart and image

Every chart version and image is signed with cosign keyless OIDC and ships
SLSA Build L2 provenance:

```bash
cosign verify ghcr.io/gma1k/charts/podtrace:<chart-version> \
  --certificate-identity-regexp "^https://github.com/gma1k/podtrace" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

cosign verify ghcr.io/gma1k/podtrace:<app-version> \
  --certificate-identity-regexp "^https://github.com/gma1k/podtrace" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

See [supply chain](https://github.com/gma1k/podtrace/blob/main/docs/supply-chain.md)
for verifying provenance and enforcing it at admission time.

## Configuration

Every section of
[`values.yaml`](https://github.com/gma1k/podtrace/blob/main/deploy/charts/podtrace/values.yaml)
is documented inline with its defaults.

| Section | Purpose |
| --- | --- |
| `crds` | CustomResourceDefinition installation, adoption and retention |
| `image` | Image shared by the operator, the agents and the session Jobs |
| `namespace` | `podtrace-system` namespace management |
| `operator` | The operator Deployment |
| `agent` | Per-node agent: metrics plane, inspections, profiling, DNS, USDT, alerting, resources |
| `session` | Job template for `PodTraceSession` runs: resources, TTL, concurrency per node |
| `webhook` | Validating webhook for the CRDs |
| `rbac` | RBAC creation |
| `metrics` | Prometheus `PodMonitor` (on) and `ServiceMonitor` (off) |
| `networkPolicy` | Restrict who may reach the agent and operator metrics ports |
| `tracerConfig` | The `default` TracerConfig the chart creates, including PII redaction |
| `examples` | Optional sample `TracerConfig` and `ExporterConfig` resources |

Commonly changed settings:

```yaml
agent:
  metrics:
    excludeNamespaces: [podtrace-system, kube-system]
    semanticConventions: true
  alerting:
    enabled: true
    # A Slack or PagerDuty URL is a credential; keep it in a Secret in the
    # podtrace-system namespace. Changing the Secret rolls the agents.
    webhookURLSecretRef: {name: podtrace-alert-webhook, key: url}

session:
  # Unset by default: a session runs as long as it asks, up to 24h. Set a cap
  # on shared multi-tenant clusters.
  maxDuration: ""

tracerConfig:
  redaction:
    enabled: true
```

Read every default:

```bash
helm show values oci://ghcr.io/gma1k/charts/podtrace --version <chart-version>
```

## Upgrading

```bash
helm upgrade podtrace oci://ghcr.io/gma1k/charts/podtrace \
  --version <chart-version> --namespace podtrace-system --reuse-values
```

The chart `version` and the podtrace `appVersion` move together. Read the
[CHANGELOG](https://github.com/gma1k/podtrace/blob/main/CHANGELOG.md) before
upgrading across a minor version. `--reuse-values` keeps the defaults of the
chart version you installed from; drop it to pick up new defaults.

## Uninstalling

```bash
helm uninstall podtrace --namespace podtrace-system
```

CRDs are kept by default (`crds.keep=true`) so that your podtrace resources are
not cascade-deleted. Remove them once you are sure:

```bash
kubectl delete crd -l app.kubernetes.io/name=podtrace
```

## Stability

The CRDs are at `v1alpha1`; field names may change before `v1beta1`. See
[STABILITY.md](https://github.com/gma1k/podtrace/blob/main/STABILITY.md).

## Links

- [Source code](https://github.com/gma1k/podtrace)
- [Documentation](https://github.com/gma1k/podtrace/tree/main/docs)
- [Continuous metrics](https://github.com/gma1k/podtrace/blob/main/docs/continuous-metrics.md)
- [Continuous inspections](https://github.com/gma1k/podtrace/blob/main/docs/continuous-inspections.md)
- [Operator and chart values](https://github.com/gma1k/podtrace/blob/main/docs/operator.md)
- [Issue tracker](https://github.com/gma1k/podtrace/issues)
- [Security policy](https://github.com/gma1k/podtrace/blob/main/SECURITY.md)
