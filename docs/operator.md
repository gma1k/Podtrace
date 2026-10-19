# Podtrace Operator

The podtrace operator runs the same eBPF-based tracing podtrace's CLI binary
already provides, but driven through Kubernetes Custom Resources. Instead of
SSHing to a node or `kubectl exec`-ing a privileged pod, users `kubectl apply`
a CR; the operator and an agent DaemonSet handle the rest.

## Architecture at a glance

```
                       +---------------------------+
                       | podtrace operator         |
                       | (Deployment in            |
                       |  podtrace-system)         |
                       +---------------------------+
                                | reconciles
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
  +------------+         +-------------+         +--------------+
  | TracerCfg  |         | PodTrace    |         | PodTraceSess |
  | (cluster)  |         | (continuous |         | (bounded     |
  |            |         |  realtime)  |         |  diagnose)   |
  +-----+------+         +------+------+         +------+-------+
        |                       |                       |
        v                       v                       v
  podtrace-agent          exporter bundle         per-node Job
  DaemonSet               (CM + Secret in         under
  (one pod / node)        podtrace-system)        podtrace-system
```

Three reconcilers, each owning one CRD:

- **TracerConfigReconciler** — manages cluster-wide infrastructure: the agent
  ServiceAccount + RBAC (cluster-wide ClusterRole + namespaced Role for bundle
  reads in `podtrace-system`), the agent DaemonSet, and the session SA.
- **PodTraceReconciler** — continuous tracing CR. Materializes an exporter
  bundle in `podtrace-system` for each PodTrace, watches per-node status from
  agents, and aggregates `status.nodeStatus` rollups.
- **PodTraceSessionReconciler** — bounded diagnose CR. Spawns one privileged
  Job per node hosting a matched pod, mounts the exporter bundle into the
  Job, and reads kubelet termination messages for `status.summary`.

## What runs where

| Component | Where | Privilege | Notes |
|---|---|---|---|
| Operator Deployment | `podtrace-system` | Unprivileged, runAsNonRoot=65532, readOnly rootfs, `drop: ["ALL"]` | Single replica with leader election. |
| Agent DaemonSet | `podtrace-system`, every node | Privileged: CAP_BPF + CAP_SYS_ADMIN + CAP_PERFMON, hostPID, hostPath mounts | One pod per node hosts long-lived eBPF probes + status writers. |
| Session Job | `podtrace-system`, pinned to one node | Same caps as agent | Created on demand by the session reconciler. TTL'd 300s after Completed. |
| Validating webhook | Inside operator pod (port 9443) | Inherits operator's unprivileged context | TLS via cert-manager (default) or external. |

## Custom Resources

| CRD | Scope | Purpose | Doc |
|---|---|---|---|
| [`TracerConfig`](crd-tracerconfig.md) | Cluster | Image, agent runtime defaults, session caps. One agent fleet each; usually a single `default`, optionally one per node pool. | crd-tracerconfig.md |
| [`ExporterConfig`](crd-exporterconfig.md) | Namespace | Reusable exporter destination (OTLP, Jaeger, Zipkin, Splunk, DataDog). | crd-exporterconfig.md |
| [`PodTrace`](crd-podtrace.md) | Namespace | Continuous tracing of pods matching a selector. | crd-podtrace.md |
| [`PodTraceSession`](crd-podtracesession.md) | Namespace | Bounded diagnose-mode trace producing a report artifact. | crd-podtracesession.md |

## Install via Helm

For a public release:

```bash
helm install podtrace oci://ghcr.io/gma1k/charts/podtrace --version 0.1.0 \
  --namespace podtrace-system --create-namespace \
  --set operator.enabled=true
```

For a custom build of this checkout:

```bash
helm install podtrace deploy/charts/podtrace \
  --namespace podtrace-system \
  --create-namespace \
  --set operator.enabled=true \
  --set image.tag=<your-built-tag>
```

This single install renders the CRDs, the namespace (with PSA `enforce:
privileged`), the operator Deployment, agent ClusterRole + namespaced bundle
Role, and a default `TracerConfig` CR — which the TracerConfigReconciler
picks up and uses to roll out the agent DaemonSet automatically.

See [installation.md](installation.md) for prerequisites, kind/cluster
specifics, and webhook TLS setup.

## Key invariants

- **`podtrace-system` is the only PSA-privileged namespace.** All raw eBPF
  pods land here. User namespaces stay PSA-restricted.
- **Cross-namespace bundles avoid Kubernetes' namespaced-owner forbidding.**
  ConfigMaps/Secrets/Jobs the operator creates in `podtrace-system` on
  behalf of a user-namespace CR cannot use ownerReferences (Kubernetes
  forbids cross-namespace owner refs for namespaced resources). Cleanup
  goes through `podtrace.io/cleanup` finalizers + label selectors instead.
- **Per-session RBAC is scoped to one named ConfigMap or Secret.** The
  session ServiceAccount can patch only the specific `spec.reportRef`
  object — not arbitrary objects in the user namespace.
- **Server-Side Apply for status writes.** Multiple agents patch the same
  PodTrace's `status.nodeStatus` array concurrently; SSA with per-node
  `FieldOwner` keeps them from clobbering each other.

## Observability

Operator and agent both expose Prometheus metrics:

- **Operator** — `/metrics` on port 8080 in the operator pod. Standard
  controller-runtime metrics (workqueue depth, reconcile latency, error rate).
- **Agent** — `/metrics` on port 9090 in each agent pod. Per-CR event
  counters, dropped-event counters, active-cgroup gauge, reconcile counter,
  and `podtrace_agent_backend_degraded{reason=...}` — set to `1` if the
  agent failed to load the real eBPF backend and is running in noop
  fallback mode. Healthy agents emit no `backend_degraded` series; alert
  on `max by(node)(podtrace_agent_backend_degraded) > 0` and the `reason`
  label routes to remediation (`permission_denied`, `btf_unavailable`,
  `kernel_too_old`, `tracefs_unmounted`, `collection_failed`,
  `ringbuf_failed`, `map_lookup_failed`, `invalid_event`, `unknown`).

  A degraded agent also fails its **readiness probe**, so the pod reports
  `0/1` and a DaemonSet rollout stalls rather than completing. That is
  deliberate: the agent still starts, still serves its endpoints and still
  reconciles, so if readiness ignored the backend the pod would report `1/1`
  and every rollout gate, `kubectl rollout status`, `helm --wait`, CI,
  would pass while nothing was being captured. `/readyz` returns `503` with
  the reason in the body; `/healthz` keeps passing, so the pod is not
  restarted and its logs and metrics stay available for diagnosis.

  The agent serves both endpoints only once its eBPF backend has loaded,
  which on a busy node can take minutes. A **startup probe** allows five
  minutes for that, and the liveness probe only starts counting after it
  passes. `/healthz` fails when the agent's status loop has not ticked for
  three `statusReportInterval`s (at least 90s); each tick gives up on the API
  server after one interval, so a slow API server delays status reports
  rather than getting healthy agents restarted.

  With kernel aggregation on, the workload counters only move when the agent
  drains its BPF map, so the agent also publishes its drain clock:
  `podtrace_agent_kernel_metrics_drained_timestamp_seconds` (when the last
  drain completed), `podtrace_agent_kernel_metrics_drain_interval_seconds`,
  and `podtrace_agent_kernel_metrics_seconds_since_drain` (measured by the
  agent when scraped, `-1` before the first drain). A reader that takes rates
  between two scrapes, such as `podtrace status`, times its reads
  to the drains with these instead of its own clock. They are collector
  internals, with no compatibility promise.

  The continuous profiler's on-CPU sampler reports
  `podtrace_agent_oncpu_sampler_cpus` (the CPUs it runs on; `0` means the node
  fell back to `sched_switch` stacks), `podtrace_agent_oncpu_samples_total`,
  `podtrace_agent_oncpu_samples_lost_total{reason}` (`stack_unavailable`,
  `count_map_full`, `stack_evicted`) and
  `podtrace_agent_oncpu_drain_failures_total`. See
  [profiling.md](profiling.md#where-the-samples-come-from).

  Diagnostics granularity (per-program + per-CR failure surfaces):

  - `podtrace_agent_program_attach_failures_total{program,reason}` —
    counter, bumped once per failed eBPF program attach at agent boot.
    `program` is the BPF symbol (e.g. `tracepoint_sched_switch`),
    `reason` reuses the `backend_degraded` classifier so the same
    alert rule covers both signals. Healthy agents emit no series.
  - `podtrace_agent_exporter_init_failures_total{cr_namespace,cr_name,reason}` —
    counter, **edge-triggered**: one increment per ok→fail transition.
    `reason ∈ {unknown, nil_payload, unsupported_type, endpoint_missing,
    tls_invalid, auth_missing}`. A sustained bad config does not inflate
    this counter — `rate()` detects new failures, not their duration.

  The per-CR event counters (`events_exported_total`, `events_dropped_total`)
  and the `enrichment_*` series are folded in from the agent's internal
  statistics every 15 seconds and on every reconcile, so they keep moving on
  a node whose CRs and pods have not changed for hours. When a CR stops
  targeting a node, every per-CR series for it is deleted, including
  `spans_batched_total`, `spans_delivered_total` and
  `export_delivery_dropped_total`; the final flush of its exporter, which
  finishes in the background, does not bring them back.

  Policy-wiring observability (one series per CR):

  - `podtrace_agent_effective_sample_rate{cr_namespace,cr_name}` — the
    sample rate (0.0–1.0) the agent is actually applying, after the
    operator-side min(CR, ExporterConfig) resolution.
  - `podtrace_agent_policy_generation{cr_namespace,cr_name}` —
    `metadata.generation` of the source CR at bundle-read time. Compare
    against the CR's live generation to detect bundle-propagation lag.
  - `podtrace_agent_threshold_tripped_total{cr_namespace,cr_name,threshold}` —
    counter, bumped once per event that exceeds a configured threshold
    (`threshold ∈ {fs_slow, rtt_spike, error_rate}`). Stateless per-event
    evaluation: a counter delta over a window is the trip frequency
    directly.
  - `podtrace_agent_error_rate_breached_total{cr_namespace,cr_name}` —
    counter, edge-triggered: one increment per ok→breached transition of
    the rolling-window error rate exceeding `spec.thresholds.errorRatePercent`.
    The rate is measured over decoded requests (HTTP, gRPC, FastCGI, Redis,
    Memcached, Kafka, database), not over every traced event.

  Machine-readable failure surfaces are also stamped onto the CR itself:
  `PodTrace.status.nodeStatus[*].reason` carries a closed enum
  (`AgentUnready`, `BackendUnavailable`, `BundleLoadFailed`,
  `ExporterBuildFailed`, `ExporterDeliveryFailed`, `ProgramAttachFailed`, `PolicyParseError`,
  `PodMatchFailed`, `CgroupResolutionFailed`, `Unknown`) alongside the
  free-text `message`. The operator lifts that enum into the rolled-up
  `Degraded` condition's `reason` field, so `kubectl describe podtrace`
  surfaces the same precise class without needing to query metrics.

Enable scrape configs via Helm:

```bash
helm upgrade podtrace ... \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.podMonitor.enabled=true
```

Both templates are gated on `monitoring.coreos.com/v1` being installed —
flipping the toggle on a cluster without prometheus-operator is a silent
no-op rather than a hard install failure.

### Restricting the metrics port

The agent's port 9090 serves `/metrics`, `/issues` and `/profile` without
authentication. `/issues` lists every workload's active issues on the node and
`/profile` returns symbolised CPU stacks for every workload on the node, in
every namespace, so whoever can reach the port can read another tenant's
profile. The chart leaves `networkPolicy.enabled` off by default, which lets
any pod reach it.

`networkPolicy.enabled: true` adds NetworkPolicies for the agent and the
operator. The operator can always reach the agents' port 9090, because it reads
`/issues` to link issues across workloads. Who else can reach it is
`networkPolicy.metricsFrom`; **left empty, it allows every source**, so the
policy restricts nothing on 9090. Name your scrapers there:

```yaml
networkPolicy:
  enabled: true
  metricsFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
      podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
  allowAPIServerProxy: true
```

`kubectl podtrace status` reads the agents through the API server's pod proxy,
so once `metricsFrom` is set the API server has to be allowed too: on Cilium
with `allowAPIServerProxy: true`, on other CNIs by adding the control-plane
node addresses to `metricsFrom` as `ipBlock`s. Anyone with `get` on
`pods/proxy` in the podtrace namespace can still read every endpoint through
the API server.

Both [PodTrace](crd-podtrace.md) (continuous) and
[PodTraceSession](crd-podtracesession.md) (bounded) drive the real eBPF
backend by default, with events surfacing as OpenTelemetry spans on the
configured exporter. Session reports can also be uploaded directly to
S3-, GCS-, or Azure-Blob–compatible object stores — see
[Object-store report sinks](object-store-reports.md).

## Going further

- [Installation](installation.md) — prerequisites, Helm install, kind setup
- [PodTrace CR](crd-podtrace.md) — continuous tracing reference
- [PodTraceSession CR](crd-podtracesession.md) — bounded diagnose reference
- [Migration](migration.md) — moving from CLI to CR-driven workflows
- [Architecture](architecture.md) — internals of the tracer itself
