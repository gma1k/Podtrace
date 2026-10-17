# PodTrace — continuous tracing CR

`PodTrace` declares a continuous tracing intent against a set of pods. The
operator creates an exporter bundle in `podtrace-system`, the agent
DaemonSet matches the selector, and per-node status entries roll up into
the CR's `.status.nodeStatus` array.

The agent loads the real eBPF backend by default and emits one
OpenTelemetry span per kernel event to the configured exporter. A
no-op backend remains available for clusters where loading eBPF
programs is undesirable — opt in by passing `--backend=noop` to the
agent (DaemonSet-template override; production deployments leave this
unset).

## Minimal example

```yaml
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata:
  name: prod-otlp
  namespace: my-app
spec:
  type: otlp
  otlp:
    endpoint: otel-collector.observability:4318
    protocol: http
    insecure: true
---
apiVersion: podtrace.io/v1alpha1
kind: PodTrace
metadata:
  name: watch-api
  namespace: my-app
spec:
  selector:
    matchLabels:
      app: api
  filters: [dns, net]
  exporterRef:
    name: prod-otlp
```

## Spec reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `selector` | LabelSelector | one of selector/podRefs/appSelector | Pods labeled to trace. Empty selector is rejected. |
| `podRefs` | `[{namespace, name}]` | one of selector/podRefs/appSelector | Explicit pod list. Cross-namespace allowed. |
| `appSelector` | `{matchSelectors: []LabelSelector}` | one of selector/podRefs/appSelector | Application of several workloads: a pod matching **any** selector is traced (union, de-duplicated). Exactly-one-of is enforced by CEL + webhook. |
| `namespaceSelector` | LabelSelector | optional | Widens `selector` across namespaces. `matchLabels` and `matchExpressions` are both evaluated against namespace labels; an empty selector (`{}`) matches every namespace. A matched namespace is only traced if it consents via the `podtrace.io/allow-tracing-from` annotation. |
| `filters` | `[dns,net,fs,cpu,proc,crypto]` | optional | Empty = all categories. Agents enforce the set per-event in userspace and only the listed categories reach the configured exporter. |
| `exporterRef.name` | string | required | Names an `ExporterConfig` in the same namespace. |
| `paused` | bool | optional | Stop emitting events without deleting the CR. |
| `samplePercent` | int 0-100 | optional | Workload-owner sampling intent. The operator combines this with `ExporterConfig.spec.samplePercent` (platform-owner cap) and writes the **minimum** of the two to the bundle — that minimum is what every exporter applies. Unset on either side is treated as 100%. The resolved value is echoed at `status.policy.effectiveSampleRate`. Sampling is per trace and consistent across nodes: the decision is a hash of the trace id keyed by this PodTrace's UID, so a caller choosing its own trace ids cannot force its requests into, or keep them out of, the sample. |
| `thresholds.errorRatePercent` | int 0-100 | optional | When set, the agent stamps `podtrace.threshold.error_rate.observed=true` on every span whose source event carries a non-zero error code and bumps `podtrace_agent_threshold_tripped_total{threshold="error_rate"}`. |
| `thresholds.rttSpikeMs` | int ≥0 | optional | When set, the agent tags spans whose source event latency exceeds this threshold (Connect/TCPSend/TCPRecv/UDPSend/UDPRecv) and bumps `podtrace_agent_threshold_tripped_total{threshold="rtt_spike"}`. |
| `thresholds.filesystemLatencyMs` | int ≥0 | optional | When set, the agent tags FS-event spans (Open/Read/Write/Close/Fsync/Unlink/Rename) whose latency exceeds the threshold and bumps `podtrace_agent_threshold_tripped_total{threshold="fs_slow"}`. |

## Status reference

| Field | Notes |
|---|---|
| `matchedPods` | Number of matched pods: the sum of every node's `matchedPods`. |
| `nodeStatus[]` | One entry per node hosting a matched pod. Each carries `node`, `ready`, `matchedPods`, `activeCgroups` (the pod and container cgroups traced there, so usually more than the pods), `totalEvents`, `droppedEvents` (this PodTrace's events lost on that node), `kernelDroppedEvents` (events the node's agent lost in the kernel before they could be attributed to any PodTrace; the same node-wide figure on every PodTrace that node reports for), `lastHeartbeat`, `message`, and `policyHash` (the hash of the bundle the agent last observed — see "Verifying policy propagation" below). |
| `conditions` | Standard Kubernetes condition objects. `Ready=True` once at least one node reports healthy. `Degraded=True` on bundle sync errors. `Paused` mirrors `spec.paused`. `PolicyApplied=True` once the operator has resolved `spec.filters`/`spec.samplePercent`/`spec.thresholds` and written them to the bundle. |
| `observedGeneration` | Most recent generation reconciled. |
| `policy.effectiveSampleRate` | The operator-resolved sample rate (0–100), already reduced to the minimum of `spec.samplePercent` and `ExporterConfig.spec.samplePercent`. This is what every agent and exporter actually applies — do not infer effective sampling from `spec` alone. |
| `policy.filters` | Sorted, deduplicated copy of `spec.filters` written to the bundle. |
| `policy.thresholds` | Echo of `spec.thresholds` written to the bundle. |
| `policy.generation` | `metadata.generation` of the CR at bundle-write time. Pair with `nodeStatus[].policyHash` to verify propagation reached every node. |
| `policy.hash` | sha256 over the bundle's policy fields. Two CRs with identical filters/sample/thresholds produce the same hash regardless of exporter. |

### Verifying policy propagation

`status.policy.hash` is what the operator wrote; each
`status.nodeStatus[].policyHash` is what that node's agent observed. When
they agree, the bundle has propagated:

```bash
kubectl get podtrace watch-api -n my-app -o jsonpath='
status.policy.hash = {.status.policy.hash}{"\n"}
{range .status.nodeStatus[*]}{.node}: {.policyHash}{"\n"}{end}'
```

A node showing an empty or stale hash means the agent has not yet
re-read the bundle ConfigMap — usually a transient state during edits.

## Multi-CR merging on shared targets

Two `PodTrace` CRs targeting overlapping pods produce **one** tracer
process per node. The agent merges:

- **CgroupIDs** — union, so the kernel-side filter admits any matched pod.
- **Filters** — union, so the agent emits any event type any CR cares about.
- **Exporters** — per-CR dispatch table, so each CR's events land on its
  own exporter (router filters by event type per CR).

Result: overlapping CRs share kernel resources, do not double-trace, and
each independently reports `totalEvents` on its own `nodeStatus`.

## Creating a PodTrace with the CLI (`podtrace watch`)

`podtrace watch` is a convenience front-end that authors a `PodTrace` for you
and exits — no YAML to hand-write. It is the ergonomic way to express
"trace this application everywhere, continuously". The resulting CR is an
ordinary `PodTrace`: the operator and agents take over exactly as if you had
applied the manifest yourself.

```bash
# --app NAME is shorthand for selector app.kubernetes.io/name=NAME
podtrace watch --app api --all-namespaces --exporter prod-otlp

# Arbitrary selector, scoped to one namespace
podtrace watch --label app=api,tier=web -n my-app --exporter prod-otlp

# Only namespaces carrying a label
podtrace watch --app api --namespace-selector team=payments --exporter prod-otlp

# Render the manifest without applying it
podtrace watch --app api --all-namespaces --print-only
```

`--app`/`--label`/`--all-namespaces` also exist on the **root** command, but
there they drive *ephemeral* tracing (resolve matching pods and stream events
to your terminal), exactly like `--pod-selector`:

```bash
# ephemeral: trace the application now, stream to this terminal (no CR)
podtrace --app api -n my-app --diagnose 30s --filter dns,net
podtrace --label tier=web -n my-app
```

So the same targeting vocabulary works two ways: `podtrace <targeting>` traces
now (terminal); `podtrace watch <targeting>` records continuously (exporter).
The managed-only flags (`--exporter`, `--name`, `--namespace-selector`,
`--sample`, `--print-only`) exist only on `watch`.

| Flag | Maps to | Notes |
|---|---|---|
| `--app NAME` | `spec.selector.matchLabels[app.kubernetes.io/name]=NAME` | Mutually exclusive with `--label`. Also the default PodTrace name. |
| `--label k=v,…` | `spec.selector` | Any label selector. Requires `--name`. |
| `--all-namespaces` | `spec.namespaceSelector: {}` | Matches every namespace. Mutually exclusive with `--namespace-selector`. |
| `--namespace-selector k=v` | `spec.namespaceSelector` | Only namespaces carrying these labels. |
| `--exporter NAME` | `spec.exporterRef.name` | Defaults to `default`; must be an `ExporterConfig` in `-n`. Checked before create. |
| `--name NAME` | `metadata.name` | Defaults to the `--app` value. |
| `--filter dns,net,…` | `spec.filters` | Empty = all categories. |
| `--sample N` | `spec.samplePercent` | 0-100; unset by default. |
| `--print-only` | — | Print YAML, skip the exporter check and the apply. |

> **Application targeting.** A `PodTrace` can target several workloads at once
> via `spec.appSelector` (a union of label selectors — see above). For a
> user-facing "application" object that owns and keeps its `PodTrace` in sync,
> use the [`ApplicationTrace`](crd-applicationtrace.md) CR, or
> `podtrace watch --application`. The on-node merge router means overlapping
> traces never conflict.

## Common operations

```bash
# Apply
kubectl apply -f my-podtrace.yaml

# Watch reconcile
kubectl get podtraces.podtrace.io -A -w

# Inspect per-node rollup
kubectl get podtrace watch-api -n my-app -o jsonpath='{range .status.nodeStatus[*]}{.node}: ready={.ready} events={.totalEvents}{"\n"}{end}'

# Pause without deleting
kubectl patch podtrace watch-api -n my-app --type=merge -p '{"spec":{"paused":true}}'

# Resume
kubectl patch podtrace watch-api -n my-app --type=merge -p '{"spec":{"paused":false}}'

# Delete (finalizer cleans up the bundle in podtrace-system)
kubectl delete podtrace watch-api -n my-app
```

## RBAC

Continuous CRs do not require any extra user-namespace RBAC beyond what
the operator's ClusterRole already grants. The exporter `Secret` (when
the bundle has credentials) lives in the user namespace and the operator
reads it during reconcile; agents only read the operator-materialized
bundle in `podtrace-system`.

## Troubleshooting

**`status.nodeStatus` is empty:** The agent DaemonSet hasn't reported
yet, OR no node has a matched pod. Check:

```bash
kubectl get pods -n my-app -l <your-selector>
kubectl -n podtrace-system get pods -l podtrace.io/component=agent
```

**`Degraded=True ExporterNotFound`:** The named ExporterConfig isn't in
the same namespace. Cross-namespace exporter references are not allowed.

**`Degraded=True BundleSync`:** The operator failed to materialize the
exporter bundle in `podtrace-system`. Likely a missing user-namespace
Secret referenced by the ExporterConfig. Check the operator log.

**Events stay at zero:** The agent matched no pods, the matched pods
generate no kernel events of the configured `filters`, or
`podtrace_agent_backend_degraded` is non-zero on the agent's node
(check `kubectl -n podtrace-system logs daemonset/podtrace-agent` for
the failure reason). The continuous CR uses the real eBPF backend by
default — confirm with
`kubectl -n podtrace-system get ds podtrace-agent -o jsonpath='{.spec.template.spec.containers[0].args}'`
that `--backend=noop` is not present.

## Related

- [crd-podtracesession.md](crd-podtracesession.md) — bounded diagnose CR for one-shot traces
- [crd-exporterconfig.md](crd-exporterconfig.md) — exporter setup
- [operator.md](operator.md) — operator architecture
