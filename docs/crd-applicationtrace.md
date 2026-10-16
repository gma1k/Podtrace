# ApplicationTrace — application-level continuous tracing CR

`ApplicationTrace` is the user-facing "application" object. You describe an
application as a set of workloads (label selectors), and the operator
materializes and **owns** a single `PodTrace` that traces all of them at once —
using `PodTrace.spec.appSelector` (the union of your selectors). The proven
`PodTrace` → operator-bundle → agent datapath does the work; `ApplicationTrace`
is a thin, stable wrapper that owns its child and aggregates its status.

Deleting the `ApplicationTrace` garbage-collects the generated `PodTrace` (owner
reference cascade).

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
kind: ApplicationTrace
metadata:
  name: checkout
  namespace: my-app
spec:
  # An application of three workloads, traced as one (union, de-duplicated).
  appSelector:
    matchSelectors:
      - matchLabels: { app.kubernetes.io/name: checkout, tier: frontend }
      - matchLabels: { app.kubernetes.io/name: checkout, tier: cart }
      - matchLabels: { app.kubernetes.io/name: checkout, tier: payment }
  filters: [dns, net]
  exporterRef:
    name: prod-otlp
```

Or via the CLI (no YAML):

```bash
podtrace watch --application --app checkout --exporter prod-otlp        # one selector
podtrace watch --application --name checkout \
  --label tier=frontend --label tier=cart --label tier=payment \
  --exporter prod-otlp                                                  # several workloads
```

## Spec reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `appSelector.matchSelectors` | `[]LabelSelector` | yes (≥1) | The application's workloads. A pod matching **any** selector is traced (union). Become `PodTrace.spec.appSelector.matchSelectors`. |
| `namespaceSelector` | LabelSelector | optional | Widen across namespaces. Empty (set) = every namespace; nil = the application's own namespace. |
| `exporterRef.name` | string | yes | Names an `ExporterConfig` in the same namespace; inherited by the generated `PodTrace`. |
| `filters` | `[dns,net,fs,cpu,proc,crypto]` | optional | Empty = all categories. |
| `samplePercent` | int 0-100 | optional | Sampling intent, passed through. |
| `thresholds` | object | optional | Passed through to the generated `PodTrace`. |
| `paused` | bool | optional | Stop tracing without deleting; propagated to the child. |

### Admission checks

With the validating webhook on (`webhook.enabled=true`), an ApplicationTrace is rejected at `kubectl apply` when its name is longer than 63 characters, `appSelector.matchSelectors` is empty or holds a malformed selector, `namespaceSelector` is malformed, or `exporterRef` names no ExporterConfig in the namespace. A `namespaceSelector` reaching a namespace that has not granted tracing is admitted with a warning, as for a PodTrace; the operator still enforces consent at reconcile time.

## Status reference

| Field | Notes |
|---|---|
| `podTraceRef` | Reference to the generated child `PodTrace` (same namespace). |
| `matchedPods` | Live pod count, aggregated from the child. |
| `targetNamespaces` | Resolved namespace set, from the child. |
| `conditions` | `Ready` (mirrors the child), `Reconciled`, `Degraded`, `Paused`. |

## How it relates to PodTrace

- `ApplicationTrace` (`appt`) — the application object you manage.
- It owns one `PodTrace` (`pt`) named after the application; that `PodTrace`
  carries `spec.appSelector` = the union of `selectors`.
- Want a single workload? Use a plain `PodTrace` with `spec.selector` (or
  `podtrace watch --app NAME`). Want the application abstraction (one object,
  aggregated status, cascade delete)? Use `ApplicationTrace`.

## Common operations

```bash
kubectl apply -f application.yaml
kubectl get applicationtraces.podtrace.io -A          # or: kubectl get appt -A
kubectl get appt checkout -n my-app -o yaml           # status.matchedPods, conditions
kubectl get pt -n my-app -l podtrace.io/application=checkout   # the generated child
kubectl delete appt checkout -n my-app                # cascades to the child PodTrace
```

## Related

- [crd-podtrace.md](crd-podtrace.md) — the underlying continuous-trace CR (and `appSelector`)
- [crd-exporterconfig.md](crd-exporterconfig.md) — exporter setup
- [operator.md](operator.md) — operator architecture
