# ExporterConfig — exporter destination CR

`ExporterConfig` is namespace-scoped and reusable. Multiple `PodTrace`
or `PodTraceSession` CRs in the same namespace can reference one
`ExporterConfig` via `spec.exporterRef.name`. The operator materializes
each ExporterConfig referenced into an exporter bundle (ConfigMap +
optional Secret) in `podtrace-system`, which agents and session Jobs
read.

## Five exporter types

The CRD's `spec.type` is an enum: `otlp` | `jaeger` | `zipkin` |
`splunk` | `datadog`. The CRD also requires the matching typed field
to be populated; the validating webhook enforces this cross-field
invariant.

### OTLP

```yaml
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata:
  name: otlp-collector
  namespace: my-app
spec:
  type: otlp
  otlp:
    endpoint: otel-collector.observability:4318
    protocol: http              # http | grpc
    insecure: true              # disable TLS — do not use in prod
    headers:
      - name: X-Tenant
        value: team-a            # literal header
      - name: Authorization
        valueFrom:
          name: otlp-auth         # Secret in same namespace
          key: bearer-token
```

Literal-valued headers go straight into the bundle ConfigMap.
Secret-valued headers are loaded into the companion Secret under the
fixed `credential` key. Today only ONE Secret-valued header is
supported per OTLP exporter.

#### Metrics as a second signal

An OTLP exporter can also carry the continuous metrics plane, to the same
endpoint and with the same headers:

```yaml
spec:
  type: otlp
  otlp:
    endpoint: otel-collector.observability:4318
    metrics:
      enabled: true
      interval: 60s             # default 60s, clamped to 10s-10m
```

OTLP only — no other exporter type in this set speaks OTLP metrics, and
a bundle that asks for metrics on another type is rejected rather than
silently ignored.

The plane must also be enabled on the TracerConfig
(`spec.agent.metrics.enabled`), because the push republishes that surface
rather than producing a second one. Several PodTraces pointing at the same
collector share one metric stream, since the series are node-wide rather
than per-CR. See [continuous-metrics.md](continuous-metrics.md) for the
wire details, including how convention metric names differ between the
scrape and the push.

### Jaeger

```yaml
spec:
  type: jaeger
  jaeger:
    endpoint: jaeger-collector.observability:4318
```

Agent mode ships to Jaeger's **OTLP/HTTP receiver** (port 4318 by
default), not the legacy Thrift `/api/traces` endpoint. Jaeger 1.35+
ships an OTLP receiver out of the box. No credentials.

### Zipkin

```yaml
spec:
  type: zipkin
  zipkin:
    endpoint: http://zipkin.observability:9411/api/v2/spans
```

Direct Zipkin export **is not supported in agent mode**. The upstream
OTel SDK Zipkin exporter is deprecated. To route spans to Zipkin,
deploy an OpenTelemetry Collector with the `zipkin` exporter and
configure podtrace with `type: otlp` pointing at the Collector. See
[Agent-mode exporter support](./tracing-exporters.md#agent-mode-exporter-support).

### Splunk

```yaml
spec:
  type: splunk
  splunk:
    endpoint: splunk-otel-collector.splunk:4318
    tokenSecretRef:
      name: splunk-access-token
      key: token
```

Agent mode ships to the **Splunk OpenTelemetry Collector** over
OTLP/HTTP. The token in `tokenSecretRef` is forwarded as the
`X-SF-TOKEN` header. Direct HEC (`:8088/services/collector`) is not
the agent's wire format; deploy the Splunk OTel Collector and route to
its OTLP port instead.

### DataDog

```yaml
spec:
  type: datadog
  datadog:
    endpoint: datadog-agent.datadog:4318  # optional; defaults to this
    site: datadoghq.com                    # or datadoghq.eu, etc.
    apiKeySecretRef:
      name: dd-api-key
      key: api_key
```

Agent mode ships to the **DataDog Agent's OTLP intake**. Enable the
OTLP receiver in your Datadog Agent Helm values (the receiver is off
by default on older Agent versions). The API key in
`apiKeySecretRef` is forwarded as the `DD-API-KEY` header.

## Optional fields shared by all types

```yaml
spec:
  samplePercent: 50               # 0-100; sampler applied at the exporter SDK
```

## Spec reference (full)

| Field | Type | Notes |
|---|---|---|
| `type` | enum | `otlp` / `jaeger` / `zipkin` / `splunk` / `datadog` |
| `otlp.endpoint` | string | Required when `type=otlp`. |
| `otlp.protocol` | enum | `http` / `grpc`. Defaults to `http`. |
| `otlp.insecure` | bool | Disables TLS. |
| `otlp.headers[]` | list | Either literal `value` or `valueFrom: SecretKeySelector`. |
| `otlp.headersFromSecret` | object | `{name}` reference to a Secret in the same namespace; every key in that Secret becomes an OTLP header. Use for bulk or additional secret-backed headers beyond the single `headers[].valueFrom` credential. |
| `otlp.metrics.enabled` | bool | Pushes the continuous metrics plane to this endpoint beside the spans. Requires the plane to be on in the TracerConfig. |
| `otlp.metrics.interval` | duration | Push period. Defaults to `60s`; clamped to `10s`-`10m`. Must not be negative. |
| `jaeger.endpoint` | string | Required when `type=jaeger`. |
| `zipkin.endpoint` | string | Required when `type=zipkin`. |
| `splunk.endpoint` | string | Splunk HEC URL. |
| `splunk.tokenSecretRef` | object | `{name, key}` selector. |
| `datadog.site` | string | E.g. `datadoghq.com`, `datadoghq.eu`. |
| `datadog.apiKeySecretRef` | object | `{name, key}` selector. |
| `samplePercent` | int 0-100 | Optional sampling rate. |

## Bundle materialization

For each PodTrace or session referencing an ExporterConfig, the
operator creates two objects in `podtrace-system`:

1. **ConfigMap** named `pt-bundle-<exporterUID>` (continuous) or
   `pts-bundle-<sessionUID>` (session). Carries
   `type`, `endpoint`, `protocol`, `insecure`, `site`,
   `headers.<name>` for literals, `header_secret_name` when applicable,
   `sample_percent`, `metrics` and `metrics_interval_seconds` when metric
   export is on, and a `bundle.yaml` blob the CLI consumes.
2. **Secret** with the same name (created only when the exporter
   references credential material). Carries the resolved value under
   the fixed `credential` key, plus one `header.<name>` key for each
   key of the Secret referenced by `otlp.headersFromSecret`.

## Credential rotation

When you update the upstream Secret referenced by an ExporterConfig,
the operator re-reads it on the next reconcile and patches the
companion bundle Secret in `podtrace-system`. Agents pick up the new
credential on their next bundle reload (driven by ConfigMap
ResourceVersion change).

To force an immediate refresh without waiting for the next reconcile
tick:

```bash
kubectl annotate exporterconfig <name> -n <ns> \
  podtrace.io/rotated-at="$(date -Iseconds)" --overwrite
```

This causes the operator to see a generation bump and re-render the
bundle.

## Cross-namespace references

ExporterConfig and the user-namespace Secret it references must live
in the same namespace. The operator does not (and intentionally cannot)
read Secrets from other user namespaces — that boundary keeps the
operator's RBAC narrow.

If you want to share one ExporterConfig across many namespaces, copy
the CR into each namespace (the bundle is per-CR anyway).

## Who may create an ExporterConfig

Treat `create` on ExporterConfig as equivalent to `get` on every Secret in
that namespace. The operator copies whichever Secret an ExporterConfig
names, using its own access rather than its author's: every key of
`otlp.headersFromSecret` is sent as a request header to the configured
endpoint, `headers[].valueFrom` sends one key, and
`reportRef.objectStore.credentialsSecretRef` on a session hands the
uploader that Secret's cloud credentials. The `SecretMissing` and
`SecretKeyMissing` readiness reasons also tell the author whether a Secret
or key exists.

This is by design. Only grant ExporterConfig, PodTrace and PodTraceSession
writes to principals that may already read the namespace's Secrets, which
is true of the built-in `edit` and `admin` roles. Where a principal may
create workloads but must not read Secrets (Secrets managed by an external
operator, say), do not give it podtrace write access in that namespace.

## Status reference

The operator runs a dedicated reconciler that keeps an ExporterConfig's
status fresh:

```yaml
status:
  referencedBy: 3
  observedGeneration: 4
  conditions:
    - type: Ready
      status: "True"
      reason: SecretsResolved
      message: all referenced Secrets resolved
    - type: Referenced
      status: "True"
      reason: Referenced
      message: 3 referent(s)
```

### Field semantics

| Field | Meaning |
|---|---|
| `referencedBy` | Count of `PodTrace` + non-terminal `PodTraceSession` objects in the same namespace whose `spec.exporterRef.name` matches this EC. Terminal sessions (`Completed`, `Failed`) are excluded so the count reflects active load. |
| `observedGeneration` | Mirrors `metadata.generation` on the last successful reconcile. |

### Conditions

| Type | Status | Reason | Meaning |
|---|---|---|---|
| `Ready` | `True` | `SecretsResolved` | All required Secrets and keys resolved. |
| `Ready` | `False` | `SecretMissing` | A referenced Secret does not exist. The message names the Secret. |
| `Ready` | `False` | `SecretKeyMissing` | The referenced Secret exists but lacks the required key. The message names both. |
| `Ready` | `False` | `InvalidSpec` | `spec.type` does not match the populated typed field. Normally blocked by the admission webhook; this reason appears on clusters where the webhook is disabled. |
| `Ready` | `Unknown` | `TransientError` | Transient API error during reconcile. Self-heals on the next watch event. |
| `Referenced` | `True` | `Referenced` | At least one `PodTrace` or active `PodTraceSession` uses this EC. |
| `Referenced` | `False` | `Unreferenced` | No active referents. Useful for alerting on orphaned ECs: `kubectl wait --for=condition=Referenced=false`. |

### What the status reconciler does *not* do

- It does **not** probe the exporter endpoint. Network reachability is reported by the agent at first export, surfacing as a `Degraded` condition on the referring `PodTrace` / `PodTraceSession`. Probing here would flap on transient backend issues and cause false alerts across every CR that references the EC.
- It does **not** validate credential *contents* against the remote service (e.g. it never tries the Splunk token against Splunk). The agent learns about credential rejections on first export.
- It does **not** mutate the spec. Missing Secrets must be fixed by the user; the controller surfaces the condition and waits.

## Related

- [crd-podtrace.md](crd-podtrace.md)
- [crd-podtracesession.md](crd-podtracesession.md)
- [operator.md](operator.md)
- [tracing-exporters.md](tracing-exporters.md) — original CLI-mode exporter docs
