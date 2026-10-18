# Viewing podtrace events

You created a `PodTrace`, `PodTraceSession`, or `PodTraceSchedule`, the
operator is happy, the agent is happy — now where are the actual
syscalls the pod made?

This guide is the canonical answer. There are four surfaces; each
trades off freshness, durability, and how kubectl-friendly the access
path is. Pick the one that matches what you're doing.

## TL;DR — pick a surface

| You want… | Use | Read it with |
|---|---|---|
| Live events streaming in your terminal | `kubectl podtrace` CLI mode | the CLI itself prints them |
| One bounded snapshot you can `kubectl get` | `PodTraceSession` with `spec.reportRef.configMap` | `kubectl get cm <name> -o go-template='{{range $k,$v := .data}}{{$v}}{{end}}'` |
| Archived per-run snapshots over time | `PodTraceSchedule` with `reportRef.objectStore` | `aws s3 cp s3://…/<key> -` |
| Real-time spans in a UI (production) | any CR with an `ExporterConfig` pointed at OTLP | Jaeger / Tempo / Datadog / Splunk |

## Live CLI streaming

The CLI runs from your workstation against any pod in the cluster.
Under the hood it spawns a short-lived privileged pod on the **target
pod's node** (one per node when targets span multiple nodes), runs
eBPF there against the host's `/sys/fs/cgroup`, and streams events
back to your terminal. The spawn pod is deleted on exit.

```bash
# One pod, real-time
kubectl podtrace -n my-app api-pod-abc

# Many pods via label selector (one spawn pod per node)
kubectl podtrace -n my-app --pod-selector app=api

# Ctrl+C → spawn pod stopped gracefully, final diagnostic report on stdout
```

### Why a spawn pod

eBPF programs run in the kernel of the machine where they're loaded.
The workstation kernel can't observe a pod running on a remote node,
so the CLI loads eBPF *on that node* by way of an ephemeral pod with
`hostPID` and the host's `/proc` + `/sys/fs/cgroup` mounted at
`/host/*`. The child binary respects `PODTRACE_PROC_BASE` and
`PODTRACE_CGROUP_BASE` env vars and finds the cgroup hierarchy there.

### Flags that control the spawn

| Flag | Default | What it does |
|---|---|---|
| `--local` | off | Skip the spawn; run eBPF on the workstation. Use for kind/minikube/docker-desktop where the workstation IS the kubelet host. |
| `--image` | linker default `ghcr.io/gma1k/podtrace:<CLI version>` | Override the image the spawn pod runs. Also settable via `PODTRACE_IMAGE` env. |
| `--spawn-namespace` | target pod's namespace | Namespace where the spawn pod lives. Also settable via `PODTRACE_SPAWN_NAMESPACE`. |

### Required cluster setup

The spawn pod is privileged (`hostPID`, `CAP_BPF`, `CAP_SYS_ADMIN`,
hostPath mounts). If the target namespace enforces PodSecurity
"restricted" or "baseline", admission rejects the spawn pod with an
error the CLI surfaces verbatim, including the one-line remediation:

```bash
kubectl label ns/<ns> pod-security.kubernetes.io/enforce=privileged --overwrite
```

Or use `--spawn-namespace=<centralized-ns>` to point at a namespace
you've already labelled for privileged workloads.

RBAC needed in **your kubeconfig** (the workstation): `pods` (`create`, `get`,
`delete`, `list`, `watch`), `pods/log`, `pods/attach`. Falls back to
`pods/log` (stream-only, no stdin) if `pods/attach` is denied. **The spawn
pod itself runs as the default ServiceAccount and needs zero RBAC** — the
workstation pre-resolves every target's containerID and hands it to the
spawn pod via a flag, so the child binary never calls the K8s API.

For the full CLI flag reference see [usage.md](usage.md).

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `cgroup path not found for container <id>` | You passed `--local` on a cluster where the workstation isn't the kubelet host | Remove `--local`, or run on the kubelet host |
| `violates PodSecurity` admission error | Spawn namespace enforces non-privileged PSA | Label the namespace (CLI prints the exact command) or use `--spawn-namespace` |
| `ImagePullBackOff` on the spawn pod | Cluster can't pull the image | Use `--image=<reachable-ref>` or pre-pull via `talosctl image pull` / your registry mirror |
| Spawn pod created but stdin doesn't work | RBAC denies `pods/attach` (degraded mode) | Grant `pods/attach` in the spawn namespace |

## Surface 2: a single ConfigMap (kubectl-friendly snapshot)

Best for short, point-in-time diagnose runs you want to share via a
manifest, paste into a ticket, or archive into git.

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: my-trace, namespace: my-app }
spec:
  selector: { matchLabels: { app: api } }
  duration: 30s
  filters: [dns, net, fs, proc]          # capture everything
  exporterRef: { name: my-otlp }
  reportRef:
    configMap: { name: my-trace-report }
EOF

# Wait until the session reaches the Completed state
until [ "$(kubectl -n my-app get podtracesession my-trace -o jsonpath='{.status.state}')" = "Completed" ]; do sleep 5; done

# Read the full human-readable report
kubectl -n my-app get cm my-trace-report -o go-template='{{range $k,$v := .data}}{{$v}}{{end}}' | less
```

What the report contains (sample from a curl workload):

```
=== Diagnostic Report (collected over 30.013s) ===

Summary:
  Total events: 3,643
  Events per second: 115.3

DNS Statistics:
  Total lookups: 4
  P50: 0.00ms  P95: 0.00ms  P99: 0.00ms

TCP Statistics:
  Send operations: 112  Receive operations: 662
  Average RTT: 0.02ms  Max: 0.26ms
  P50=0.01ms  P95=0.09ms  P99=0.11ms
  Total bytes transferred: 678.58 KB

Process and Syscall Activity:
  Open calls: 2,848
  Top opened files:
    - /usr/local/lib/libcurl.so.4 (68 opens)
    - /usr/local/lib/libssh2.so.1 (68 opens)
    …

Error Chains:
  Chain 1 (Severity: critical):
    Root cause: PROC error on /etc/ld-musl-x86_64.path (code: -2)
    Chain length: 34 errors
    Suggestions:
      - No such file or directory — verify file paths and permissions
```

The "Error Chains" section is podtrace's diagnostic engine: it groups
related failures into causal chains and offers fixes.

Use `reportRef.secret` instead of `configMap` when the report may
contain sensitive hostnames/paths/payloads. Same read pattern,
`-o go-template='{{range $k,$v := .data}}{{$v}}{{end}}' | base64 -d`.

**Size limit**: ConfigMaps and Secrets are capped at 1 MiB by etcd.
For longer runs or noisier workloads, prefer Surface 3.

## Surface 3: object store (S3 / GCS / Azure)

When `reportRef.objectStore` is set, the operator attaches a native
sidecar to each session Job. After the diagnose finishes, the sidecar
uploads the report (and a JSON summary) to the bucket and surfaces the
result on `.status.reportLocation` and `Conditions[ReportUploaded]`.

```yaml
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata: { name: long-diag, namespace: my-app }
spec:
  selector: { matchLabels: { app: api } }
  duration: 10m
  filters: [dns, net, fs, proc]
  exporterRef: { name: my-otlp }
  reportRef:
    objectStore:
      uri: "s3://acme-podtrace-reports/diagnose/"
      credentialsSecretRef: { name: s3-creds }       # or use ambient creds
```

Each run produces:

- `<prefix>/<pod-name>-<rfc3339>.txt` — the human report
- `<prefix>/<pod-name>-<rfc3339>.summary.json` — the compact summary

```bash
# Find the upload location for a completed session
kubectl -n my-app get podtracesession long-diag -o jsonpath='{.status.reportLocation}{"\n"}'

# Pull it down
aws s3 cp s3://acme-podtrace-reports/diagnose/long-diag-2026-05-15T12-34-56Z.txt -
```

Requirements + ambient-credential paths (IRSA, Workload Identity,
Managed Identity), failure modes, and cluster prereqs (Kubernetes
1.29+ for the native sidecar; `TracerConfig.spec.session.sidecarUploader: true`)
are documented in detail at [object-store-reports.md](object-store-reports.md).

## Surface 4: live spans in Jaeger / Tempo / Datadog / Splunk (production)

The CRDs are agnostic about the backend — point an `ExporterConfig` at
a real OTLP-compatible receiver and every event becomes a span you can
query live. This is the path for production observability.

```yaml
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata: { name: jaeger-otlp, namespace: my-app }
spec:
  type: otlp                            # see tracing-exporters.md for non-OTLP types
  otlp:
    endpoint: jaeger-collector.observability:4318
    protocol: http
    insecure: true
---
apiVersion: podtrace.io/v1alpha1
kind: PodTrace                            # continuous, not bounded
metadata: { name: api-live, namespace: my-app }
spec:
  selector: { matchLabels: { app: api } }
  filters: [dns, net, fs, proc]
  exporterRef: { name: jaeger-otlp }
```

Spans appear in Jaeger UI under the service name configured on the
receiver. For DataDog, Splunk HEC, Zipkin (via Collector), and
deployment recipes for each backend, see
[tracing-exporters.md](tracing-exporters.md).

## Recurring captures: PodTraceSchedule

If you want the diagnose to run every N minutes/hours and archive each
run, wrap a session template in a `PodTraceSchedule`:

```yaml
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSchedule
metadata: { name: nightly-diag, namespace: my-app }
spec:
  schedule: "0 2 * * *"                   # 02:00 every day
  concurrencyPolicy: Forbid
  successfulSessionsHistoryLimit: 7
  sessionTemplate:
    spec:
      selector: { matchLabels: { app: api } }
      duration: 5m
      filters: [dns, net, fs, proc]
      exporterRef: { name: my-otlp }
      reportRef:
        objectStore:                       # one object per run, never overwritten
          uri: "s3://acme-podtrace-reports/nightly/"
```

ConfigMap sinks under a schedule **overwrite the same ConfigMap** on
every run (one named output, "latest only"). ObjectStore sinks
generate one file per run.

To manually fire a one-off from the schedule's template:

```bash
kubectl podtrace schedule trigger nightly-diag -n my-app           # honour suspend gate
kubectl podtrace schedule trigger nightly-diag -n my-app --force   # bypass it
kubectl podtrace schedule trigger nightly-diag -n my-app --print-only  # dry-run, prints YAML
```

Full schedule reference: [crd-podtraceschedule.md](crd-podtraceschedule.md).

## Inspecting a specific session's Job logs

Every PodTraceSession spawns one Job per node hosting a matched pod.
The Job's pod logs contain the **full report plus the live error-chain
analysis** — useful when you want to see the raw output the diagnose
binary printed.

```bash
SESSION=my-trace                     # session name
NS=my-app                            # session namespace

JOB=$(kubectl -n podtrace-system get jobs \
  -l podtrace.io/session=$SESSION,podtrace.io/session-namespace=$NS \
  -o name | head -1)

kubectl -n podtrace-system logs "$JOB"
```

If `successfulSessionsHistoryLimit` on a schedule keeps several
completed sessions around, this works for each of them.

## Why my session shows 0 events

Most common causes, in order:

1. **DNS-only filter against cached resolutions.** Glibc caches DNS;
   a curl loop hitting the same hostname every iteration triggers one
   DNS event total, not one per iteration. Widen `filters` or use a
   fresh hostname per request.
2. **Selector didn't match.** Check
   `kubectl get podtracesession <name> -o yaml | yq '.status.jobs'` —
   if `jobs[]` is empty the operator never created a tracer Job.
3. **Pod wasn't Running when the session started.** The operator only
   attaches to pods that are Running. Cold-start or just-evicted pods
   miss the capture window.
4. **Workload is genuinely idle.** Add load (e.g. `curl` in a loop)
   while the session runs.

## Where else this is documented

- CLI flags + sample reports: [usage.md](usage.md)
- The bounded-session CR in depth: [crd-podtracesession.md](crd-podtracesession.md)
- The continuous-trace CR: [crd-podtrace.md](crd-podtrace.md)
- The recurring-schedule CR: [crd-podtraceschedule.md](crd-podtraceschedule.md)
- ObjectStore upload internals: [object-store-reports.md](object-store-reports.md)
- All exporter types: [tracing-exporters.md](tracing-exporters.md)
