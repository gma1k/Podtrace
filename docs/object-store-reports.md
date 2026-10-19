# Object-store session reports

User-facing reference for the `objectStore` sink on
`PodTraceSession.spec.reportRef`.

## What it does

When `spec.reportRef.objectStore` is set, the operator attaches a native
sidecar (`report-uploader`) to each session Job. After the main session
container finishes writing `/var/run/podtrace/report.txt`, the sidecar
uploads it (and the matching `summary.json`) to the cloud object store
named by `spec.reportRef.objectStore.uri`.

Once the upload succeeds, the operator surfaces:

- `status.reportLocation` — the resolved object URI, e.g.
  `s3://my-bucket/reports/diag-abc-2026-05-13T12-34-56Z.txt`
- `status.conditions[type=ReportUploaded]` —
  - `True` (`ObjectStoreUploadSucceeded`) when the upload landed.
  - `False` (`ObjectStoreUploadFailed`) when the sidecar exited non-zero;
    `message` carries the sidecar's stderr.
  - `Unknown` (`UploadPending`) while the sidecar is still running.

## When to use

| Sink | Best for | Max size |
|---|---|---|
| `configMap` | small text reports a human will copy/paste | ~1 MiB (etcd limit) |
| `secret` | reports containing sensitive paths or payloads | ~1 MiB (etcd limit) |
| `objectStore` | large reports, archival, downstream pipelines | bucket-dependent (TB-scale) |

The three sinks are mutually exclusive — set at most one.

## Cluster requirements

- **Kubernetes 1.29+**. The sidecar uses the native sidecar pattern
  (initContainer with `restartPolicy: Always`). Older clusters will
  silently treat the sidecar as a regular initContainer, which exits
  before the main session starts and breaks the upload.
- `TracerConfig.spec.session.sidecarUploader: true`. Off by default
  because most clusters have no destination bucket. Flip via Helm:
  `--set tracerConfig.sidecarUploader=true`.

## URI scheme

```
s3://<bucket>/<key-or-prefix>
gs://<bucket>/<key-or-prefix>
azblob://<storage-account>/<container>/<key-or-prefix>
```

A **trailing slash** means "prefix mode" — the uploader picks the
object filename:

| URI | Resolves to (example) |
|---|---|
| `s3://b/reports/` | `s3://b/reports/<pod>-2026-05-13T12-34-56Z.txt` |
| `s3://b/reports/fixed.txt` | `s3://b/reports/fixed.txt` |

In prefix mode the uploader **also** writes a second object:
`<key>.summary.json` carrying the same compact summary that lands on
`status.summary`. Use prefix mode unless you have a downstream pipeline
that needs a fixed key (and accepts that consecutive sessions will
overwrite it).

## Credentials

The uploader sidecar runs in the **podtrace system namespace**, not in the
session's namespace. Its ambient identity — the node's EC2 instance profile,
the AKS node / kubelet managed identity, the GKE node service account, or a
workload-identity grant to the system namespace — belongs to the cluster
admin. Two rules keep a session owner from borrowing it:

1. **Ambient credentials are admin-only by default.** A session in the
   operator's own namespace (`podtrace-system`) may leave
   `credentialsSecretRef` unset (or omit the credential keys) and use the
   ambient identity. A session in any other namespace must supply a static
   credential in its Secret, unless the admin sets
   `operator.objectStore.crossNamespaceAmbientCredentials: true`
   (`PODTRACE_OBJECTSTORE_CROSS_NAMESPACE_AMBIENT_CREDENTIALS`), which lets
   every namespace that can create a PodTraceSession write with that
   identity to any bucket it can reach.
2. **A custom `endpoint` needs static credentials or the admin's
   allowlist.** The Secret's `endpoint` is honoured when the same Secret
   carries a static credential (S3 `access_key_id` + `secret_access_key`,
   GCS `service_account_json`, Azure `account_key` or the SPN trio), or when
   its host is in `operator.objectStore.endpointAllowlist`
   (`PODTRACE_OBJECTSTORE_ENDPOINT_ALLOWLIST`, comma-separated,
   `*.example.com` matches subdomains). Without either, an ambient token
   would be sent to whatever host the Secret names. An allowlisted endpoint
   with no static credential still needs rule 1 to allow ambient
   credentials, except GCS, which then uploads unauthenticated.

The endpoint must be an `http(s)://` URL, and a link-local or metadata
address (`169.254.169.254`, `168.63.129.16`, `fd00:ec2::254`, ...) is
always refused. The bucket connection goes through the same egress guard as
the exporters (see [configuration.md](configuration.md#egress-guard)):
metadata addresses are refused at dial time too, and redirects are not
followed. Credential providers (IMDS, managed identity, the GKE metadata
server) keep their own clients.

A session the rules refuse gets `Degraded=True` with reason
`ObjectStoreCreds` before any Job is created; the sidecar enforces the same
rules again when it uploads.

| Setup | Works by default |
|---|---|
| Static keys, no endpoint (AWS S3, GCS SA key, Azure key/SPN) | yes, any namespace |
| Static keys + endpoint (MinIO, R2, Wasabi, SeaweedFS, Azurite) | yes, any namespace |
| No Secret / no static keys, session in `podtrace-system` | yes (ambient) |
| No Secret / no static keys, session in another namespace | no — set `crossNamespaceAmbientCredentials` |
| Endpoint without static keys (S3 VPC endpoint, sovereign Azure cloud, fake-gcs-server) | no — add the host to `endpointAllowlist` |

For clusters without ambient credentials, supply a Secret in the
session's namespace and reference it from `credentialsSecretRef.name`.
The Secret's keys are read by the backend per the schema below.

### S3 (`s3://`)

| Key | Required when | Notes |
|---|---|---|
| `access_key_id` | no ambient credentials | static AWS access key |
| `secret_access_key` | no ambient credentials | static AWS secret |
| `session_token` | optional | STS session tokens |
| `region` | optional | defaults to `AWS_REGION` env, then `us-east-1` |
| `endpoint` | S3-compatible (R2, Wasabi, B2, SeaweedFS) | URL of the non-AWS endpoint; needs the static keys or an allowlisted host |
| `force_path_style` | usually with `endpoint` | set to `"true"` for path-style addressing |

### GCS (`gs://`)

| Key | Required when | Notes |
|---|---|---|
| `service_account_json` | no ambient credentials | full SA key JSON (`gcloud iam service-accounts keys create`) |
| `endpoint` | testing only | for fake-gcs-server / dev clusters; without `service_account_json` the host must be allowlisted and the upload is unauthenticated |

### Azure Blob (`azblob://`)

| Key | Required when | Notes |
|---|---|---|
| `account_key` | shared-key auth | preferred for local-dev / Azurite |
| `tenant_id` / `client_id` / `client_secret` | SPN auth | all three required |
| `endpoint` | Azurite, sovereign clouds | overrides the `https://<account>.blob.core.windows.net` default; needs `account_key`, the SPN trio, or an allowlisted host |

Leave every key absent to fall back to `DefaultAzureCredential`
(Managed Identity, env vars, CLI auth), subject to the ambient rule above.

## Example: S3 with explicit credentials

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: backup-s3-creds
  namespace: my-app
type: Opaque
stringData:
  access_key_id: AKIA...
  secret_access_key: ...
  region: eu-west-1
---
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata:
  name: nightly-trace
  namespace: my-app
spec:
  selector:
    matchLabels: { app: api }
  duration: 60s
  exporterRef:
    name: prod-otlp
  reportRef:
    objectStore:
      uri: s3://podtrace-reports/diagnose/
      credentialsSecretRef:
        name: backup-s3-creds
```

After the session completes:

```bash
kubectl -n my-app get pts nightly-trace \
  -o jsonpath='{.status.reportLocation}'
# s3://podtrace-reports/diagnose/nightly-trace-...-2026-05-13T12-34-56Z.txt
```

## Example: GCS with ambient credentials (no Secret)

```yaml
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSession
metadata:
  name: gcs-trace
  namespace: my-app
spec:
  selector:
    matchLabels: { app: api }
  duration: 60s
  exporterRef:
    name: prod-otlp
  reportRef:
    objectStore:
      uri: gs://podtrace-reports/diagnose/
      # No credentialsSecretRef — Workload Identity supplies creds.
```

The session pod runs in `podtrace-system` under a per-session
ServiceAccount, so grant the bucket to the node service account or to the
`podtrace-system` namespace's Workload Identity principal set. A session in
a namespace other than `podtrace-system` needs the admin's
`crossNamespaceAmbientCredentials` opt-in to use it.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `ReportUploaded=False`, message contains `dial tcp: lookup ... no such host` | bucket name typo or wrong region |
| `ReportUploaded=False`, message contains `AccessDenied` | credentials are valid but lack `s3:PutObject` (or equivalent) on the bucket |
| `Degraded=True` reason `ObjectStoreCreds`, message `ambient credentials are not allowed` | session outside `podtrace-system` with no static credential; add keys to the Secret or ask the admin for `crossNamespaceAmbientCredentials` |
| `Degraded=True` reason `ObjectStoreCreds`, message `custom endpoint host ... is only honoured` | Secret has `endpoint` but no static credential; add the keys or ask the admin to allowlist the host |
| `ReportUploaded=False`, message contains `netguard: refusing` | the endpoint redirects, or resolves to a link-local / metadata address |
| `ReportUploaded=Unknown` indefinitely | cluster is <1.29 — the sidecar isn't getting native lifecycle semantics; upgrade or flip `tracerConfig.sidecarUploader=false` and use a ConfigMap sink instead |

## Security considerations

- The uploader sidecar runs with the **session pod's** ServiceAccount in
  the system namespace. It does NOT need K8s API access — it reads files
  from the shared rundir and uploads via HTTPS to the cloud.
- Its ambient cloud identity is the admin's; see
  [Credentials](#credentials) for when a session may use it.
- The credentials Secret is projected into the sidecar only — the main
  session container cannot see it.
- Object URIs are stored verbatim on the CR; do not embed secrets in
  the URI (use the Secret).