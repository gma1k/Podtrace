# Configuration Reference

Podtrace is configured entirely through environment variables, read once when
the process starts. There is no configuration file format, and **nothing in
podtrace reads a `.env` file**. The tracked [`.env.example`](../.env.example) at
the repository root is a reference listing only.

Where to set these depends on how podtrace runs:

| Mode | Where the variables go |
|---|---|
| Standalone CLI | Your shell, for example `PODTRACE_LOG_LEVEL=debug podtrace ...` |
| Helm install | `env` entries on the agent or operator values in `deploy/charts/podtrace` |
| Operator managed | The pod spec the operator generates, or the matching `TracerConfig` field |

Most runtime behavior also has a CRD or CLI equivalent, which takes precedence
where one exists. See [operator.md](operator.md) and
[crd-tracerconfig.md](crd-tracerconfig.md).

## How values are parsed

Podtrace uses **two boolean conventions**. Convention 1 covers everything except
the escape hatches, and it is the only one that trims whitespace and normalizes
case.

1. **`strconv.ParseBool`**, used by everything in `internal/config`. Accepts
   `true`, `TRUE`, `True`, `1`, `t` and their negatives. This is the common case.
2. **Exactly `"1"`**, used by the escape hatches listed under
   [Escape hatches](#escape-hatches). Setting one of those to `true` does
   nothing at all; only the literal `1` enables it.

Convention 2 compares against a raw string with no warning, so a value it does
not recognize is silently ignored. Only convention 1 reports the mismatch. Every
variable below follows convention 1 unless its row says otherwise, and the only
exceptions are in the escape hatches section.

Other rules:

- An empty value counts as unset, so the default applies.
- Integers must be **positive**. Zero, negative, or unparsable values are
  rejected, and the default is used instead.
- Durations are Go duration strings (`500ms`, `10s`, `5m`) and must be positive.
- A value that is set but rejected is **not silent**. Podtrace writes a JSON
  warning to stderr and falls back to the default:

  ```json
  {"level":"warn","component":"config","message":"environment variable ignored","key":"PODTRACE_EVENT_BATCH_SIZE","value":"-1","reason":"must be a positive integer"}
  ```

  If a variable seems to have no effect, check stderr for that line first.

## Core runtime

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PODTRACE_VERSION` | build value | Overrides the reported version string |
| `PODTRACE_IMAGE` | `ghcr.io/gma1k/podtrace` | Image used for spawned workloads |
| `PODTRACE_EVENT_BUFFER_SIZE` | `10000` | Userspace event channel depth |
| `PODTRACE_EVENT_BATCH_SIZE` | `100` | Events processed per batch |
| `PODTRACE_BATCH_INTERVAL` | `10ms` | Batch flush interval |
| `PODTRACE_SHUTDOWN_TIMEOUT` | `5s` | Grace period for a clean stop |
| `PODTRACE_RESOURCE_MONITOR_INTERVAL` | `5s` | Self-monitoring sample interval |
| `PODTRACE_CONTAINER_PID` | `1` | PID treated as the container's root process |
| `PODTRACE_MANAGEMENT_PORT` | `0` | `0` disables the management listener |
| `PODTRACE_GRPC_PORT` | `50051` | Port treated as gRPC for protocol detection |
| `PODTRACE_ARTIFACT_BASE` | unset | Confines session artifacts to this directory |

## eBPF and kernel

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_BPF_OBJECT` | unset (the embedded object) | Loads this object instead of the embedded one. Ignored with an error when podtrace runs with file capabilities or setuid; run as root to override |
| `PODTRACE_BTF_FILE` | unset | Explicit BTF path when the kernel exposes none |
| `PODTRACE_RING_BUFFER_SIZE_KB` | `2048` | Raise if you see dropped events |
| `PODTRACE_BPF_HASH_MAP_SIZE` | `4096` | Max entries in the per-program hash maps |
| `PODTRACE_BPF_LOG_LEVEL` | unset | Verifier log level; `0` or unset stays quiet |
| `PODTRACE_BPF_LOG_SIZE` | `65536` when verbose | Verifier log buffer size in bytes |
| `PODTRACE_USDT_ENABLED` | `true` | USDT probe discovery |
| `PODTRACE_DNS_PAYLOAD_ENABLED` | `true` | Parse DNS payloads |
| `PODTRACE_DNS_PACKET_CAPTURE` | `true` | Parse DNS via packets rather than libc uprobes |
| `PODTRACE_CRITICAL_PATH` | `true` | In `--diagnose` runs, break each served request's duration down by where it went; see [Language Runtime Adapters](language-runtime-adapters.md#critical-path) |
| `PODTRACE_CAPTURE_HEADERS` | unset | Comma-separated HTTP header allowlist, max 4 |

See [ebpf-internals.md](ebpf-internals.md) and
[compatibility.md](compatibility.md) for kernel requirements.

## Host paths

Override these when the host layout is not standard, for example on Talos or a
container with a remapped root.

| Variable | Default |
|---|---|
| `PODTRACE_CGROUP_BASE` | `/sys/fs/cgroup` |
| `PODTRACE_PROC_BASE` | `/proc` |
| `PODTRACE_DOCKER_BASE` | `/var/lib/docker/containers` |
| `PODTRACE_CONTAINERD_BASE` | `/var/lib/containerd` |
| `PODTRACE_CONTAINERD_OVERLAY_PATTERN` | `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs` |
| `PODTRACE_CONTAINERD_NATIVE_PATTERN` | `/var/lib/containerd/io.containerd.snapshotter.v1.native/snapshots/*/fs` |
| `PODTRACE_LDSOCONF_BASE` | `/etc` |
| `PODTRACE_BINARY_SEARCH_PATHS` | unset | Colon-separated. Unset falls back to `/app/main`, `/app/app`, `/usr/local/bin/app`, `/bin/app` |

## Kubernetes integration

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_K8S_ENRICHMENT_ENABLED` | `true` | Enrich events with pod metadata |
| `PODTRACE_K8S_USE_INFORMERS` | `true` | Use informers instead of direct API calls |
| `PODTRACE_K8S_INFORMERS_SYNC_TIMEOUT_SEC` | built-in | Informer cache sync timeout, in seconds |
| `PODTRACE_K8S_API_TIMEOUT` | `500ms` | Per-call API server timeout |
| `PODTRACE_K8S_CACHE_TTL` | `300` | Pod metadata cache TTL, in seconds |
| `PODTRACE_MAX_TARGET_PODS` | `256` | Cap on simultaneously targeted pods |
| `PODTRACE_SPAWN_NAMESPACE` | target pod's namespace | Namespace for the ephemeral spawn pod |
| `PODTRACE_SPAWN_SA` | unset | Service account for the spawn pod |
| `PODTRACE_NODE_LOCAL` | unset | Sentinel; `1` marks a node-local run |
| `PODTRACE_BOOTSTRAP_IMAGE` | unset | Image for the bootstrap `TracerConfig` |
| `PODTRACE_BOOTSTRAP_TC_NAME` | unset | Name of the bootstrap `TracerConfig` |

## CRI resolution

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_CRI_RESOLVE` | `true` | Resolve cgroup paths via the CRI socket |
| `PODTRACE_CRI_ENDPOINT` | autodetected | Explicit CRI socket path |
| `PODTRACE_CRI_CGROUP_FIELDS` | unset | Extra comma-separated JSON fields to search for the cgroup path |
| `PODTRACE_CRI_ALLOW_PODMAN` | off | Convention 2: exactly `1` |

## Metrics

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_METRICS_ADDR` | `127.0.0.1:3000` | Prometheus listener address |
| `PODTRACE_METRICS_LABEL_LIMIT` | `200` | Max distinct label values |
| `PODTRACE_METRICS_POD_LABEL_LIMIT` | `500` | Max distinct pod label values |
| `PODTRACE_METRICS_ENABLE_PPROF` | `false` | Also enabled by `PODTRACE_PROFILING_ENABLED` |

See [metrics.md](metrics.md).

## Tracing exporters

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_TRACING_ENABLED` | `false` | Master switch |
| `PODTRACE_TRACING_SAMPLE_RATE` | `1.0` | Fraction of traces exported |
| `PODTRACE_TRACING_SYNTHESIZE_SPANS` | `false` | Build spans from correlated events |
| `PODTRACE_TRACING_EXPORTER_TIMEOUT` | `10s` | Per-export timeout |
| `PODTRACE_OTLP_ENDPOINT` | `http://localhost:4318` | Default exporter |
| `PODTRACE_JAEGER_ENDPOINT` | unset | Opt-in; no default endpoint is assumed |
| `PODTRACE_SPLUNK_ENDPOINT` | unset | Requires `PODTRACE_ALERT_SPLUNK_ENABLED` |
| `PODTRACE_SPLUNK_TOKEN` | unset | HEC token |
| `PODTRACE_DATADOG_ENDPOINT` | unset | Opt-in, e.g. `http://localhost:8126/v0.4/traces` |
| `PODTRACE_DATADOG_API_KEY` | unset | |
| `PODTRACE_ZIPKIN_ENDPOINT` | unset | Opt-in, e.g. `http://localhost:9411/api/v2/spans` |
| `PODTRACE_EXPORTER_CREDENTIAL` | unset | Inline credential; takes precedence over the file form |
| `PODTRACE_EXPORTER_CREDENTIAL_FILE` | unset | Path to a credential file |

See [distributed-tracing.md](distributed-tracing.md) and
[tracing-exporters.md](tracing-exporters.md).

## Alerting

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_ALERTING_ENABLED` | `false` | Master switch |
| `PODTRACE_ALERT_EVENTS_ENABLED` | `true` | Emit Kubernetes Events for alerts |
| `PODTRACE_ALERT_MIN_SEVERITY` | `warning` | Minimum severity to dispatch |
| `PODTRACE_ALERT_WEBHOOK_URL` | unset | Generic webhook sink |
| `PODTRACE_ALERT_SLACK_WEBHOOK_URL` | unset | Slack incoming webhook |
| `PODTRACE_ALERT_SLACK_CHANNEL` | `#alerts` | |
| `PODTRACE_ALERT_SPLUNK_ENABLED` | `false` | Gates the Splunk endpoint and token |
| `PODTRACE_ALERT_DEDUP_WINDOW` | `5m` | Suppress repeats inside this window |
| `PODTRACE_ALERT_RATE_LIMIT` | `10` | Alerts per minute |
| `PODTRACE_ALERT_HTTP_TIMEOUT` | `10s` | |
| `PODTRACE_ALERT_MAX_RETRIES` | `3` | |
| `PODTRACE_ALERT_MAX_PAYLOAD_SIZE` | `1048576` | 1 MiB |
| `PODTRACE_ALERT_WARN_PCT` | `80` | Clamped to 0 to 100 |
| `PODTRACE_ALERT_CRIT_PCT` | `90` | Clamped to 0 to 100 |
| `PODTRACE_ALERT_EMERG_PCT` | `95` | Clamped to 0 to 100 |

See [alerting.md](alerting.md).

## Profiling

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_PROFILING_ENABLED` | `false` | Also turns on the pprof endpoint |
| `PODTRACE_PROFILING_PPROF_PORTS` | `6060,8080,8081,9090,2345` | Ports scanned for a pprof server |
| `PODTRACE_PROFILING_AUTO_TRIGGER_MS` | `500` | Latency that auto-starts a profile |
| `PODTRACE_PROFILING_DEFAULT_DURATION` | `30s` | |
| `PODTRACE_PROFILING_MAX_CONCURRENT` | `1` | |

See [profiling.md](profiling.md).

## Caches

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_CACHE_MAX_SIZE` | `10000` | Process cache entries |
| `PODTRACE_CACHE_TTL_SECONDS` | `3600` | |
| `PODTRACE_CACHE_EVICTION_THRESHOLD` | `0.9` | Fill ratio that triggers eviction |
| `PODTRACE_PROCESS_CACHE_EVICTION_RATIO` | `0.9` | |
| `PODTRACE_PID_CACHE_EVICTION_RATIO` | `0.9` | |

## Rate limiting, sampling, and resilience

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_RATE_LIMIT_PER_SEC` | `10` | |
| `PODTRACE_RATE_LIMIT_BURST` | `20` | |
| `PODTRACE_EVENT_SAMPLING_RATE` | `100` | Sample 1 in N when saturated |
| `PODTRACE_ERROR_BACKOFF_ENABLED` | `true` | |
| `PODTRACE_CIRCUIT_BREAKER_ENABLED` | `true` | |

## Analysis thresholds

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_TCP_LATENCY_SPIKE_MS` | `100` | |
| `PODTRACE_TCP_REALTIME_MS` | `10` | |
| `PODTRACE_UDP_LATENCY_SPIKE_MS` | `100` | |
| `PODTRACE_CONNECT_LATENCY_MS` | `1` | |
| `PODTRACE_HIGH_ERROR_COUNT_THRESHOLD` | `100` | |
| `PODTRACE_SPIKE_RATE_THRESHOLD` | `5.0` | |
| `PODTRACE_MIN_LATENCY_FOR_STACK_NS` | `1000000` | 1ms; below this no stack is captured |
| `PODTRACE_MAX_EVENTS_FOR_STACKS` | `10000` | |
| `PODTRACE_MAX_BYTES_FOR_BANDWIDTH` | `10485760` | 10 MiB |

## CLI output limits

These only affect how much detail the CLI prints. They do not change collection.

| Variable | Default |
|---|---|
| `PODTRACE_TOP_TARGETS_LIMIT` | `5` |
| `PODTRACE_TOP_FILES_LIMIT` | `5` |
| `PODTRACE_TOP_URLS_LIMIT` | `5` |
| `PODTRACE_TOP_PROCESSES_LIMIT` | `10` |
| `PODTRACE_TOP_STATES_LIMIT` | `10` |
| `PODTRACE_MAX_STACK_TRACES_LIMIT` | `5` |
| `PODTRACE_MAX_STACK_FRAMES_LIMIT` | `5` |
| `PODTRACE_MAX_OOM_KILLS_DISPLAY` | `5` |
| `PODTRACE_MAX_BURSTS_DISPLAY` | `3` |
| `PODTRACE_TIMELINE_BUCKETS` | `5` |
| `PODTRACE_MAX_CONNECTION_TARGETS` | `10` |

## Privacy

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_REDACT_PII` | `false` | Redacts passwords, bearer tokens, emails, card numbers |
| `PODTRACE_REDACT_CUSTOM_RULES` | unset | Additional redaction patterns |
| `PODTRACE_REDACT_DNS_NAMES` | `false` | Strip DNS names from captured events. Also set by the operator |

## Object store

| Variable | Default | Notes |
|---|---|---|
| `PODTRACE_OBJECTSTORE_CREDENTIALS_DIR` | unset | Directory of mounted credentials; unset disables upload |

See [object-store-reports.md](object-store-reports.md).

## Escape hatches

Every variable in this section weakens a safety check or a scoping guarantee.
They exist for debugging and for platforms where a check misfires, and they are
**not** intended for normal operation.

All of them use convention 2: the value must be exactly `1`. Setting them to
`true` has no effect.

| Variable | Effect when set to `1` |
|---|---|
| `PODTRACE_ALLOW_BROAD_CGROUP` | Permits a cgroup filter broad enough to match unintended workloads |
| `PODTRACE_ALLOW_ROOT_CGROUP` | Permits attaching at the root cgroup, tracing everything on the node |
| `PODTRACE_ALLOW_CGROUP_FILTER_DISABLE` | Lets podtrace continue when the cgroup filter cannot be applied. Uses `ParseBool`, not `1` |
| `PODTRACE_DISABLE_USERSPACE_CGROUP_FILTER` | Drops the userspace filter that backstops the kernel one |
| `PODTRACE_DISABLE_ATTRIBUTION_CORRELATOR` | Disables event to pod attribution |
| `PODTRACE_FORCE_DISABLE_L7` | Turns off all L7 protocol parsing |
| `PODTRACE_SKIP_SELINUX_CHECK` | Skips the SELinux preflight check |
| `PODTRACE_SKIP_LOCKDOWN_CHECK` | Skips the kernel lockdown preflight check |

Two more weaken transport security. Both use `ParseBool`:

| Variable | Default | Effect |
|---|---|---|
| `PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR` | `false` | Allows binding metrics to a non-loopback address |
| `PODTRACE_OTLP_INSECURE` | `false` | Allows plaintext OTLP to a non-loopback host |
| `PODTRACE_EXPORTER_INSECURE` | `false` | Allows plaintext export to a non-loopback host |
| `PODTRACE_ALERT_SPLUNK_ALLOW_HTTP` | `false` | Allows plaintext HTTP to the Splunk endpoint |
| `PODTRACE_ALERT_WEBHOOK_ALLOW_HTTP` | `false` | Allows plaintext HTTP to the webhook endpoint |

### Egress guard

Trace, event and metric exporters and the object-store report uploader
connect through a guard that refuses link-local and cloud-metadata addresses
(169.254.0.0/16, fe80::/10, `fd00:ec2::254`, `100.100.100.200`,
`168.63.129.16`, and those addresses reached through NAT64 `64:ff9b::/96` or
IPv4-mapped forms), the unspecified address and multicast, and refuses
redirects. Private and loopback
addresses stay reachable so in-cluster collectors work.

| Variable | Default | Effect |
|---|---|---|
| `PODTRACE_EXPORTER_BLOCK_PRIVATE` | `false` | Also refuses RFC 1918 / ULA private addresses |

`HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` are honoured. Behind a proxy the
guard cannot see the address the proxy dials, so it checks the target host
before handing the request over: a literal IP directly, a name by resolving it
locally and refusing if any address is blocked. That check is resolver-based:
a name whose answer changes between podtrace's lookup and the proxy's is not
caught, and a name the local resolver cannot resolve is left to the proxy.

### Object-store report uploads (operator)

Set on the operator Deployment (Helm `operator.objectStore.*`). See
[object-store-reports.md](object-store-reports.md#credentials).

| Variable | Default | Effect |
|---|---|---|
| `PODTRACE_OBJECTSTORE_CROSS_NAMESPACE_AMBIENT_CREDENTIALS` | `false` | Lets sessions outside the operator's namespace upload with the uploader's ambient identity |
| `PODTRACE_OBJECTSTORE_ENDPOINT_ALLOWLIST` | unset | Comma-separated hosts a Secret's `endpoint` may name without static credentials; `*.example.com` matches subdomains |

## Keeping this page correct

The authoritative list lives in `internal/config/config.go`, plus roughly thirty
variables read directly at their point of use in other packages. To find
anything not listed here:

```bash
git ls-files '*.go' | grep -v _test.go | xargs grep -hoE 'PODTRACE_[A-Z0-9_]+' | sort -u
```
