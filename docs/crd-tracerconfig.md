# TracerConfig — agent fleet infrastructure config

`TracerConfig` is cluster-scoped. Each one owns an **agent fleet**: a
DaemonSet, its ServiceAccount and RBAC, and the template for the session
Jobs the operator spawns.

Most clusters need exactly one, named `default`. A cluster with several
node pools that need different images, resource envelopes or capture
policies can run one TracerConfig per pool — see
[Multiple TracerConfigs](#multiple-tracerconfigs).

When `helm install --set operator.enabled=true` runs with the chart
default (`tracerConfig.create=true`), a `default` TracerConfig is
rendered automatically — most users never touch this CR directly.

## Rendered by the chart

The chart's
[`templates/cr-bootstrap.yaml`](../deploy/charts/podtrace/templates/cr-bootstrap.yaml)
applies the CR from `values.yaml` via a post-install hook Job:

| values.yaml field | TracerConfig field |
|---|---|
| `image.repository` + `image.tag` | `spec.image` |
| `image.pullPolicy` | `spec.imagePullPolicy` |
| `image.pullSecrets` | `spec.imagePullSecrets` |
| `namespace.name` | `spec.systemNamespace` |
| `agent.resources` | `spec.agent.resources` |
| `agent.priorityClassName` | `spec.agent.priorityClassName` |
| `agent.eventBufferSize` | `spec.agent.eventBufferSize` |
| `agent.statusReportInterval` | `spec.agent.statusReportInterval` |
| `agent.btfMode` | `spec.btfMode` |
| `agent.btfSource` | `spec.btfSource` |
| `agent.nodeSelector` | `spec.nodeSelector` |
| `agent.tolerations` | `spec.tolerations` |
| `session.resources` | `spec.session.resources` |
| `session.ttlSecondsAfterFinished` | `spec.session.ttlSecondsAfterFinished` |
| `session.activeDeadlineOffset` | `spec.session.activeDeadlineOffset` |
| `session.backoffLimit` | `spec.session.backoffLimit` |
| `session.maxConcurrentSessionsPerNode` | `spec.maxConcurrentSessionsPerNode` |
| `tracerConfig.sidecarUploader` | `spec.session.sidecarUploader` |
| `tracerConfig.redaction` | `spec.redaction` |

To change a setting, prefer `helm upgrade --reuse-values --set …`
rather than editing the CR directly — direct edits get reverted on the
next chart upgrade.

`--reuse-values` also keeps the defaults of the chart version you installed
from, so a default a newer chart changes is not applied by an upgrade that
reuses values. `session.activeDeadlineOffset`, for one, went from `30s` to
`90s`; to pick up a new default, set it with `--set`, or upgrade with your own
values file instead of `--reuse-values`.

## Spec reference

```yaml
apiVersion: podtrace.io/v1alpha1
kind: TracerConfig
metadata:
  name: default
spec:
  image: ghcr.io/gma1k/podtrace:0.14.9 # x-release-please-version
  imagePullPolicy: IfNotPresent
  systemNamespace: podtrace-system
  maxConcurrentSessionsPerNode: 2
  btfMode: auto                # auto | host | file | embedded(deprecated)
  nodeSelector: {}
  tolerations: []
  fleetPriority: 0             # tie-break when fleets overlap

  agent:
    priorityClassName: system-node-critical
    eventBufferSize: 10000
    statusReportInterval: 30s
    resources:
      requests: { cpu: 100m, memory: 128Mi }
      limits:   { cpu: 1,    memory: 512Mi }

  session:
    ttlSecondsAfterFinished: 300
    activeDeadlineOffset: 90s
    backoffLimit: 0
    sidecarUploader: false
    resources:
      requests: { cpu: 100m, memory: 128Mi }
      limits:   { cpu: 1,    memory: 1Gi }
```

### Notable fields

- **`image`** — One container image serves all three runtime roles
  (operator, agent, CLI in session Jobs). Override at the chart level.
- **`btfMode`**:
  - `auto` (default): prefer `/sys/kernel/btf/vmlinux` when present,
    fall back to embedded stub types.
  - `host`: require `/sys/kernel/btf/vmlinux` (fails closed on minimal
    distros without BTF).
  - `file`: load BTF from a blob you supply through `btfSource`. See
    [Supplying BTF for a kernel without it](#supplying-btf-for-a-kernel-without-it).
  - `embedded`: **deprecated, and does nothing.** No BTF is shipped in the
    image, so the agent behaves exactly as for `auto`, and the admission
    webhook warns when you set it. Use `file`. It stays in the enum because
    removing a published enum value is a breaking change; it goes at the next
    stored-version cutover.
- **`btfSource`** — where `btfMode: file` reads the blob. Exactly one of
  `configMap` or `hostPath`. Ignored, and rejected at admission, in any other
  mode: a staged blob nothing loads reads as a configured feature.
- **`maxConcurrentSessionsPerNode`** — protects nodes from privileged
  Job pile-ups when many sessions land on the same node.
- **`fleetPriority`** — orders fleets that target the same node. Advisory:
  it decides what the `Conflict` condition reports, not which agent
  runs. See [Multiple TracerConfigs](#multiple-tracerconfigs).
- **`session.activeDeadlineOffset`** (default `90s`) — how long a session
  Job may run past its `duration` before Kubernetes kills it. The offset pays
  for pulling the image, loading the eBPF programs and writing the report;
  loading alone takes over ten seconds on an idle node and longer on a busy
  one. When starting the trace took so long that collecting for the whole
  `duration` would run past the deadline, the session collects for less and
  its report says so, rather than being killed with no report.
- **`session.sidecarUploader`** — opt-in native sidecar that re-uploads
  the report to `spec.reportRef`. Acts as a backup if the CLI crashes
  before its own self-upload completes. Requires Kubernetes 1.29+.
- **`redaction`** — PII scrubbing of event `Target`/`Details` before any
  exporter or report sink. `enabled` turns on the built-in rules
  (credentials, Bearer/Basic auth, JSON/YAML secrets, emails, card
  numbers); `redactDNSNames` additionally masks DNS query names;
  `customRules` adds regex rules (`name`, `pattern`, `replace`). Applies
  to both the agent DaemonSet and session Jobs. Off by default. See
  [language-runtime-adapters.md](language-runtime-adapters.md#pii-redaction).
- **`capture.headers`** — allowlist of up to 4 HTTP header names whose
  values are captured onto HTTP/2 and HTTP/3 events (appended to event
  `Details`, one `name: value` line each, values truncated at 64 bytes).
  Captured values pass through the redaction engine when `redaction` is
  enabled. See [http3.md](http3.md#header-allowlist-capture).

### Defaults: everything on unless you say otherwise

The continuous APM plane runs on any TracerConfig, however it was created.
These toggles default to `true` in the CRD schema, so the API server fills in
whatever you leave out, and `kubectl get tracerconfig -o yaml` shows the value
the agent runs with:

| Field | Turns on |
|---|---|
| `agent.metrics.enabled` | The continuous metrics plane |
| `agent.metrics.inspections.enabled` | Continuous inspections (only while the plane is on) |
| `agent.metrics.inspections.alerts` | Raising an activated issue as an alert |
| `agent.metrics.kernelAggregation` | Folding observations in a BPF map |
| `agent.metrics.filesystem` | Regular-file operations in the plane (needs `kernelAggregation`) |
| `agent.metrics.nativeHistograms` | Native histograms on `/metrics` |
| `agent.continuousProfiling` | The always-on profile on `/profile` |
| `agent.sockOpsRTT` | Kernel smoothed RTT via `sock_ops` |
| `agent.dnsPacketCapture`, `agent.dnsFullAnswers`, `agent.usdt` | Packet DNS capture, full DNS answers, USDT probes |

Leaving out a whole block counts the same: a TracerConfig with no `agent` or
no `agent.metrics` gets every toggle above. To turn one off, write `false`:

```yaml
spec:
  agent:
    continuousProfiling: false
    metrics:
      enabled: false       # also stops inspections, which read the plane
```

The operator applies the same defaults itself when a field is still unset, for
example on an object stored before this schema, so what an agent runs never
depends on which CRD version is installed.

### The TracerConfig the operator creates

With no TracerConfig in the cluster, as on an OLM install, the operator creates
`default` itself, annotated `podtrace.io/bootstrap-source: operator`. It then
keeps the fields it wrote current on every start: `image`, `tolerations`,
`agent.resources`, `session.resources` and `agent.metrics.excludeNamespaces`.
It only updates a field it still owns in `metadata.managedFields`; editing a
field with `kubectl` makes it yours, and the operator leaves it alone. The
annotation `podtrace.io/bootstrap-fields` lists what the operator has written,
so a field you deleted is not put back.

## Status reference

```yaml
status:
  desiredAgents: 3        # node count the DaemonSet targets
  readyAgents: 3          # agents currently passing readiness probe
  activeSessions: 1       # session Jobs currently Running
  matchedNodes: 3         # nodes this fleet's constraints select
  contestedNodes: 0       # of those, how many another fleet also selects
  conditions:
    - type: Reconciled
      status: "True"
      reason: Reconciled
    - type: Degraded
      status: "False"
    - type: Conflict
      status: "False"
      reason: ExclusiveNodes
  observedGeneration: 1
```

`activeSessions` lags `kubectl get jobs` by one reconcile tick — it's
read off Job status during the TracerConfig reconcile, not via a Job
informer.

`contestedNodes` > 0 means another fleet claims some of the same nodes
and their events are counted twice; see
[Overlapping fleets](#overlapping-fleets). `Conflict=Unknown` with
reason `NodesUnreadable` means the operator cannot list Nodes, so
overlap is simply unknown — everything else still reconciles.

## Common operations

```bash
# Inspect
kubectl get tracerconfig default -o yaml

# Bump event buffer size (full chart upgrade)
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values --set agent.eventBufferSize=50000

# Restrict agents to a subset of nodes
kubectl label node my-trace-node podtrace.io/enabled=true
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values --set 'agent.nodeSelector.podtrace\.io/enabled=true'

# Cap concurrent diagnose sessions per node
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values --set session.maxConcurrentSessionsPerNode=4
```

## Multiple TracerConfigs

A cluster can run several TracerConfigs. Each owns a separate agent
fleet, so different node pools can run different images, resource
envelopes, or capture and redaction policies.

**Fleets must select disjoint node sets.** A node covered by two fleets
runs two agents, both attach their eBPF programs, and every event on
that node is exported twice — once per fleet.

### Object names

Each fleet's objects are suffixed with its TracerConfig name. The config
named `default` keeps the unsuffixed legacy names, so upgrading a
single-config cluster does not recreate anything:

| TracerConfig | DaemonSet / ServiceAccount / ClusterRole |
|---|---|
| `default` | `podtrace-agent` |
| `gpu-pool` | `podtrace-agent-gpu-pool` |

Because the name becomes the value of the `podtrace.io/tracer-config`
label on the DaemonSet's (immutable) pod selector, TracerConfig names
are limited to 63 characters.

### Example: two node pools

```yaml
apiVersion: podtrace.io/v1alpha1
kind: TracerConfig
metadata:
  name: general
spec:
  image: ghcr.io/gma1k/podtrace:0.14.9 # x-release-please-version
  nodeSelector:
    workload: general
---
apiVersion: podtrace.io/v1alpha1
kind: TracerConfig
metadata:
  name: regulated
spec:
  image: ghcr.io/gma1k/podtrace:0.14.9 # x-release-please-version
  nodeSelector:
    workload: regulated
  redaction:
    enabled: true
    redactDNSNames: true
```

The chart renders only one TracerConfig. Apply additional ones with
`kubectl apply`, or set `tracerConfig.create=false` and manage all of
them yourself.

Session Jobs follow the same fleets. A `PodTraceSession` spawns one Job
per node, and each Job takes the image, resources and redaction policy of
the fleet targeting *its* node — so a session whose pods span two pools
runs under each pool's own policy. Pin the whole session to one config
with `spec.tracerConfigRef`. See
[crd-podtracesession.md](crd-podtracesession.md#tracerconfig-resolution).

### Overlapping fleets

Overlap depends on how nodes are labelled, not on how the two specs
compare: `{pool: a}` and `{zone: eu-1}` both match a node carrying both
labels, and two fleets that are disjoint today start colliding the
moment someone relabels a node. So podtrace detects overlap
continuously rather than rejecting it once at admission.

**The operator reports overlap; it does not resolve it.** Both
DaemonSets keep running on a contested node. What you get is:

- `status.matchedNodes` and `status.contestedNodes` on each TracerConfig
- a `Conflict` condition naming the contested nodes and the rival config
- `podtrace_operator_tracerconfig_contested_nodes`, and
  `count by (node) (podtrace_agent_info) > 1` from the agents

```console
$ kubectl get tracerconfig
NAME        DESIRED   READY   SESSIONS   AGE
general     3         3       0          5m
regulated   2         2       0          5m

$ kubectl describe tracerconfig regulated | grep -A3 Conflict
  Type:     Conflict
  Status:   True
  Reason:   OverlappingNodes
  Message:  shares node(s) node-7 with TracerConfig general; this config
            has highest priority on 0 of them. …
```

`spec.fleetPriority` (higher wins; ties broken by the older
`creationTimestamp`, then by name) records which fleet *should* own a
contested node. It is advisory today — it decides what the Conflict
condition reports, nothing more.

Admission rejects only the collisions that hold regardless of node
labels: a second TracerConfig with no `nodeSelector` and no required
`nodeAffinity` (which would target every node), and a `nodeSelector`
identical to an existing config's. Anything subtler comes back as a
warning at apply time and as the `Conflict` condition afterwards.

### RBAC

Overlap detection reads Nodes, so the operator's ClusterRole includes
`nodes: get, list, watch`. It is read-only — podtrace never writes to a
Node. On an upgrade where the operator image is newer than its
ClusterRole, overlap detection reports `Conflict=Unknown` with reason
`NodesUnreadable` and everything else reconciles normally.

## Related

- [operator.md](operator.md) — operator architecture
- [installation.md](installation.md) — Helm install
- [crd-podtrace.md](crd-podtrace.md) — continuous tracing
- [crd-podtracesession.md](crd-podtracesession.md) — bounded diagnose

## Supplying BTF for a kernel without it

Almost nobody needs this. podtrace requires kernel **5.8+** (BPF ring
buffers), and essentially every distro kernel at or above that level ships
`CONFIG_DEBUG_INFO_BTF`. BTFHub, the archive that exists precisely to serve
BTF-less kernels, carries almost nothing above the 5.8 line: RHEL/CentOS
7 and 8, Ubuntu 16.04 and 18.04, Debian 9 and 10, SLES 12 and 15.3, Fedora
up to 31 and Amazon Linux are all below podtrace's floor already.

What is left is **custom and vendor-built kernels** at 5.8+ where whoever
built them left `CONFIG_DEBUG_INFO_BTF` off. If that is you, you built the
kernel, so you can produce its BTF.

### Check whether you need it at all

```bash
ls -l /sys/kernel/btf/vmlinux     # present: you need nothing here
podtrace diagnose-env             # reports btfVmlinux and btfFile
```

### Produce the blob

From a `vmlinux` with DWARF (the debug build of the kernel you are running):

```bash
pahole -J vmlinux                 # writes a .BTF section into vmlinux
```

That file works as-is, but it is megabytes. Minimise it against podtrace's
own BPF object, which drops every type podtrace never relocates against.
The object is compiled into the binary rather than shipped as a file, so
write it out first:

```bash
podtrace diagnose-env --dump-bpf-object ./podtrace.bpf.o
bpftool gen min_core_btf vmlinux vmlinux.btf ./podtrace.bpf.o
```

Measured against a 6.x kernel, that turns a **5.4MB** BTF into **2.7KB** —
podtrace relocates against very few kernel types. A ConfigMap caps at 1MiB,
so minimising is what makes the ConfigMap path usable at all.

**Regenerate the blob when you upgrade podtrace.** `min_core_btf` output is
specific to the BPF object it was generated against; a podtrace release that
relocates against a type your blob omits will fail to load on that node.
The `hostPath` route with a full unminimised BTF avoids that coupling.

### Hand it to the agent

ConfigMap (preferred, travels with the cluster, survives node replacement):

```bash
kubectl -n podtrace-system create configmap node-btf \
  --from-file=vmlinux.btf=./vmlinux.btf
```

```yaml
spec:
  btfMode: file
  btfSource:
    configMap:
      name: node-btf
      key: vmlinux.btf     # optional, this is the default
```

Or through Helm:

```bash
helm upgrade --reuse-values podtrace deploy/charts/podtrace \
  --set agent.btfMode=file \
  --set agent.btfSource.configMap.name=node-btf
```

hostPath, for a blob too large for a ConfigMap or already staged on the node:

```yaml
spec:
  btfMode: file
  btfSource:
      hostPath: /var/lib/podtrace/vmlinux.btf
```

The path is mounted as the file itself, not as its directory, so nothing
else beside it is exposed to the agent. It must exist on **every** node the
agent runs on, a node missing it leaves that agent's pod stuck in
`ContainerCreating`.

### The CLI needs it too

The agent DaemonSet and the session Jobs the operator renders both pick the
blob up from `btfSource`. The CLI does not: `podtrace <pod> --diagnose` spawns
its own privileged pod, and that pod loads its own BPF collection. It also runs
happily with no operator installed at all, so there is no TracerConfig for it
to read. Pass the node path instead:

```bash
podtrace -n shop checkout-7d9f --diagnose 30s \
  --btf-file /var/lib/podtrace/vmlinux.btf
```

The path is on the **node**, not on your workstation, and is mounted as the
file itself. Unnecessary on any node with `/sys/kernel/btf/vmlinux`, which is
nearly all of them.

### Confirm it took

```bash
kubectl describe tracerconfig default | grep -A2 Reconciled
```

The `Reconciled` condition names the blob it loaded, for example
`spec.btfMode=file, the agent loads BTF from ConfigMap node-btf key
vmlinux.btf`. A heterogeneous fleet needs one TracerConfig per kernel, with
`nodeSelector` narrowing each to its own nodes.
