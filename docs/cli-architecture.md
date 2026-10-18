# CLI architecture: the node-spawn model

`kubectl podtrace` (and the standalone `podtrace` binary) doesn't load
eBPF on the workstation it's invoked from. It identifies the node
hosting each target pod and runs a short-lived privileged pod *on
that node*; eBPF is loaded inside the spawned pod against the host
namespaces it mounts.

## Why

eBPF code runs in the kernel of the machine where it's loaded. The
workstation's kernel has no visibility into a remote node's processes
or cgroups, so loading eBPF on the workstation can only observe the
workstation itself. The CLI used to assume the workstation was the
kubelet host; that worked on kind, minikube, and docker-desktop but
silently failed on any real cluster (Talos, GKE, EKS, AKS, OpenShift,
Fargate, anywhere the workstation isn't the node).

The spawn model fixes the structural mismatch: the kernel that loads
eBPF is the same kernel running the target pod.

## What the spawn looks like

```
                  workstation                          target node (kubelet host)
 ┌──────────────────────────────────┐      ┌─────────────────────────────────────────┐
 │ kubectl podtrace -n app api-pod  │      │                                         │
 │  │                               │      │  /sys/fs/cgroup ─┐                      │
 │  │ ResolveTargetNodes()          │ ──▶  │  /proc           ├─ mounted at /host/*  │
 │  │ → app/api-pod on worker-3     │      │  /run/containerd ┘  in spawned pod      │
 │  │                               │      │                                         │
 │  │ Create privileged Pod         │ ──▶  │  podtrace-cli-worker-3-abc12345         │
 │  │ on worker-3, hostPID, mounts  │      │   ├─ podtrace --pods app/api-pod ...    │
 │  │                               │      │   ├─ PODTRACE_NODE_LOCAL=1              │
 │  │ Attach to pod stdout/stderr   │ ◀──  │   ├─ PODTRACE_PROC_BASE=/host/proc      │
 │  │                               │      │   ├─ PODTRACE_CGROUP_BASE=...           │
 │  │ Print events to terminal      │      │   └─ loads eBPF, attaches to cgroup     │
 │  │                               │      │                                         │
 │  │ on exit: Delete spawn pod     │ ──▶  │  (gone)                                 │
 └──────────────────────────────────┘      └─────────────────────────────────────────┘
```

The spawned pod runs the **same** `podtrace` binary the user has on
their workstation, just inside the node's kernel. The
`PODTRACE_NODE_LOCAL=1` env var tells the child binary it's already
on the kubelet host and to skip the spawn step itself (no recursion).

## When the spawn is skipped

Three conditions short-circuit the spawn and run eBPF on the local
host instead:

1. `--local` flag set explicitly.
2. `PODTRACE_NODE_LOCAL=1` env var set (the child uses this).
3. The cluster is reached through the in-cluster ServiceAccount — the
   binary runs inside a Pod with no kubeconfig of its own, typical when the
   operator launches a session Job.

Like kubectl, the CLI prefers a kubeconfig: `--kubeconfig`, then the
`KUBECONFIG` path list, then `~/.kube/config`, and only when none of them
names a cluster, the in-cluster ServiceAccount. A CLI run from a CI or
debug pod with `KUBECONFIG` pointing at another cluster therefore traces
that cluster, spawning there as it would from a workstation. `--context`
picks a context from the same kubeconfig.

## Stopping a trace

The first Ctrl+C (or SIGTERM) stops a spawned trace the way it stops a
`--local` one: each spawn pod is deleted with a 30s grace period, so its
podtrace gets SIGTERM, prints its final report and Kubernetes Events
section, and the CLI keeps streaming until it exits, then exits 0. A
Ctrl+C before the spawn pod is streaming exits 130 with nothing to
report. A second Ctrl+C stops at once.

### Use `--local` for kind / minikube / docker-desktop

These setups run cluster nodes as docker containers on your workstation,
which means the workstation kernel **is** the cluster's kernel. The
spawn step exists to bridge a different-kernel gap that doesn't apply
here, so it's pure overhead — pod-create latency, an image pull,
PodSecurity labelling, RBAC bootstrap, all of it skippable.

```bash
# kind / minikube / docker-desktop — fastest, zero setup
./bin/podtrace --local -n my-app my-pod
```

`--local` needs the agent's capability set on the local binary: `CAP_BPF`,
`CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_RESOURCE` and
`CAP_SYS_PTRACE` (for uprobes in containers that do not run as root).
The release tarball ships these via setcap; for source builds,
`./scripts/build-and-setup.sh` runs setcap automatically as the last
step of `make build`. **`cp` does NOT preserve file capabilities** — if
you copy the binary somewhere else (like `~/.krew/bin/`), re-run
`sudo ./scripts/setup-capabilities.sh /path/to/copy` or just invoke the
original `./bin/podtrace` directly.

For all other clusters (Talos, EKS, GKE, AKS, OpenShift, bare-metal,
Fargate), do **not** use `--local` — the workstation kernel isn't the
node's, and eBPF on the workstation can't see the target pod's
syscalls. The default spawn behavior is the correct choice.

## RBAC

### What the workstation needs (your kubeconfig)

The user running `kubectl podtrace` needs to be able to:

```yaml
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create", "get", "delete", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/log", "pods/attach"]
  verbs: ["get", "create"]
```

Cluster-wide read on `pods` is required for target selection. `pods/attach` is
preferred (real Ctrl+C and stdin); the CLI falls back to `pods/log` (read-only)
when attach is denied and prints a degraded-mode warning. Any user with `view` +
`pod-exec` already has this — there is nothing to apply.

### What the spawn pod needs (zero, by default)

**The spawn pod runs as the namespace's default ServiceAccount and needs no
permissions.** The workstation pre-resolves each target pod's containerID and
hands it to the spawn pod via a hidden `--preresolved-pod` flag; the child
binary builds its `PodInfo` from that hand-off without making a single K8s API
call. This is what makes `kubectl podtrace -n ns pod` work out-of-the-box on a
fresh cluster.

The optional [deploy/cli-rbac/role.yaml](../deploy/cli-rbac/role.yaml) ServiceAccount + ClusterRole exists
only for enriched-events correlation (annotating traces with Kubernetes
`Event` objects). Without it, you lose the events sidebar but tracing itself
works perfectly.

## PodSecurity

The spawn pod is privileged: `hostPID=true`, capabilities `BPF`,
`SYS_ADMIN`, `PERFMON`, `SYS_RESOURCE`, `NET_ADMIN`, plus hostPath
mounts for `/sys/fs/bpf`, `/sys/kernel/btf`, `/proc`, `/sys/fs/cgroup`,
`/run/containerd`.

Namespaces that enforce `restricted` or `baseline` will reject the
spawn pod. The CLI surfaces this with an exact remediation command:

```bash
kubectl label ns/<spawn-ns> pod-security.kubernetes.io/enforce=privileged --overwrite
```

Or use `--spawn-namespace=<dedicated-ns>` to centralize the
admission requirement in one namespace.

## Reaping leaked pods

If the CLI crashes or its connection drops before the in-process
`defer Delete` runs, the spawn pod survives until its
`activeDeadlineSeconds` ceiling (default 1h) kicks in. To clean up
sooner, the next CLI invocation runs a reaper that lists pods
labelled `app.kubernetes.io/managed-by=podtrace-cli`,
`podtrace.io/owner-host=<hostname>`, older than 2h, and deletes
them. The owner-host filter ensures collaborators sharing a cluster
don't reap each other's pods.

Manual reaper:

```bash
kubectl delete pods -A -l app.kubernetes.io/managed-by=podtrace-cli
```

## Image source

The spawn pod runs the container image baked at link time:
`ghcr.io/gma1k/podtrace:<CLI version>`. Override precedence:

1. `--image <ref>` flag
2. `PODTRACE_IMAGE` env var
3. Linker default (`-X .../config.Image`, set by the Makefile)

Dev builds (CLI version like `dev` or `dev-<sha>`) have no published
image, so they fall back to `ghcr.io/gma1k/podtrace:latest` and emit
a startup warning telling the user to pin a real tag.

## Multi-node fan-out

When `--pods` / `--pod-selector` / `--all-in-namespace` resolves to
pods on multiple nodes, the CLI launches one spawn pod per node and
streams them concurrently. Output lines are prefixed with
`[<node-name>] ` when more than one node is in play, so collated
output is greppable per node.

`v1` snapshot semantics: the target set is resolved once at start.
If new pods matching the selector appear on a fresh node mid-run,
they're not picked up. To trace them, restart the CLI.
