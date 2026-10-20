# Installation

## Install

Four install paths, ordered by friction:

1. **Quickstart manifest** — single `kubectl apply`, working demo, end-to-end. Best for evaluating podtrace.
2. **OperatorHub.io / OLM** — one-click install on OpenShift or any OLM-managed cluster.
3. **Helm chart** — production install with custom values,
   validating webhook, custom RBAC. Best for ongoing operation.
4. **Building from source** — for contributors or air-gapped
   clusters.

### Quickstart manifest (one-shot demo)

Two pre-rendered manifests are attached to every GitHub Release: `quickstart.yaml` (namespace + CRDs + operator) and `quickstart-demo.yaml` (a sample nginx workload + a `PodTraceSession`). They are separate files because kubectl cannot apply custom resources in the same invocation that installs their CRDs. Apply them in order:

```bash
kubectl apply -f https://github.com/gma1k/podtrace/releases/latest/download/quickstart.yaml
kubectl apply -f https://github.com/gma1k/podtrace/releases/latest/download/quickstart-demo.yaml
```

What it deploys, in order:

| Resource | Namespace | Purpose |
|---|---|---|
| 6 CRDs (`podtrace.io`) | cluster | Operator's API surface |
| `podtrace-system` Namespace + RBAC + Deployment | `podtrace-system` | Operator runtime |
| `default` `TracerConfig` | cluster | Governs the agent DaemonSet |
| `podtrace-demo` Namespace + nginx Deployment | `podtrace-demo` | Sample workload |
| `demo-otlp` `ExporterConfig` | `podtrace-demo` | No-op OTLP target (no network calls) |
| `demo-trace` `PodTraceSession` | `podtrace-demo` | 30s diagnose against nginx |

```bash
# Session should reach state: Completed
kubectl get podtracesession demo-trace -n podtrace-demo

# Inspect status.summary (aggregated event counts)
kubectl get podtracesession demo-trace -n podtrace-demo \
  -o jsonpath='{.status.summary}{"\n"}'

# Read the full human-readable report
kubectl get cm nginx-trace-report -n podtrace-demo \
  -o go-template='{{range $k,$v := .data}}{{$v}}{{end}}'
```

The demo session has `ttlSecondsAfterFinished: 600`, so it auto-deletes itself 10 minutes after completing. To tear down everything immediately:

```bash
kubectl delete ns podtrace-system podtrace-demo
kubectl delete crd -l app.kubernetes.io/name=podtrace
```

### OperatorHub.io / OLM

On OpenShift or any cluster running [Operator Lifecycle Manager (OLM)](https://olm.operatorframework.io/),
Podtrace is published in the [OperatorHub.io community catalog](https://operatorhub.io/operator/podtrace).
This is the most ergonomic install path for OpenShift admins, one
click in the Console UI, OLM handles the operator lifecycle (install,
upgrade, RBAC).

**OpenShift Console:** Operators → OperatorHub → search "podtrace" → Install.

**CLI install via Subscription manifest**:

```bash
kubectl apply -f - <<EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: podtrace
  namespace: operators
spec:
  channel: stable
  name: podtrace
  source: operatorhubio-catalog
  sourceNamespace: olm
EOF

# Wait for the InstallPlan to apply
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded \
  csv -n operators -l operators.coreos.com/podtrace.operators \
  --timeout=5m
```

To uninstall:

```bash
kubectl delete subscription podtrace -n operators
kubectl delete csv -n operators -l operators.coreos.com/podtrace.operators
kubectl delete crd -l app.kubernetes.io/name=podtrace
```

### Helm chart

For production deployments, custom values, validating webhook, multi-tenant agent config, custom RBAC — install via the published OCI Helm chart in GHCR instead:

```bash
helm install podtrace oci://ghcr.io/gma1k/charts/podtrace --version 0.1.0 \
  --namespace podtrace-system --create-namespace \
  --set operator.enabled=true
```

The chart installs CRDs, namespace, operator, agent DaemonSet, and a
default `TracerConfig`. See [operator.md](operator.md) for what each
piece does, and the [chart values reference](../deploy/charts/podtrace/values.yaml)
for available overrides.

### Upgrading an existing install

The continuous APM plane is **on by default** from this release: workload
metrics, inspections, continuous profiling, kernel-side aggregation and kernel
smoothed RTT (`sock_ops`), plus the agents' `PodMonitor` and
`prometheus.io/scrape` annotations. A fresh `helm install` gets all of it with
no further values.

An existing release does not pick the new defaults up on its own if you
upgrade with `--reuse-values`, which reuses the values the release was
installed with, where these were off. Either reset to the new defaults while
keeping your own overrides:

```bash
helm upgrade podtrace ghcr.io/gma1k/charts/podtrace \
  --namespace podtrace-system --reset-then-reuse-values
```

or set the flags explicitly:

```bash
helm upgrade podtrace ghcr.io/gma1k/charts/podtrace \
  --namespace podtrace-system --reuse-values \
  --set agent.metrics.enabled=true \
  --set agent.metrics.inspections.enabled=true \
  --set agent.metrics.kernelAggregation=true \
  --set agent.continuousProfiling=true \
  --set agent.sockOpsRTT=true \
  --set metrics.podMonitor.enabled=true
```

What to expect after the upgrade:

- **Agent CPU.** The plane costs roughly 0.12 cores per node with the default
  event categories; see [continuous-metrics.md](continuous-metrics.md#cost-measured).
  Keep an eye on the agent's CPU against `agent.resources.limits.cpu`.
- **Kubernetes Events.** Inspections write an Event on the pod of a workload
  that raises an issue. They start no session and send no webhook unless you
  configure a `PodTraceSchedule` or `agent.alerting`.
- **Exemplars.** With kernel aggregation on, histogram exemplars (the trace id
  linking a bucket to a trace) appear only while a `PodTrace` keeps the ring
  buffer open.
- **`sock_ops` RTT** needs kernel 5.10+ and cgroup v2. Where it cannot attach,
  `network_rtt_seconds` is absent and `net.rtt_spike_rate` falls back to
  socket-call latency, and says so in its message.

To keep podtrace an on-demand tracer only, upgrade with
`--set agent.metrics.enabled=false --set agent.continuousProfiling=false --set agent.sockOpsRTT=false`.

#### TracerConfigs not managed by the chart

On OLM, and for any TracerConfig you wrote yourself, the agent toggles now
default to **on in the CRD schema**, so a field you left out means on rather
than off. After the upgrade, a TracerConfig that never mentioned
`agent.metrics` runs the full plane. To keep one off, say so:

```bash
kubectl patch tracerconfig <name> --type=merge -p \
  '{"spec":{"agent":{"continuousProfiling":false,"sockOpsRTT":false,"metrics":{"enabled":false}}}}'
```

On OLM, the TracerConfig the operator created itself is also kept current:
each operator start brings its image, tolerations, resources and the
namespaces the metrics plane skips up to that operator's defaults, so an
operator upgrade moves the agents along with it and the control-plane node
gains an agent. A field you have edited, or deleted, is left as you left it.

Chart-managed TracerConfigs are unaffected: the chart writes every toggle
explicitly, on or off. See
[crd-tracerconfig.md](crd-tracerconfig.md#defaults-everything-on-unless-you-say-otherwise).

### Verifying signatures and provenance

Every released image, chart, CLI tarball, and quickstart manifest is signed
via cosign keyless OIDC and carries SLSA v1.0 Build L2 provenance, both
recorded in the public Rekor transparency log. Verify before running:

```bash
gh attestation verify oci://ghcr.io/gma1k/podtrace:latest \
  --repo gma1k/podtrace \
  --signer-workflow gma1k/podtrace/.github/workflows/release.yml
```

That checks in one step that the image was built by the release workflow in
this repository. To check the cosign signature specifically:

```bash
# x-release-please-version
cosign verify ghcr.io/gma1k/podtrace:0.11.0 \
  --certificate-identity-regexp '^https://github\.com/gma1k/podtrace/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The image also ships an SBOM:

```bash
# x-release-please-version
cosign download attestation ghcr.io/gma1k/podtrace:0.11.0 \
  --predicate-type https://spdx.dev/Document | jq .
```

Both quickstart manifests are attested. Download the bundle from the release
and verify offline:

```bash
cd $(mktemp -d)
for f in quickstart.yaml quickstart-demo.yaml quickstart.sigstore.json; do
  curl -fsSLO "https://github.com/gma1k/podtrace/releases/latest/download/$f"
done

gh attestation verify quickstart.yaml \
  --bundle quickstart.sigstore.json \
  --repo gma1k/podtrace \
  --signer-workflow gma1k/podtrace/.github/workflows/release.yml
```

The `.sha256` companions are still published for scripts that consume them,
but note that a checksum served from the same release page as the file it
describes proves nothing about origin — use the attestation for that.

To enforce provenance at admission time rather than checking it by hand, see
[supply-chain.md](supply-chain.md) for a Kyverno policy, the full artifact
coverage table, and what the L2 claim does and does not cover.

### Install the CLI

For workstation use (interactive `podtrace` invocations from a laptop
or CI runner), separate from the cluster operator install above. Each
release ships signed tarballs for linux + macOS × amd64 + arm64:

```bash
# Linux amd64
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_linux_amd64.tar.gz \
  | sudo tar xz -C /usr/local/bin podtrace

# Linux arm64
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_linux_arm64.tar.gz \
  | sudo tar xz -C /usr/local/bin podtrace

# macOS Apple Silicon
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_darwin_arm64.tar.gz \
  | sudo tar xz -C /usr/local/bin podtrace

# macOS Intel
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_darwin_amd64.tar.gz \
  | sudo tar xz -C /usr/local/bin podtrace
```

`/usr/local/bin` is root-owned on most systems, so the tar extract needs
`sudo`. The binary already has the executable bit set inside the tarball
(preserved from `go build`), so no `chmod +x` is required.

To install without sudo, extract to a user-writable directory on `$PATH`:

```bash
mkdir -p ~/.local/bin
curl -fsSL https://github.com/gma1k/podtrace/releases/latest/download/podtrace_linux_amd64.tar.gz \
  | tar xz -C ~/.local/bin podtrace
# ensure ~/.local/bin is on $PATH (most modern shells include it by default)
```

`podtrace --version` should report the tag you installed.

#### Install via krew

If you have [krew](https://krew.sigs.k8s.io/) installed, the simplest
path is `kubectl krew install`:

```bash
kubectl krew install podtrace
kubectl podtrace --version
kubectl krew upgrade podtrace
```

> **How `kubectl podtrace` reaches the kernel**
>
> - **Real clusters** (Talos, EKS, GKE, AKS, OpenShift, bare-metal): the CLI
>   spawns a short-lived privileged pod on the target pod's node and runs
>   eBPF there. Zero workstation caps needed; one-time namespace
>   PodSecurity label required. See [cli-architecture.md](cli-architecture.md).
>
> - **kind / minikube / docker-desktop**: the workstation **is** the kubelet
>   host (nodes are docker containers sharing the host kernel), so the
>   spawn step is wasted overhead. Add `--local`:
>   ```bash
>   kubectl podtrace --local -n my-app api-pod
>   ```
>   Skip-the-spawn means eBPF loads on your workstation directly, no
>   privileged pod, no PSA label, no image to load. Same UX as pre-PR
>   podtrace on a single-node setup. Needs `CAP_BPF` / `CAP_SYS_ADMIN`
>   (and the rest of the set below) on the local binary — the release tarball ships these via setcap, and
>   `make build` + `./scripts/setup-capabilities.sh` does the same for
>   source builds.

#### Verify the tarball

The tarballs are attested directly, so a single command establishes that the
one you downloaded was built by the release workflow in this repository:

```bash
cd $(mktemp -d)
curl -fsSLO https://github.com/gma1k/podtrace/releases/latest/download/podtrace_linux_amd64.tar.gz

gh attestation verify podtrace_linux_amd64.tar.gz \
  --repo gma1k/podtrace \
  --signer-workflow gma1k/podtrace/.github/workflows/release.yml
```

##### Alternative: cosign keyless + sha256sum

The release pipeline also signs `checksums.txt` via cosign keyless and
records the signing event in the [public Rekor transparency log](https://search.sigstore.dev/).
Trust chain: sigstore bundle → checksums file → tarball. This route takes two
steps because the signature covers the checksum file rather than the tarball,
but it needs only `cosign`, not `gh`.

```bash
cd $(mktemp -d)

# Pull checksums + sigstore bundle
for f in checksums.txt checksums.txt.sigstore.json; do
  curl -fsSLO https://github.com/gma1k/podtrace/releases/latest/download/$f
done

# Verify the signature was produced by a workflow in gma1k/podtrace
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/gma1k/podtrace/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# Verify the tarball matches the (now-trusted) checksum
curl -fsSLO https://github.com/gma1k/podtrace/releases/latest/download/podtrace_linux_amd64.tar.gz
sha256sum -c checksums.txt --ignore-missing
```

If the cosign verify step succeeds, the certificate's identity proves the
tarball was built by `release.yml` in the `gma1k/podtrace` repository, from a
release tag. A looser pattern such as `https://github.com/gma1k/podtrace/.+`
would also accept any other workflow or branch in the repository, the `test*`
tags the release workflow signs as prereleases, and repositories whose name
merely starts with `podtrace`.

### Building from source

If you need a custom build (development, air-gapped clusters, or
unsupported architectures), the rest of this document covers the
toolchain setup and build steps.

## Prerequisites

### System Requirements

- **Linux Kernel**: 5.8+ with BTF support
- **Go**: 1.24+
- **Kubernetes**: Access to a Kubernetes cluster
- **Build Tools**: `clang 18+` and `llc` (LLVM toolchain), **libbpf headers 0.8+** (e.g. `libbpf-dev` on Debian/Ubuntu)

### Check Kernel Support

```bash
# Check kernel version
uname -r

# Check for BTF support
ls /sys/kernel/btf/vmlinux
```

### Check Go Version

```bash
go version
```

If you need to upgrade Go:

```bash
wget -q https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```
### Check Clang Version

```bash
clang --version
```

The eBPF programs need clang 18 or newer. Some distros ship an older default (Ubuntu 22.04 ships clang 14). Install a newer one from [apt.llvm.org](https://apt.llvm.org/):

```bash
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 18
```

This installs a versioned binary, so `clang --version` still reports the
distro default. Check with `clang-18 --version`, and pass it to the build
with `make build CLANG=clang-18`.

### Check libbpf Headers

The eBPF programs use `bpf_loop()` and `barrier_var()`, which need libbpf
headers 0.8 or newer. Check that yours provide them:

```bash
grep -q bpf_loop /usr/include/bpf/bpf_helper_defs.h && \
grep -q barrier_var /usr/include/bpf/bpf_helpers.h && \
echo "libbpf headers OK"
```

If nothing is printed, your distro's `libbpf-dev` is too old (Ubuntu 22.04
ships 0.5.0). Install newer headers into your home directory and point the
build at them:

```bash
git clone --depth 1 https://github.com/libbpf/libbpf ~/libbpf
make -C ~/libbpf/src install_headers DESTDIR=$HOME/libbpf-hdr
make build LIBBPF_INCLUDE=$HOME/libbpf-hdr/usr/include
```
## Building from Source

### 1. Clone the Repository

```bash
git clone https://github.com/gma1k/podtrace.git
cd podtrace
```

### 2. Install Dependencies

**System packages (Debian/Ubuntu):**

```bash
sudo apt update
sudo apt install -y clang llvm build-essential libbpf-dev
```

**Go modules:**

```bash
make deps
```

This downloads Go modules and tidies dependencies.

### 3. Build

```bash
# Build eBPF program and Go binary
make build
```

This will:
- Compile the eBPF program (`bpf/podtrace.bpf.c`) to a per-arch object at
  `internal/ebpf/embedded/podtrace.<arch>.bpf.o` (e.g.
  `internal/ebpf/embedded/podtrace.amd64.bpf.o`)
- Build the Go binary to `bin/podtrace`, embedding the per-arch BPF object
  via the `embed_bpf` build tag

### 4. Set Capabilities (Optional)

To run without `sudo`, set the required capabilities:

```bash
# Build and set capabilities in one step
make build-setup

# Or manually
sudo ./scripts/setup-capabilities.sh
```

The script sets the same capabilities the agent and spawn pods run with:
- `CAP_BPF`: loading eBPF programs and maps (kernel 5.8+)
- `CAP_PERFMON`: perf events and tracing programs
- `CAP_SYS_ADMIN`: creating kprobes through the perf_kprobe PMU
- `CAP_NET_ADMIN`: attaching network programs
- `CAP_SYS_RESOURCE`: raising the locked-memory limit for BPF maps
- `CAP_SYS_PTRACE`: reading `/proc/<pid>/root`, `exe` and `maps` of container
  processes that do not run as root, without which their library uprobes
  (TLS, HTTP/2, database) attach to nothing

`cp` does not preserve file capabilities. For a copy elsewhere, such as
`~/.krew/bin/podtrace`, pass its path:

```bash
sudo ./scripts/setup-capabilities.sh ~/.krew/bin/podtrace
```

## Verification

Test the build:

```bash
./bin/podtrace --help
```

You should see usage information.

## Troubleshooting

### Build Errors

**Error: "bpf/bpf_helpers.h file not found" (or similar libbpf header)**
- Install libbpf headers: `sudo apt install libbpf-dev` (Debian/Ubuntu). The Makefile adds `/usr/include` so that `<bpf/bpf_helpers.h>` is found; you can override with `make LIBBPF_INCLUDE=/path/to/include` if your headers are elsewhere.


**Error: "clang 18+ required to compile the eBPF programs"**
- Your default `clang` is older than 18. See [Check Clang Version](#check-clang-version), then build with `make build CLANG=clang-18`.

**Error: "call to undeclared function 'bpf_loop'" or "'barrier_var'"**
- Your libbpf headers are older than 0.8. See [Check libbpf Headers](#check-libbpf-headers) and build with `make build LIBBPF_INCLUDE=$HOME/libbpf-hdr/usr/include`.

**Error: "failed to load eBPF program"**
- Ensure kernel version is 5.8+
- Check BTF support: `ls /sys/kernel/btf/vmlinux`
- Verify clang is installed: `clang --version` (or `clang-18 --version`)

**Error: "Go version too old"**
- Upgrade Go to 1.27+, or set `GOTOOLCHAIN=auto` so `go` downloads the
  exact toolchain (`go 1.27.2` per `go.mod`) on demand.
- The Makefile will show upgrade instructions

**Error: "permission denied" when attaching probes**
- Run with `sudo` or set capabilities
- Check capabilities: `getcap bin/podtrace`

### Runtime Errors

**Error: "failed to resolve pod"**
- Ensure `kubectl` is configured correctly
- Check Kubernetes API access
- Verify pod name and namespace are correct

**Error: "cgroup path not found"**
- Ensure the pod is running
- Check container runtime (Docker, containerd, CRI-O)
- Verify cgroup v2 support
- **Kubelet with `--cgroup-driver=systemd` (e.g. Ubuntu/Debian):** Podtrace automatically looks for container cgroups under both the default cgroup root and `/sys/fs/cgroup/systemd/`. No configuration is required. If you use a custom cgroup root via `PODTRACE_CGROUP_BASE`, ensure it is the host’s cgroup root (e.g. when running in a DaemonSet, mount the host’s `/sys/fs/cgroup` and set `PODTRACE_CGROUP_BASE` to that mount).

**Error: "DNS tracking unavailable"**
- This is a warning, not an error
- DNS tracking requires libc to be found
- The tool will work without DNS tracking

**File Path Resolution Issues:**
- If paths show as `ino:DEV/INO` instead of actual paths, this means inode extraction returned 0
- This can happen if using the placeholder `vmlinux.h` instead of a full version generated from BTF
- To enable full path resolution, generate a complete `vmlinux.h`:
  ```bash
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
  make build
  ```
- Path tracking still works via `open()` events even without inode extraction
- **Note:** The repository includes a minimal placeholder `vmlinux.h` for basic compilation. For full CO-RE support, generate it from BTF as shown above.

## Running in Kubernetes

### As a DaemonSet (recommended)

When Podtrace runs **inside a container** (DaemonSet or Job), it must see the **host’s** cgroup tree, process tree, and (for CRI-based resolution) the container runtime socket. Otherwise you get “no events collected” because:

1. **Cgroup resolution** uses `PODTRACE_CGROUP_BASE` (default `/sys/fs/cgroup`). In a container that is the **container’s** cgroup, not the target pod’s, so the target pod’s cgroup path does not exist and resolution can fail or be wrong.
2. **Event filtering** either uses a kernel cgroup ID (derived from the cgroup path) or a userspace check that reads `/proc/<pid>/cgroup` via `PODTRACE_PROC_BASE`. In a container, default `/proc` is the **container’s** `/proc`; PIDs from the target pod are not visible there, so every event is filtered out and no events are collected.
3. **CRI resolution** (containerd/crio) looks for sockets under `/run/containerd/containerd.sock` etc.; those exist on the host, not in the container, unless you mount and set `PODTRACE_CRI_ENDPOINT`.

Use the following pattern so the DaemonSet pod sees the host’s cgroups, proc, and (optionally) CRI socket, and point Podtrace at them with environment variables:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: podtrace
spec:
  selector:
    matchLabels:
      app: podtrace
  template:
    metadata:
      labels:
        app: podtrace
    spec:
      hostPID: true          # optional but recommended so PIDs match host
      hostNetwork: false     # set true only if you need it
      containers:
      - name: podtrace
        image: your-registry/podtrace:latest
        command: ["/bin/sh", "-c"]
        args:
        - |
          # Example: trace a specific pod for 30s then exit
          ./podtrace -n default my-app-pod --diagnose 30s
          # Or keep running and trace interactively (depends on your entrypoint)
          exec ./podtrace -n default my-app-pod
        env:
        # Point at host mount paths so resolution and filtering see the target pod
        - name: PODTRACE_CGROUP_BASE
          value: /host/sys/fs/cgroup
        - name: PODTRACE_PROC_BASE
          value: /host/proc
        # If you use CRI for pod→cgroup resolution, mount runtime socket and set:
        # - name: PODTRACE_CRI_ENDPOINT
        #   value: unix:///host/run/containerd/containerd.sock
        securityContext:
          capabilities:
            add:
            - SYS_ADMIN
            - BPF
          privileged: false
        volumeMounts:
        - name: host-cgroup
          mountPath: /host/sys/fs/cgroup
          readOnly: true
        - name: host-proc
          mountPath: /host/proc
          readOnly: true
        # Optional: for CRI resolution (containerd example)
        # - name: host-run
        #   mountPath: /host/run
        #   readOnly: true
      volumes:
      - name: host-cgroup
        hostPath:
          path: /sys/fs/cgroup
          type: Directory
      - name: host-proc
        hostPath:
          path: /proc
          type: Directory
      # - name: host-run
      #   hostPath:
      #     path: /run
      #     type: Directory
```

- **PODTRACE_CGROUP_BASE**: Must be the **host** cgroup root (e.g. `/host/sys/fs/cgroup`). Required so that pod→cgroup resolution finds the target pod’s cgroup and (on cgroup v2) so the tracer can set the in-kernel cgroup filter.
- **PODTRACE_PROC_BASE**: Must be the **host** `/proc` (e.g. `/host/proc`). Required for userspace cgroup filtering (cgroup v1 or when kernel cgroup ID is not used) so that `/proc/<pid>/cgroup` exists for the target pod’s PIDs.
- **PODTRACE_CRI_ENDPOINT**: Set to the path where you mount the host’s runtime socket (e.g. `unix:///host/run/containerd/containerd.sock`) if you want CRI-based resolution. Otherwise resolution falls back to scanning the host cgroup and proc (which only works if `PODTRACE_CGROUP_BASE` and `PODTRACE_PROC_BASE` point at the host).

### As a Pod (simple example)

You can also run Podtrace as a single Pod with the same host mounts and env vars as above:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: podtrace
spec:
  containers:
  - name: podtrace
    image: your-registry/podtrace:latest
    env:
    - name: PODTRACE_CGROUP_BASE
      value: /host/sys/fs/cgroup
    - name: PODTRACE_PROC_BASE
      value: /host/proc
    securityContext:
      capabilities:
        add:
        - SYS_ADMIN
        - BPF
    volumeMounts:
    - name: host-cgroup
      mountPath: /host/sys/fs/cgroup
      readOnly: true
    - name: host-proc
      mountPath: /host/proc
      readOnly: true
  volumes:
  - name: host-cgroup
    hostPath:
      path: /sys/fs/cgroup
      type: Directory
  - name: host-proc
    hostPath:
      path: /proc
      type: Directory
```

### Cgroup driver (systemd vs cgroupfs)

Podtrace works with both kubelet cgroup drivers:

- **`--cgroup-driver=cgroupfs`**: Container cgroups are under the default hierarchy (e.g. `/sys/fs/cgroup/kubepods.slice/...`).
- **`--cgroup-driver=systemd`** (common on Ubuntu/Debian): Container cgroups are under the systemd hierarchy (e.g. `/sys/fs/cgroup/systemd/kubepods.slice/...`).

Podtrace tries both the default cgroup root and `/sys/fs/cgroup/systemd` when resolving pod cgroup paths, so no extra configuration is needed for systemd-driven nodes. If your node uses a different layout, set `PODTRACE_CGROUP_BASE` to the host’s cgroup root (and, when running in a container, mount that path into the pod).

### Required Permissions

- **Host cgroup and proc** mounted and `PODTRACE_CGROUP_BASE` / `PODTRACE_PROC_BASE` set (see above); otherwise you get no events when running in a container.
- Kubernetes API access (for pod resolution).
- eBPF capabilities: `SYS_ADMIN`, `BPF`.

## Operator install via Helm

For the CRD-driven workflows (continuous `PodTrace`, bounded
`PodTraceSession`), install the operator alongside the binary. The
chart ships under `deploy/charts/podtrace/`.

### Quick install

For a public release, prefer the OCI chart (no clone needed):

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
  --set image.tag=<version>
```

This single command:

- Renders all six CRDs (`TracerConfig`, `PodTrace`, `PodTraceSession`, `PodTraceSchedule`, `ApplicationTrace`, `ExporterConfig`).
- Creates `podtrace-system` with PSA `enforce: privileged` (the agent DaemonSet and session Jobs need this; user namespaces stay restricted).
- Deploys the operator (unprivileged, single replica with leader election).
- Installs operator ClusterRole + agent RBAC (cluster-scoped ClusterRole + namespaced Role for bundle reads in `podtrace-system`).
- Renders a `default` `TracerConfig`, which the operator picks up and uses to roll out the `podtrace-agent` DaemonSet on every node.

### Verify

```bash
kubectl -n podtrace-system get deploy,ds,pods
kubectl get tracerconfig default
kubectl -n podtrace-system get pods -l podtrace.io/component=agent -o wide
```

You should see the operator Deployment Ready, the DaemonSet with one
pod per node, and `tracerconfig/default` present.

### Common overrides

```bash
# Restrict the agent to nodes labeled podtrace.io/enabled=true
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values \
  --set 'agent.nodeSelector.podtrace\.io/enabled=true'

# Bump per-agent event buffer
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values --set agent.eventBufferSize=50000

# Enable Prometheus monitoring (no-op without prometheus-operator)
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.podMonitor.enabled=true

# Disable the chart-rendered TracerConfig (you author your own)
helm upgrade podtrace deploy/charts/podtrace \
  --reuse-values --set tracerConfig.create=false
```

### Webhook TLS

Validating webhooks require TLS. The chart's default
(`webhook.certSource=cert-manager`) renders a `Certificate` that
issues serving certs and annotates the `ValidatingWebhookConfiguration`
with `cert-manager.io/inject-ca-from`. Requires cert-manager already
installed.

For air-gapped clusters without cert-manager, switch to
`webhook.certSource=self-signed` and supply `webhook.caBundle` /
`webhook.tls` directly.

### kind quick start

On a kind cluster, mark the test image as locally loaded so kubelet
doesn't try to pull from a registry:

```bash
make docker-build IMAGE_TAG=dev
kind load docker-image ghcr.io/gma1k/podtrace:dev

helm install podtrace deploy/charts/podtrace \
  --namespace podtrace-system \
  --create-namespace \
  --set operator.enabled=true \
  --set image.repository=ghcr.io/gma1k/podtrace \
  --set image.tag=dev \
  --set image.pullPolicy=Never
```

See [operator.md](operator.md) for the architectural picture and
[crd-podtracesession.md](crd-podtracesession.md) for an end-to-end
trace example after install.

### Uninstall

```bash
helm uninstall podtrace --namespace podtrace-system
```

The chart applies the `TracerConfig` from a hook Job rather than as a
tracked release resource, so Helm does not remove it on its own — and
that object owns the agent DaemonSet. Left in place it would keep a
privileged, `CAP_SYS_ADMIN` pod running on every node with no operator
left to reconcile or stop it, so a `pre-delete` hook deletes it. The
DaemonSet, its ServiceAccount and its ClusterRole go with it through
their owner references.

To keep the agents running across an uninstall — reinstalling the chart
without interrupting capture, or managing the `TracerConfig` outside the
release — opt out:

```bash
helm uninstall podtrace --namespace podtrace-system \
  --set tracerConfig.retainOnUninstall=true
```

Then remove them by hand when you are done:

```bash
kubectl delete tracerconfig default
```

Two things Helm never removes, by design:

- **CRDs**, and with them every `PodTrace`, `PodTraceSession`,
  `ExporterConfig` and report object in the cluster. Delete them with
  `kubectl delete crd -l app.kubernetes.io/name=podtrace` only when you
  intend to lose that data.
- **The namespace**, if the chart created it.

OLM and raw-`kubectl` installs do not run Helm hooks. On those paths the
operator self-bootstraps a `TracerConfig`, so delete it yourself when
removing podtrace.
