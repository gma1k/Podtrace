# Compatibility Matrix

Where podtrace runs, what features depend on what, and which environments
are known not to work. Rules of thumb at the top, details and verification
commands below.

For installation steps, see [installation.md](installation.md).
For per-cloud specifics, jump to the [distro-specific notes](#distro-specific-notes).

## At a glance

| Requirement      | Minimum                | Recommended       |
|------------------|------------------------|-------------------|
| Linux kernel     | 5.8 (BPF ring buffer)  | 6.1+              |
| BTF              | Required on the running kernel | `/sys/kernel/btf/vmlinux` present |
| Architecture     | amd64, arm64           | Same              |
| Kubernetes       | 1.28                   | 1.32–1.36         |
| Cgroup driver    | systemd or cgroupfs    | systemd, v2       |
| Container runtime | containerd, CRI-O    | Same              |
| Privileges       | `CAP_BPF` + `CAP_PERFMON` (kernel 5.8+) or `CAP_SYS_ADMIN` (older) | Distinct caps, no full privileged |

## Kernel requirements

### Hard requirement: 5.8+

Podtrace uses BPF ring buffers (`BPF_MAP_TYPE_RINGBUF`), which were added
in kernel 5.8. There is no perf-buffer fallback today. On older kernels
the agent will fail to load.

Verify:

```bash
uname -r                       # 5.8 or higher
ls /sys/kernel/btf/vmlinux     # exists → BTF available
```

### If the node has no BTF

Rare above the 5.8 floor: essentially every distro kernel that clears it
ships `CONFIG_DEBUG_INFO_BTF`. BTFHub, the archive that exists to serve
BTF-less kernels, carries almost nothing above 5.8, RHEL/CentOS 7 and 8,
Ubuntu 16.04 and 18.04, Debian 9 and 10, SLES 12 and 15.3, Fedora up to 31
and Amazon Linux are all below podtrace's floor already.

What remains is custom and vendor-built kernels with the option left off.
For those, supply the BTF yourself with `btfMode: file` for the agent and
sessions, and `--btf-file` for the CLI, see
[crd-tracerconfig.md](crd-tracerconfig.md#supplying-btf-for-a-kernel-without-it).
(`btfMode: embedded` is deprecated and does nothing; podtrace ships no BTF
archive.)

### Building without bpftool

When `bpftool` is unavailable at build time there is no kernel BTF to
generate a header from, and the build falls back to the stub
[bpf/vmlinux.h](../bpf/vmlinux.h).

**Every probe still works.** The stub declares the kernel types the probes
walk — `task_struct`, `pid`, `upid`, `nsproxy`, `net`, `ns_common`,
`css_set`, `cgroup`, `kernfs_node`, `dentry`, `qstr`, `path`, `file`,
`renamedata`, `sock`, `sock_common`, `in6_addr`, `msghdr`, `iov_iter`,
`iovec` — under `preserve_access_index`. The layouts written there are
deliberately not the kernel's: clang emits a CO-RE relocation per field
access and libbpf rewrites every offset from the running kernel's own BTF
when the program loads, so only the field *names* have to match.

Two consequences worth knowing:

- **The running kernel still needs BTF.** The stub removes the need for
  BTF on the *build host*, not on the target. A kernel without
  `/sys/kernel/btf/vmlinux` cannot relocate, and the collection will not
  load.
- **Enum values are relocated too, not baked in.** `enum iter_type`, which
  selects how a socket payload is addressed, has been reordered across
  releases. It is read with `bpf_core_enum_value()` rather than taken from
  a header, so a binary built against one kernel does not misread payloads
  on another.

### Kernel features that are genuinely conditional

These are not build-time choices; they depend on the kernel the agent runs
on, and each is detected at load or probe time rather than compiled out:

| Feature | Requires |
|---|---|
| `vfs_rename` argument layout | Detected with `bpf_core_type_exists(struct renamedata)`; the signature changed at 6.3 |
| OOM victim `comm` | Detected with `bpf_core_field_exists(tp->__data_loc_comm)` |
| OOM victim cgroup | `bpf_task_from_pid` / `bpf_task_release` kfuncs |
| `bpf_loop` (traceparent scanning) | 5.17+ |

## Architecture support

Five `BPF_GOARCH` values are wired in the [Makefile](../Makefile):

| Arch     | `__TARGET_ARCH_*` | CI tested | Status      |
|----------|-------------------|-----------|-------------|
| amd64    | `x86`             | ✅        | First-class |
| arm64    | `arm64`           | ✅        | First-class |
| ppc64le  | `powerpc`         | ❌        | Best-effort |
| s390x    | `s390`            | ❌        | Best-effort |
| riscv64  | `riscv`           | ❌        | Best-effort |

CI builds amd64 (ubuntu-26.04) and arm64 (ubuntu-26.04-arm) on every
push, see [.github/workflows/ebpf-build.yml](../.github/workflows/ebpf-build.yml).
Other architectures may build but have no test coverage; report
breakage and we will look at it.

## Kubernetes versions

The chart [Chart.yaml](../deploy/charts/podtrace/Chart.yaml) declares
`kubeVersion: ">=1.28.0-0"`.

The Go client surfaces (`k8s.io/client-go v0.36.1`,
`sigs.k8s.io/controller-runtime v0.24.1`) realistically support
**Kubernetes 1.32–1.36**. Test against 1.36 in chainsaw e2e and
envtest; 1.28–1.31 remain within the chart's `kubeVersion` floor but
are outside the client-go test matrix.

Verify your cluster version with `kubectl version --short`.

## Cgroup support

Both cgroup v1 and v2 are supported. Both `systemd` and `cgroupfs` drivers
work. Cgroup filtering happens in userspace using `/proc/<pid>/cgroup`,
not via a kernel-side cgroup ID, so the chart sets:

- `PODTRACE_CGROUP_BASE` to the host cgroup root
- `PODTRACE_PROC_BASE` to the host `/proc` (so the agent sees host PIDs,
  not its own container's `/proc`)

See [installation.md#environment-variables](installation.md#environment-variables) for
the full env reference.

## Container runtime

Tested with **containerd** and **CRI-O**. Docker shim (legacy) works on
EKS AL2 with `/run/dockershim.sock`. Auto-detection of the CRI socket
covers the common paths (`/run/containerd/containerd.sock`,
`/var/run/containerd/containerd.sock`, `/run/crio/crio.sock`).

## Privileges

The agent DaemonSet requires:

- `CAP_BPF` (load BPF programs, kernel 5.8+)
- `CAP_PERFMON` (read performance/tracing data)
- `CAP_SYS_ADMIN` is **not** required on 5.8+; it is an older fallback
  some hardened kernels demand.
- `hostPID: true`, hostNetwork on the agent only (so probes see host
  PIDs/sockets)
- Read-only host mounts: `/sys`, `/proc`, host cgroup root

The operator Deployment runs unprivileged as user `65532` (distroless
nonroot). Per-session Jobs inherit the agent capability set on the node
they target.

See [deploy/charts/podtrace/templates/](../deploy/charts/podtrace/templates/)
for the exact `securityContext`.

## Distro-specific notes

Five managed/distro-specific guides are maintained separately. Each one
covers BTF availability, cgroup mode, kernel version, container runtime,
and any platform quirks (AppArmor, SELinux, Pod Security Standards, etc).

| Distro                   | Status   | Notes |
|--------------------------|----------|-------|
| [Azure AKS](aks.md)                | ✅ Supported | Ubuntu 22.04 / Azure Linux, BTF on by default since 1.25 |
| [AWS EKS](eks.md)                  | ✅ Supported (on EC2) | AL2, AL2023, Bottlerocket, Ubuntu node groups |
| [AWS EKS Fargate](eks.md#fargate)  | ❌ Not supported | No BPF / kprobe access on Fargate |
| [Google GKE Standard](gke.md)      | ✅ Supported | COS or Ubuntu, kernel 5.8+ |
| [Google GKE Autopilot](gke.md#autopilot) | ❌ Not supported | No BPF kprobe access |
| [GKE Sandbox (gVisor)](gke.md#sandbox) | ❌ Not supported | gVisor exposes a different syscall surface |
| [OpenShift / OKD](openshift.md)    | ⚠️ Partial | RHEL 9 (5.14+) ✅; RHEL 8 (4.18) ❌ — below 5.8 ring-buffer requirement |
| [Talos Linux](talos.md)            | ✅ Supported | v1.3+ kernel 6.1+, cgroupfs driver |

If you are on a distro not listed and ring-buffer + BTF are available,
podtrace will most likely work. We accept new distro guides as PRs to
this directory.

## Verifying your environment

```bash
# 1. Kernel version (need 5.8+)
uname -r

# 2. BTF available?
ls -l /sys/kernel/btf/vmlinux

# 3. Required capabilities reachable?
capsh --print | grep -E "cap_bpf|cap_perfmon|cap_sys_admin|cap_sys_ptrace"

# 4. Cgroup version
stat -fc %T /sys/fs/cgroup        # cgroup2fs → v2; tmpfs → v1

# 5. Container runtime socket
ls /run/containerd/containerd.sock /run/crio/crio.sock 2>/dev/null

# 6. Architecture
uname -m
```

If everything above checks out and podtrace still fails to start, see
the troubleshooting section in
[installation.md#troubleshooting](installation.md#troubleshooting).

## Related

- [STABILITY.md](../STABILITY.md) — versioning policy and `v1alpha1`
  guarantees.
- [installation.md](installation.md) — install steps and troubleshooting.
- [ebpf-internals.md](ebpf-internals.md) — how the BPF programs load and
  attach.
- [development.md](development.md) — building from source.