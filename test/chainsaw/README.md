# Chainsaw e2e suite

End-to-end tests for the podtrace operator, expressed as
[Chainsaw](https://kyverno.github.io/chainsaw/) test cases. Each
sub-directory under [`tests/`](tests/) is one test scenario; each is
independently runnable.

## Prerequisites

- A running Kubernetes cluster reachable via the current `KUBECONFIG`
  (kind is the expected target).
- Image `ghcr.io/gma1k/podtrace:dev` loaded into the cluster
  (`make docker-build IMAGE_TAG=dev && kind load docker-image …`).
- The operator already installed via Helm with the chart-rendered
  defaults (the smoke script `test/e2e/kind-smoke.sh` does this).
- `chainsaw` CLI on `$PATH`. Install:

  ```bash
  make chainsaw-tools   # installs the version CI uses (CHAINSAW_VERSION in the Makefile)
  ```

## Running

```bash
# Run the full suite
make chainsaw

# Run one test
chainsaw test --test-dir test/chainsaw/tests/session-cr-lifecycle

# Pass-through args
chainsaw test --test-dir test/chainsaw/tests --include-test-regex 'session.*'
```

Each test starts from a clean state by creating its own namespace.
Timeouts are conservative — a slow kind cluster can take 90s+ for the
session lifecycle test to complete.

## Tests

| Test | What it covers |
|---|---|
| [continuous-cr-lifecycle](tests/continuous-cr-lifecycle) | `PodTrace` CR create / update filters / delete cleanly. Asserts bundle materialization in `podtrace-system`, finalizer cleanup. |
| [session-cr-lifecycle](tests/session-cr-lifecycle) | `PodTraceSession` runs a real eBPF diagnose, reaches `Completed`, populates `status.summary` and the `reportRef` ConfigMap. |
| [multi-cr-shared-agent](tests/multi-cr-shared-agent) | Two `PodTrace` CRs targeting overlapping pods produce one tracer process; both report Ready independently. |
| [agent-restart-resilience](tests/agent-restart-resilience) | Restart the agent DaemonSet; existing CRs stay healthy and per-node status reappears. **Control-plane only** — does not assert event continuity. |
| [exporter-credential-rotation](tests/exporter-credential-rotation) | Update an upstream `ExporterConfig` Secret; operator refreshes the bundle Secret in `podtrace-system`. **Control-plane only** — does not assert delivery to a real receiver. |
| [psa-enforcement](tests/psa-enforcement) | PSA `enforce: privileged` admits agent pods in `podtrace-system` and rejects equivalent pod specs in a `restricted` namespace. |
| [schedule-cr-lifecycle](tests/schedule-cr-lifecycle) | `PodTraceSchedule` fires a child `PodTraceSession` on a per-minute cron; verifies `status.lastScheduleTime`, ownership via `podtrace.io/schedule` label, and that `spec.suspend=true` halts further fires. |
| [resource-alert](tests/resource-alert) | **Serial.** Two CPU-burning pods under a 100m limit plus a mock webhook receiver. Enables agent alerting on the default `TracerConfig`, then asserts the per-cgroup resource monitors + in-kernel CPU sampler deliver a **distinct** `Resource Limit` alert for **each** pod's cgroup (multi-cgroup + per-cgroup dedup). |

## Notes

The production agent runs the real eBPF backend by default (`--backend
real`); `NoopBackend` is only the dev/kind-smoke mode (`--backend noop`),
which skips kernel attachment to exercise the control plane alone.

- **agent-restart-resilience** — control-plane scoped *by choice*: it
  asserts CRs stay Ready, per-node status reappears, bundles stay
  mounted, and finalizers don't trigger spurious cleanup across a
  DaemonSet restart. It deliberately does not compare pre/post event
  counts (that would make the test timing-sensitive), not because the
  agent can't trace.
- **exporter-credential-rotation** — without a mock OTLP receiver it
  asserts the operator's refresh path (upstream Secret edit → bundle
  Secret in `podtrace-system` carries the new credential), not delivery
  to a receiver.

Resource-limit **alerting** is delivered by the continuous agent path,
where the per-cgroup `ResourceMonitor` runs; `resource-alert` exercises
it end-to-end through a webhook receiver. One-shot `PodTraceSession`
diagnostics capture resource *events* but do not run the continuous
monitor, so they do not deliver threshold alerts — that is intentional
(sessions are point-in-time; alerting is a steady-state concern).
