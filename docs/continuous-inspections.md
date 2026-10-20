# Continuous inspections

The continuous metrics plane records what a workload is doing. Inspections are
the half that decides something is wrong.

Without them, an always-on APM still leaves the operator doing the work the
plane was supposed to remove: notice a line move on a dashboard, guess at a
cause, author a `PodTrace`, and hope the problem recurs while they are
watching. An inspection closes that loop, a rule that holds raises a typed
**issue**, and an issue can start a session on its own.

```
metrics  ──►  rule holds for `For`  ──►  issue activates
                                            │
                                            ├──►  podtrace_issue_active{...} = 1
                                            └──►  Kubernetes Event (source: issue)
                                                     │
                                                     └──►  PodTraceSchedule
                                                             trigger: Issue
                                                             └──►  PodTraceSession
                                                                     └──►  the trace
```

## Enabling it

Inspections live under the metrics plane, because they read that plane's own
series and would have nothing to evaluate without it:

They are on by default, with the metrics plane. On their own they page nobody:
an activated issue sets `podtrace_issue_active` and writes a Kubernetes Event
on the workload's pod. A session starts only when a `PodTraceSchedule` with an
`Issue` trigger exists, and a webhook fires only when
`agent.alerting` is configured. Both are yours to add.

To turn them off:

```bash
helm upgrade --install podtrace ghcr.io/gma1k/charts/podtrace \
  --set agent.metrics.inspections.enabled=false
```

To keep the rules evaluating but write no Events:

```bash
--set agent.metrics.inspections.enabled=true \
--set agent.metrics.inspections.alerts=false
```

That exposes `podtrace_issue_active` and writes no Events, so nothing starts a
session.

On a TracerConfig you edit directly, the same holds: only `enabled: false`
turns them off. Removing the `inspections` block, or `enabled` from it, puts
them back to the default, which is on:

```yaml
spec:
  agent:
    metrics:
      inspections:
        enabled: false
```

## Why rules read metrics, not events

The obvious implementation is to run the existing diagnostic detector over the
event stream. It would be wrong here, for two reasons:

1. **Under kernel-side aggregation there are no events.** The ring buffer
   carries nothing while the bypass is armed, so every rule would see an empty
   batch and report healthy, the worst failure mode an inspection can have,
   because it is indistinguishable from good news.
2. **An inspection has to agree with the dashboard beside it.** Reading the
   same gathered series a scrape returns makes a firing rule reproducible: the
   operator can run the rule's query themselves and get the same number.

So a rule evaluates over a snapshot of the agent's own registry. Whichever
path fed a metric, event stream or BPF map, the rule sees the identical
value.

## How long a condition must hold

A rule that is true for one interval is usually noise. Each rule therefore
carries a `For` duration: the condition must hold that long before the issue
activates, and the issue clears as soon as the condition stops holding. A
condition that flaps starts its `For` over rather than accumulating the time
the workload was healthy.

The durations differ per rule because the signals do. Saturation is real
within a minute; a latency regression needs longer to distinguish from a burst
of large requests.

## The rules

| Issue id | Fires when | `For` |
|---|---|---|
| `resource.saturation` | a container is near its CPU, memory or I/O limit | 1m |
| `l7.error_rate` | the workload's application-layer error ratio exceeds its threshold | 2m |
| `l7.latency_degraded` | the workload's mean request duration exceeds its threshold | 3m |
| `db.connection_acquire_slow` | callers spend a mean of 100ms or more obtaining a database connection | 2m |
| `db.pool_saturated` | a Go `database/sql` pool has 80% or more of `SetMaxOpenConns` in use | 2m |
| `net.connection_failure_rate` | the workload's outbound connection attempts fail more often than its threshold; attempts with no route for their address family (a dual-stack client's IPv6-to-IPv4 fallback) are left out | 2m |
| `net.rtt_spike_rate` | more than 5% of the workload's socket operations run slower than 100ms; against a kernel-aggregated (native) histogram the bound is taken at the next bucket edge, 105ms, so it only counts observations certainly above 100ms | 3m |
| `cpu.contention` | the workload spends a mean of 50ms or more runnable but not running, across at least 100 preemptions | 3m |
| `dns.slow_lookup_rate` | more than 5% of the workload's DNS lookups answer slower than 100ms, at 0.1 lookups per second or more | 3m |
| `fs.slow_operations` | more than 5% of the workload's regular-file reads, writes and fsyncs take longer than 50ms, at 0.1 operations per second or more | 3m |
| `dns.failure_rate` | more than 5% of the workload's DNS lookups fail (SERVFAIL, REFUSED, another error rcode, or no answer at all), at 0.1 lookups per second or more; NXDOMAIN is an answer and never counts | 3m |
| `tls.handshake_failure_rate` | more than 5% of the workload's TLS handshakes fail, at 0.1 handshakes per second or more; only handshakes through Go's `crypto/tls`, OpenSSL, LibreSSL, BoringSSL (gRPC-Java's netty-tcnative included), GnuTLS and mbedTLS are seen | 3m |

### TLS: failed handshakes, from the C libraries

`tls.handshake_failure_rate` divides `errors_total{kind="tls"}` by every
handshake in `podtrace_workload_tls_handshake_duration_seconds`, failed ones
included. A handshake is counted once, by its outcome: OpenSSL's non-blocking
handshake returns below zero on every round trip it waits for, and only the
`SSL_get_error` that follows tells a wait from a failure, so a wait is
dropped and a fatal error is the one failure. With kernel aggregation on, in
either mode the agent uses, a failed handshake reaches the counter through
the error bit of its aggregated row; a kernel test drives a real `curl`
through one refused and one accepted handshake and checks both.

A library that decides the handshake itself can abandon it without OpenSSL
ever reporting an error. netty-tcnative, the BoringSSL that gRPC-Java and
Netty ship, verifies the peer's certificate in Java: on a certificate it
rejects, every `SSL_do_handshake` returns a wait, and the connection is
freed mid-handshake. So each connection's handshake is tracked from its first
call until it is decided, and an `SSL_free` of one that never was is one
failure. A handshake is also decided only once per connection, since netty
calls `SSL_do_handshake` again on a connection that is already up.

The handshakes are those of Go's `crypto/tls`, OpenSSL (and LibreSSL and
BoringSSL), GnuTLS and mbedTLS. A Go handshake is probed at the entry of
`(*Conn).clientHandshake` and `(*Conn).serverHandshake` and at every return
in them, keyed by its goroutine since a handshake that waits on the network
can resume on another thread; `(*Conn).Handshake` is not used, since every
`Read` and `Write` calls it. Java's JSSE and rustls handshake without any of
these, so a workload built on them has no handshakes here and the rule never
fires for it.

The failures are the usual suspects: a certificate that expired or that the
client does not trust, a name that does not match, no TLS version or cipher
in common, or a client speaking TLS to a plaintext port. The session report's
TLS section lists the processes whose handshakes failed.

### DNS: a share of slow lookups, not a mean

`dns.slow_lookup_rate` reads `podtrace_workload_dns_latency_seconds`. A cache
hit answers in well under a millisecond and an upstream miss in tens of
milliseconds, so a mean moves with the hit ratio rather than with the
resolver's health; the share of lookups above 100ms does not. On a three-node
kind cluster no workload, CoreDNS's own upstream lookups included, had more
than 0.26% of lookups above 100ms, while CoreDNS had 13-23% above 25ms working
normally, which is why the bound is not lower. A workload whose DNS replies
were delayed by 150ms read 100% and raised the issue within its hold time.

A lookup that never gets an answer has no answer time, so it records no
latency and is not a slow lookup: it is a failure, and `dns.failure_rate` sees
it.

### DNS: failures, not names that do not exist

`dns.failure_rate` reads `podtrace_workload_dns_lookups_total`, which counts
every lookup by its answer in the `rcode` label. A failure is a `SERVFAIL`, a
`REFUSED`, any other error rcode (`other`), or a `timeout`: a query still
unanswered five seconds after its latest send. `NXDOMAIN` is not a failure.
Kubernetes' `ndots:5` search path tries a short name under every search
domain first, so a lookup of `kubernetes.default` answers `NXDOMAIN` several
times on its way to the name that exists; on a kind cluster a pod doing
nothing but resolving names saw 88% of its answers be `NXDOMAIN`. Counting
those would fire on every workload that resolves anything.

A resolver retransmits a query it got no answer to under the same id. The
retransmission keeps the query's first send as its start, so a lookup
answered on its second try carries the whole wait into
`podtrace_workload_dns_latency_seconds`, and only the latest send moves the
timeout. On an idle kind cluster no workload had a failed lookup; a pod
querying a server that never answers raised the issue within its hold time.
The message names the commonest failure, and the remediation follows it: a
timeout points at the resolver's reachability and conntrack, a `SERVFAIL` at
the resolver's upstreams, a `REFUSED` at which server the workload asks.

### Filesystem: slow storage, not a slow file

`fs.slow_operations` reads `podtrace_workload_filesystem_latency_seconds` for
`read`, `write` and `fsync`, every regular-file operation counted in the
kernel, page-cache hits included. Opens, closes, unlinks and renames are left
out: they are metadata operations with a latency profile of their own. On a
three-node kind cluster no workload's read, write or fsync took 1ms or longer
over five minutes, so the 50ms bound is not about clearing a noise floor: it
is above local storage and above what network block storage takes, and 5% of
operations beyond it is storage in trouble. A pod whose writes were throttled
to a handful of IOPS with a cgroup `io.max` raised it.

It needs the filesystem in the plane, which is the default with kernel
aggregation; see [Continuous Metrics](continuous-metrics.md#the-filesystem-in-the-plane).

### The two planes now evaluate the same vocabulary

`net.connection_failure_rate` and `net.rtt_spike_rate` were part of the issue
vocabulary from the start but had no continuous rule, so the same id meant
something during a session and nothing the rest of the time. Both now fire
continuously, from `podtrace_workload_network_connections_total` and
`podtrace_workload_network_latency_seconds` respectively.

`net.connection_failure_rate` applies the same `minRequestsPerMinute` traffic
floor as `l7.error_rate`, which the session plane does not. That is the one
deliberate difference between the planes: a session inspects a bounded batch
an operator asked for, while this runs against every workload forever, where a
single failed connect in an idle interval reads as a 100% failure rate. Above
the floor the two agree, and a test pins that.

`net.rtt_spike_rate` keeps its name while measuring `tcp_sendmsg` and
`tcp_recvmsg` syscall duration rather than round-trip time, because the name is
carried in the `RTTSpikeMs` TracerConfig field, in alert routing and in the
`podtrace.threshold.rtt_spike.ms` OTel attribute. Its remediation says what is
actually being timed, so a slow peer no longer sends an operator to inspect the
network path. The name becomes literally true when the measurement moves to the
kernel's own `srtt_us`.

The rule reads the latency histogram's `le="0.1"` bucket rather than the mean,
because a handful of very slow operations and a uniformly mediocre workload
produce the same mean and need different answers. The bound must be one of the
histogram's bucket boundaries; the rule refuses to interpolate between them
rather than report a spike rate no observation supports.

Where `agent.sockOpsRTT` is on and the `sock_ops` hook attaches, the
rule reads `podtrace_workload_network_rtt_seconds` instead: the kernel's own
`srtt_us`, which makes the id's name literally true. Where it cannot attach —
kernel below 5.10, no cgroup v2, a runtime that declines
`BPF_CGROUP_SOCK_OPS` — the rule falls back to syscall latency rather than
going silent, because a working approximation beats a rule that never fires.
Every message names which of the two it measured, and the remediation differs
accordingly: the kernel reading sends you to the network path outright, the
fallback tells you to rule out a slow peer first.

### Saturation beyond the database

`db.pool_saturated` reads `podtrace_workload_db_pool_utilization_percent`,
which existed with no rule reading it. It fires *before*
`db.connection_acquire_slow`: a pool at 90% of its ceiling with fast acquires
has a problem that has not reached callers yet, which is the whole point of
sampling the pool rather than waiting for queueing. Utilization counts the
connections in use, open minus idle, so a pool whose connections sit open
and idle between fast queries is not reported saturated.

`cpu.contention` reads `podtrace_workload_cpu_runqueue_latency_seconds` and
carries `podtrace_workload_lock_contention_seconds` as evidence rather than as
a second rule.

It deliberately does **not** read `cpu_blocked_seconds`, which was the obvious
choice and the wrong one: that family counts every departure from the CPU, so
an idle pod sleeping in `epoll_wait` dominates it. Measured on an idle kind
node, an nginx serving nothing showed a 2825ms mean while a pod actually
serving traffic showed 102ms, so a rule reading it fired on precisely the
workloads that were healthy. The run-queue family counts only intervals that
began with a preemption, which is the workload wanting a CPU and not getting
one. An operator seeing this asks one
question first, whether the workload is waiting for a CPU or for a lock, and
the two need opposite fixes: more CPU, or fewer callers on a hot lock. When
lock waits are the longer of the two, the remediation says so.

`db.connection_acquire_slow` replaces the `pool.exhaustion` id that was
withdrawn before an earlier release. The withdrawal was right for the reason
given then, no metric measured the thing the name claimed, and the
replacement is named more narrowly on purpose. It reads
`podtrace_workload_db_connection_acquire_seconds`, which times
`database/sql.(*DB).conn` end to end and therefore cannot separate two causes:

- **queueing** for a free slot once the pool is at `SetMaxOpenConns`, which is
  exhaustion
- **establishing** a new connection while the pool is below its maximum,
  which is churn, usually from `SetMaxIdleConns` being too low

Both block the caller, so both deserve an issue; calling it exhaustion would
have been wrong in the second case. A workload churning connections fires this
rule while its own `sql.DBStats.WaitCount` reads zero, comparing the two is
how an operator tells which cause they have. The remediation text says so.

It keys on the mean rather than the count, because a thousand callers each
waiting a microsecond is a busy pool, not a slow one. Go `database/sql` only:
absence is not evidence of a healthy pool on a JVM, Node or Python workload.
See the saturation section of [continuous-metrics.md](continuous-metrics.md).

Each rule carries the PromQL an operator can run to see what it saw. For
example, `l7.error_rate` is:

```
100 * sum by (namespace, workload) (rate(podtrace_workload_l7_requests_total{outcome="error"}[5m]))
  / sum by (namespace, workload) (rate(podtrace_workload_l7_requests_total[5m]))
```

Note the `sum by`: the ratio is taken across the whole workload, not per
protocol. Dividing one protocol's errors by that protocol's own requests would
fire on a rarely-used protocol that failed once, true, and useless.

`resource.saturation` is the one rule both planes evaluate, and it bands
severity through the same function the diagnostic detector uses, so the same
reading cannot fire at two different severities depending on which plane saw
it.

### Thresholds

Rule *shapes* are not configurable, that is what keeps the issue vocabulary
meaningful. The numbers they compare against are:

```yaml
agent:
  metrics:
    inspections:
      enabled: true
      interval: 30s
      thresholds:
        errorRatePercent: 5
        minRequestsPerMinute: 6
        meanLatency: 1s
        acquireMean: 100ms
        cpuBlockedMean: 50ms
        poolUtilizationPercent: 80
        dnsSlowLookupPercent: 5
        fsSlowOperationsPercent: 5
        dnsFailurePercent: 5
        tlsHandshakeFailurePercent: 5
```

`poolUtilizationPercent` is the warning band for `db.pool_saturated`; it
escalates to critical ten points higher.

`minRequestsPerMinute` is the traffic floor below which the error-rate,
connection-failure and slow-DNS rules stay quiet. Without it, a single failed request during an idle interval reads
as a 100% error rate, which is arithmetically true and operationally
worthless, and would page someone for every idle workload in the cluster.

## Issue ids are contractual

An id appears in `podtrace_issue_active{id=...}`, in an alert's error code, and
in whatever alert routing you build on it. Under
[STABILITY.md](../STABILITY.md) that makes the vocabulary contractual: adding
an id is a minor, renaming one is breaking. A snapshot test fails when the
registry changes, so a rename cannot happen by accident.

## What is exposed

| Metric | What it tells you |
|---|---|
| `podtrace_issue_active{id,namespace,workload,pod,resource,severity}` | 1 while an issue is firing |
| `podtrace_inspections_evaluations_total` | the loop is running; a flat counter means it is not |
| `podtrace_inspections_failures_total` | passes that could not gather fully; rules are narrowed while this rises |
| `podtrace_inspections_transitions_total{id,transition}` | activations, escalations and recoveries |
| `podtrace_inspections_tracked_issues` | issue instances held against the budget |
| `podtrace_inspections_dropped_total` | instances refused because the budget was full |
| `podtrace_inspections_untriggerable_total` | activated issues that could not start a session |
| `podtrace_agent_issue_pod_unresolved_total` | issues for which no pod could be resolved |

Each agent also serves its active issues as JSON at `/issues` on the metrics
port: id, severity, subject, the time each activated, its message as the
latest evaluation wrote it, and its likely causes on the same workload (see
[Likely causes](#likely-causes)), with the calls the agent saw in its latest
window. `kubectl podtrace status` reads it, so an issue's
message there is current. The Kubernetes Event an issue writes records the
moment it activated and is never rewritten, since an Event that looked new
again would start another session; an agent that predates `/issues` is read
from its Events instead.

An issue that worsens, warning to critical, is reported like an activation:
it writes its own Event and counts as `transition="escalated"`, so a
`PodTraceSchedule` whose `minSeverity` is the higher one starts a session from
it. One that eases back changes its severity and nothing else.

A resolved issue's `podtrace_issue_active` series is **deleted**, not set to 0.
A series left at 0 keeps answering instant queries forever, so the issue list
would only ever grow and a dashboard filtered on the metric's presence would
list every issue the node had ever seen.

### Deliberately not a status condition

An issue is a metric, not a condition on a CR. Every agent in the fleet would
otherwise contend on the same object's status, a write per node per
evaluation, with the last writer winning and no way to tell whose reading you
are looking at. The same reasoning is recorded for kernel aggregation in
[continuous-metrics.md](continuous-metrics.md).

## Likely causes

Issues rarely come alone. A saturated connection pool makes requests slow; a
slow dependency makes its callers slow. podtrace links each active issue to
the active issues that likely caused it, and follows the chain to the root:

```
WORKLOAD      ISSUE                LIKELY CAUSE
shop/front    l7.latency_degraded  db.pool_saturated on shop/backend, through l7.latency_degraded on shop/backend
shop/backend  l7.latency_degraded  db.pool_saturated on shop/backend
```

A link is a likely cause, never a verdict, and it only annotates. It never
changes when an issue fires or clears, never silences one, and never stops a
`PodTraceSchedule` from starting a session: the root cause's own issue starts
its session as it always did, so the deep capture lands on the workload that
is actually at fault.

### What can cause what

Two active issues are linked only when the table says one can cause the
other. Every pair is a mechanism, not a coincidence.

On the same workload:

| Issue | Likely causes |
|---|---|
| `l7.latency_degraded` | `db.pool_saturated`, `db.connection_acquire_slow`, `cpu.contention`, `resource.saturation`, `dns.slow_lookup_rate`, `fs.slow_operations`, `net.rtt_spike_rate` |
| `l7.error_rate` | `dns.failure_rate`, `tls.handshake_failure_rate`, `net.connection_failure_rate`, `db.pool_saturated` |
| `db.connection_acquire_slow` | `db.pool_saturated` |

On a workload it called in the same window, read from the service map:

| Issue | Likely causes |
|---|---|
| `l7.latency_degraded` | `l7.latency_degraded` of the dependency |
| `l7.error_rate` | `l7.error_rate` of the dependency |

Activation order is not consulted: being active at the same time is enough.
Every rule holds for the same time, so which of two co-active issues
activated first is mostly which evaluation saw it first.

A chain is followed to its root, an issue nothing further explains, by the
shortest path, at most six hops. When two workloads call each other while
both are slow, the chain stops at the issue that would close the cycle; when
a cycle leaves no root at all, the issue's direct causes are reported.

### Where the links come from

Each agent links the issues it sees itself, which covers causes on the same
workload, and serves them on `/issues`. When an issue activates with a cause
already active, its alert and its Kubernetes Event say so: the message gains
"Likely cause: ...", the Event gains a `podtrace.io/likely-causes`
annotation, and a session the Event starts records the cause in its reason.
The alert's title, which deduplication keys on, does not change, and an Event
is never rewritten, so a same-workload cause that appears later shows up in
`kubectl podtrace status` and the metrics, not on the Event.

A dependency usually runs on other nodes, so the cross-workload links are made
by the operator. On the leader, every 30 seconds, it reads each agent's
`/issues`, which also carries the calls the agent saw in its latest window,
maps each called Service to the workloads behind it through its
EndpointSlices, named exactly as the agents name workloads, and links the
whole cluster's issues at once. It publishes the links as
`podtrace_issue_cause` and serves the latest pass at `/correlations` on its
metrics port. `kubectl podtrace status` reads it and shows a LIKELY CAUSES
section; when the operator cannot be read, it falls back to the agents'
same-workload links and says so.

When an issue's likely cause is on another workload, the operator also writes
one Event on a pod of the affected workload, the pod the agent named or else
the first of the workload's pods by name, when the link appears:

```
Warning  PodtraceLikelyCause  pod/front-5bf4f4d7d6-znkhm  l7.latency_degraded on corr/front: likely cause db.pool_saturated on corr/backend, through l7.latency_degraded on corr/backend
```

It carries the same `podtrace.io/issue-id`, `podtrace.io/workload` and
`podtrace.io/likely-causes` annotations as an issue's Event, but its reason is
`PodtraceLikelyCause`, not the alert reason, so it never starts a session and
never counts as an issue. It is written once while the link holds and again
if the link goes away and comes back; a restarted operator announces the
links it finds once more.

A call counts as a dependency only when it carried traffic, requests or bytes,
in the window, and only to a Service that resolves to workloads. A call over
the service map's cardinality bound, recorded as `target_namespace="unknown"`,
names no real service and is never a dependency.

| Metric (operator) | What it tells you |
|---|---|
| `podtrace_issue_cause{id,namespace,workload,cause_id,cause_namespace,cause_workload}` | 1 while an issue's likely root cause is that other issue; deleted when the link no longer holds |
| `podtrace_correlation_agent_reads_failed_total` | agent reads that failed; links involving those agents' workloads are missing while it rises |

The operator reads `/issues` on the agents' inspect port (9092). With
`networkPolicy.enabled: true`, the chart's NetworkPolicy keeps that port open
to it whatever `networkPolicy.metricsFrom` and `networkPolicy.inspectFrom`
say.

### Cost

The operator reads one small JSON document per agent per interval, at most
eight at a time, and caches EndpointSlices trimmed to the Service name and each
endpoint's pod reference. Linking is linear in the links per issue, so a
densely connected call graph stays cheap.

## Starting a session from an issue

An activated issue is raised as an alert with source `issue`, which the
existing flight-recorder contract already understands. To act on it:

```yaml
apiVersion: podtrace.io/v1alpha1
kind: PodTraceSchedule
metadata:
  name: on-error-rate
  namespace: shop
spec:
  trigger:
    sources:
      - kind: Issue
        issueID: l7.error_rate
        minSeverity: warning
    selector:
      matchLabels:
        app: api
  sessionTemplate:
    spec:
      selector:
        matchLabels:
          app: api
      duration: 2m
      reportRef:
        configMap:
          name: api-error-rate-report
```

`issueID` picks one issue from [the rules](#the-rules). Leave it out and every
issue at or above `minSeverity` starts a session, so a `cpu.contention`
warning would start the same capture as an error rate. List one source per
issue to act on several. The full trigger reference, including cooldown and
the hourly cap, is in [PodTraceSchedule](crd-podtraceschedule.md#trigger-mode-flight-recorder).

The session an issue starts carries `podtrace.io/issue-id` and
`podtrace.io/trigger-reason` (what the agent measured), and its report opens
with that issue:

```text
=== Started by issue l7.error_rate ===

  Severity:       warning
  Pod:            shop/api-7d9f8b6c4-x2k8q
  Fired at:       2026-10-02T09:14:03Z
  Agent measured: High application error rate for shop/api: 100.0% of 240 requests (threshold: 5.0%)
  This capture:   does not raise this issue itself; the agent's measurement above is the evidence
  Look first at:  HTTP Statistics
```

A session raises only `net.connection_failure_rate`, `net.rtt_spike_rate` and
`resource.saturation` from its own events; the other ids read metrics a
session does not keep. For those three the report says whether the session
saw the condition too, which tells you whether it was still present while the
session collected.

### The pod requirement

The trigger contract targets a **Pod** as the Event's involved object; the
operator ignores an Event that names anything else. Saturation issues already
name a pod, because the utilization gauge carries one. A workload-scoped issue,
an error rate, a latency regression — is about a Deployment, so the agent
resolves a representative pod of that workload from the pods it is already
tracking on its own node. Any replica is a valid target: the workload's
problem is present on every replica by definition of being the workload's.

When no pod can be resolved, the issue is still graphed and still logged, and
`podtrace_inspections_untriggerable_total` increments. That case is counted
rather than dropped in silence precisely because a silently open
metric-to-session loop looks exactly like a healthy one.

## Cost

An evaluation is one `Gather()` of the agent's own registry plus a linear pass
per rule. At the default 30s interval that is negligible beside the plane it
reads.

State is bounded: the engine tracks at most `budget` issue instances (512 by
default) and refuses new ones past that, counting the refusals. An unbounded
issue map inside an agent that must never be the reason a node degrades is not
an acceptable trade for completeness.

## Related documents

- [continuous-metrics.md](continuous-metrics.md), the surface inspections read
- [crd-podtraceschedule.md](crd-podtraceschedule.md), turning an issue into a session
- [alerting.md](alerting.md), where the alert goes
- [STABILITY.md](../STABILITY.md), what a version promises about issue ids
