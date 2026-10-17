# Continuous metrics

Podtrace exposes two Prometheus surfaces. This page documents the
**continuous** one: workload metrics aggregated by the always-on agent and
intended for a permanent scrape.

The other surface is the **diagnostic** one in [metrics.md](metrics.md), served
by the CLI behind `--metrics` for the duration of one tracing run. The two are
separate on purpose and neither replaces the other:

| | Diagnostic | Continuous |
|---|---|---|
| Served by | the CLI, per run | the agent, always |
| Lifetime | one invocation | as long as the node |
| Scoped to | the pods that run targets | every pod on the node |
| Labelled by | process and pod | namespace, workload, container |
| Latency shape | histograms and latest-value gauges | histograms only |
| Answers | *why* is this pod slow | *which* workload is unhealthy |

## Enabling it

On by default: a plain install serves workload metrics on every agent's
`/metrics` and is scraped without further setup. Where the Prometheus Operator
is installed the chart's `PodMonitor` selects the agents; everywhere else the
agent pods carry `prometheus.io/scrape`, `prometheus.io/port` and
`prometheus.io/path` annotations, which the community Prometheus chart, the
OpenTelemetry Collector and Datadog discover on their own. Nothing has to be
installed for either.

To run podtrace as an on-demand tracer only, turn the plane off with
`--set agent.metrics.enabled=false`; the cost table below is what that saves.

The agent observes **every pod on the node**, not only those a
`PodTrace` or `ApplicationTrace` targets. Coverage does not require
authoring an object, that is the difference between this plane and
on-demand diagnostics.

### Chart values

```yaml
agent:
  metrics:
    enabled: true
    kernelAggregation: true    # on by default; see "Kernel-side aggregation"
    excludeNamespaces: []      # skipped by the plane; diagnostics unaffected
    seriesBudget: 0            # 0 uses the built-in default of 40000
    nativeHistograms: true
    labels:
      pod: false               # each of these multiplies series count
      process: false
```

These map onto `TracerConfig.spec.agent.metrics`, whose toggles default to
on in the CRD schema: a TracerConfig written without the chart, or the one the
operator creates on an OLM install, runs the plane too. Editing the CR directly
works but gets reverted on the next chart upgrade, so prefer
`helm upgrade --reuse-values --set …`, same rule as every other
TracerConfig field, see [crd-tracerconfig.md](crd-tracerconfig.md).

### Cost, measured

Enabling the plane costs real CPU, because it attaches probes to *every*
pod on the node: every pod's events cross the ring buffer into userspace and
the plane aggregates each one. Cost scales with **event volume**, not with
series count.

Measured on a 3-node kind cluster running Cilium, cert-manager and CoreDNS,
on the node with the workload:

| Configuration | Observations/sec | Agent CPU |
|---|---|---|
| Plane off | — | 0.01 cores |
| Plane on, default categories | ~34,000 | ~0.12 cores |

### The filesystem in the plane

The plane covers regular-file reads, writes, fsyncs, opens and closes when
kernel aggregation is on, which it is by default. Every such operation of a
targeted pod is counted in the kernel; only one that takes 1ms or longer also
becomes an event, carrying the file name. Pipes, sockets, eventfds and ttys
pass through the same kernel functions but are not filesystem I/O, so they
are left out; the network and lock families cover them.

Measured on a 3-node kind cluster, with two pods on one node doing 4KiB
`dd` reads and writes as fast as they can (330,000 reads, 90,000 writes and
350 fsyncs a second):

| `filesystem` | Agent CPU on that node |
|---|---|
| `false` | 0.26 cores |
| `true` | 0.23 cores |

The agent does not pay for the operations; the workload does, because the
probe runs in the task making the call. A cached 4KiB read on that node took
1.08µs untraced:

| How the kernel traces it | Read of a traced pod | Read of any other process |
|---|---|---|
| fentry/fexit (5.11+ with BTF) | +0.30µs | +0.12µs |
| kprobes (older kernels, or `btfMode: file`) | +0.89µs | +0.48µs |

That is noise for a workload that reads files at ordinary rates, and a few
percent of a core for one doing hundreds of thousands of cached reads a
second. `agent.metrics.filesystem: false` leaves filesystem latency to
diagnose sessions. Without kernel aggregation the plane does not cover the
filesystem at all, since it would see only the operations of 1ms or more.

With the default categories the remaining volume is dominated by network
byte counting. That is the next thing to get cheaper.

Practical guidance:

- Watch the agent's own CPU after enabling it (see below). If it approaches
  `agent.resources.limits.cpu`, raise the limit or narrow coverage — a
  throttled agent drops events and the metrics under-report.
- Use `excludeNamespaces`. System namespaces usually produce a large share
  of the events and the least interesting metrics.
- Moving aggregation into the kernel, so a metrics-only node produces no
  per-event userspace traffic at all, is the planned structural fix.


### Watch for throttling, not just for drops

The failure mode to alert on is **silent under-reporting**. If the agent is
throttled at its CPU limit it stops keeping up with the kernel, events are
lost before the plane ever sees them, and the dashboards keep looking
healthy while the numbers are wrong. Nothing in the workload metrics
themselves reveals this — a lower rate is indistinguishable from less
traffic.

Three signals together tell you whether to trust the surface:

```promql
# Is the agent at its CPU limit? (the agent's own process metrics)
rate(process_cpu_seconds_total{job="podtrace-agent"}[5m])

# Is the kernel losing events before userspace sees them?
sum by (reason) (rate(podtrace_agent_kernel_events_dropped_total[5m]))

# How much is the plane actually absorbing?
sum by (outcome) (rate(podtrace_workload_metrics_events_total[5m]))
```

The agent exposes Go and process collectors on the same endpoint, so the
first query needs no extra exporter. If CPU is pinned at the limit while
kernel drops are non-zero, the workload metrics are undercounting and
raising the CPU limit or narrowing coverage comes before trusting any
number on the dashboard.

### Environment variables

The operator renders the CR fields into agent environment. These are the
underlying knobs, useful when running the agent outside the operator:

| Variable | Default | Field |
|---|---|---|
| `PODTRACE_WORKLOAD_METRICS` | `false` | `enabled` |
| `PODTRACE_WORKLOAD_METRICS_EXCLUDE_NAMESPACES` | empty | `excludeNamespaces`, comma-separated |
| `PODTRACE_WORKLOAD_METRICS_SERIES_BUDGET` | `40000` | `seriesBudget` |
| `PODTRACE_WORKLOAD_METRICS_NATIVE_HISTOGRAMS` | `true` | `nativeHistograms` |
| `PODTRACE_WORKLOAD_METRICS_POD_LABEL` | `false` | `labels.pod` |
| `PODTRACE_WORKLOAD_METRICS_PROCESS_LABEL` | `false` | `labels.process` |

Two more knobs have no CRD field, because they tune eviction rather than
what is measured:

| Variable | Default | Meaning |
|---|---|---|
| `PODTRACE_WORKLOAD_METRICS_SERIES_TTL` | `15m` | How long a series may go unobserved before it is deleted |
| `PODTRACE_WORKLOAD_METRICS_REAP_INTERVAL` | `1m` | How often the agent checks for idle series |

Nothing is rendered when the plane is disabled, so a cluster not using it
sees a byte-identical agent pod template and no rollout.

## Labels

Every workload family carries the same four base labels:

| Label | Source | Why this one |
|---|---|---|
| `namespace` | pod namespace | |
| `workload` | controller owner name, with `ReplicaSet` resolved to its `Deployment` | Survives a rollout; a pod name does not |
| `workload_kind` | `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `Pod`, … | Functionally determined by `workload`, so it costs no extra series |
| `container` | container name | |

Notably **absent**, and deliberately so:

- **`pod`**: a pod name changes on every rollout, so a pod label mints a
  fresh series each deploy and retires the old one. That churn, not the
  instantaneous series count, is the dominant cost in Prometheus.
- **`process_name`**: unbounded, and bounding it to the top *N* leaves an
  `other` bucket that answers nothing.

Both are available on the diagnostic surface, where the run is short enough
for them to be free, and both belong on spans rather than series when you
need per-request detail.

If you need one of them here anyway, `agent.metrics.labels.pod` and
`agent.metrics.labels.process` add them. Expect the series count to rise by
roughly the number of pods per workload, or the number of distinct process
names, and size `seriesBudget` accordingly.

## Workload metrics

These are the contractual surface. Metric names and label keys follow the
rule in the [*Metrics surface*](../STABILITY.md#metrics-surface) section of
STABILITY.md: a minor release may rename or relabel them, a patch release may
not.

### Application layer

| Metric | Type | Extra labels |
|---|---|---|
| `podtrace_workload_l7_requests_total` | Counter | `protocol`, `status_class`, `outcome` |
| `podtrace_workload_l7_request_duration_seconds` | Histogram | `protocol` |

For HTTP (every version) and gRPC these families count the requests the
workload **served**. When the workload makes a call, the response it reads
belongs to the caller's side of the exchange: it is recorded on the
[service map](#the-service-map) edge families, and not here, so a call
between two traced workloads is counted once as served (on the callee) and
once as an edge (on the caller), and a caller's latency never includes its
upstream's. A probe that cannot tell which side the process was on records
the response in both places, as before. Other L7 protocols (FastCGI, Redis,
Memcached, Kafka, databases) carry no role and are recorded in both places.

`protocol` is one of `http`, `http2`, `http3`, `grpc`, `fastcgi`, `redis`,
`memcached`, `kafka`, `database`, `unknown`. HTTP/2 and HTTP/3 keep their own
values rather than collapsing into `http`, because distinguishing them is the
point of podtrace's L7 coverage.

`status_class` is `1xx` through `5xx`, or `unknown` when the probe could not
recover a status. The class rather than the exact code is deliberate: a code
multiplies every L7 series by the number of codes a real service returns, and
buys nothing a class does not. The exact code belongs on a span, where it
costs one attribute instead of one series.

`outcome` is `ok` or `error`, so an error ratio is one query rather than a sum
over classes. A `4xx` is a client error and counts as `ok` — it is a failure
of the request, not of the workload being observed, and remains visible
through `status_class`.

### OpenTelemetry semantic conventions

Enabled with `agent.metrics.semanticConventions=true`, the plane also emits
the convention's own names for the L7 signals, **in addition to** the native
families above. That doubling is the point: a stock Grafana, Datadog or
Honeycomb dashboard queries these names, so podtrace becomes a drop-in
inside a stack you already run rather than a second dialect to learn.

| Metric | Attributes |
|---|---|
| `http_server_request_duration_seconds` | `http_request_method`, `http_response_status_code`, `network_protocol_name` |
| `rpc_server_duration_seconds` | `rpc_system`, `rpc_method` |
| `db_client_operation_duration_seconds` | `db_system_name`, `db_operation_name` |

The two server families follow the native L7 families: they hold requests
the workload served, never the responses to calls it made.

These carry **no `podtrace_` prefix** — the names belong to the convention,
and prefixing them would make them invisible to the dashboards they exist to
serve.

Identity arrives as `service_name`, `k8s_namespace_name` and
`k8s_container_name`. `service_name` is the workload, because that is the
label conventional dashboards group by. Semconv's workload keys are
kind-specific (`k8s.deployment.name`, `k8s.statefulset.name`, …) and a
Prometheus family has one fixed label set, so there is no single key that
could carry the workload for every kind.

Three deliberate differences from the native families:

- **`http_response_status_code` is the real code**, not the class. The
  convention expects a code, and a dashboard filtering `status >= 500`
  cannot work on `"5xx"`. This costs roughly ten times the cardinality on
  that one family.
- **`rpc_method` and `db_operation_name` are bounded.** Both come from
  observed traffic, so their value space is open; past
  `PODTRACE_WORKLOAD_METRICS_ATTRIBUTE_CARDINALITY` (default 50) the tail
  folds into `_other` rather than minting series without end.
- **Kafka and FastCGI are absent.** Neither has a server-duration
  convention, and forcing them into one would misdescribe them. They remain
  on the native `podtrace_workload_l7_*` families.

`http.route` is not emitted. podtrace observes the wire, so it sees the
request target rather than the server's route template, and the convention
explicitly warns against substituting the raw path.

#### When the method is `_OTHER`

`http_request_method` carries the real method on every transport podtrace
decodes: HTTP/1.x reads it off the request line in BPF, and HTTP/2 and
HTTP/3 read the `:method` pseudo-header out of HPACK and QPACK
respectively. The method travels request-to-response, because the duration
is only known once the response arrives.

It falls back to `_OTHER` — the convention's own placeholder — in two
cases, both of them honest:

- **The method was outside the convention's set.** `:method` is an
  arbitrary token chosen by the peer, so it is folded to
  GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS/CONNECT/TRACE and anything else
  becomes `_OTHER`. Passing the raw token through would hand Prometheus an
  unbounded, peer-chosen label dimension, which is precisely what the
  series budget cannot defend against.
- **No method was recovered at all.** On a late-joined HTTP/2 connection
  the `:method` may have been indexed into the dynamic table before
  capture attached, and some C-library HTTP/3 adapters measure timing
  without decoding the peer's headers.

`http_response_status_code` is `0` on the same principle, for a response
whose status could not be recovered — a gRPC-over-h2 stream, most often.
The convention would have the attribute omitted; a Prometheus family has
one fixed label set and cannot omit a label, so `0` is the sentinel.

### The service map

Every L7 call and every TCP and UDP transfer records **both ends** of the
edge, so the topology is a PromQL expression rather than a datastore. An
HTTP or gRPC call is drawn from the caller's side only: the served side of
the same call is on the L7 families, and its far end is a client's
ephemeral port, not a Service.

```promql
sum by (workload, target_service) (
    rate(podtrace_workload_edge_requests_total[5m])
)
```

| Metric | Type | Extra labels |
|---|---|---|
| `podtrace_workload_edge_requests_total` | Counter | `outcome` |
| `podtrace_workload_edge_request_duration_seconds` | Histogram | — |
| `podtrace_workload_edge_bytes_total` | Counter | `direction` |

All three carry `namespace` and `workload` for the near end, and
`target_namespace` and `target_service` for the far end. The first two are
RED per edge: rate and errors from the counter, duration from the histogram.
The byte counter puts flows carrying no L7 payload podtrace can decode, a
database, a cache, DNS, anything over TLS — on the map too, since the TCP
and UDP probes stamp the socket tuple onto the event even when nothing
decoded the payload. The shipped Grafana dashboard draws all of it as a node graph.

The far end is a **Service**, not a pod. A Service name survives a rollout;
a pod name and a pod IP do not, and a label carrying one would mint a new
series on every rollout and never stop.

#### The map is directed

A peer is resolved by **address and port together**, and that is what keeps
each call counted once. A client reaches a service on the service's own
port, so its peer resolves to that Service. The server replying to that
client sees the client's *ephemeral* port, which matches no endpoint, so the
server side draws nothing.

Resolving on address alone would record every call twice — once from each
end — and where both workloads have a Service the map would show a reversed
duplicate edge for every arrow. The query above would report double the real
rate.

Two consequences follow, both deliberate:

- **A cluster-local address matching no Service endpoint draws no edge.**
  It is either the client half of a call already recorded from the other
  end, or a peer podtrace cannot name; collapsing every such peer into one
  graph node would merge unrelated systems into a single node that means
  nothing.
- **`target_service="external"`** is the one placeholder that is drawn.
  Traffic leaving the cluster is a real destination, and it reports
  `target_namespace="unknown"` — as does a target folded into `_other` by
  the cardinality bound, because carrying a real namespace next to an
  approximate service would imply a precision the label no longer has.

#### How the far end is resolved

A peer is looked up by address and port against two indexes:

1. **EndpointSlices**, keyed on backend `address:port`. Most TCP lands here:
   conntrack rewrites a connection's destination before the socket is
   established, so the socket carries a backend pod address.
2. **Service ClusterIPs**, keyed the same way. An unconnected UDP datagram
   is addressed to the ClusterIP and nothing rewrites what the probe reads,
   so without this most UDP flows would have no far end at all.

Endpoints are tried first, because a backend address is the more specific
answer and names the same Service.

Peers come from three probe families:

- **L7**, whose record is fused with its L4 socket.
- **TCP send and receive**, read straight off the socket.
- **UDP send and receive**. A connected socket names its peer the way TCP
  does; an unconnected one names it in the datagram, which the kernel writes
  into `msg_name` on receive and the caller supplies on send. Resolvers
  differ on which form they use, so both are handled.

All of it works on a build made without `bpftool`: the socket fields are
read through CO-RE, so libbpf relocates the offsets from the running
kernel's own BTF when the program loads. The iterator kind that locates a
socket payload is relocated the same way rather than baked in at compile
time — `enum iter_type` has been reordered across releases, so a constant
taken from the build host's headers silently misreads payloads on a kernel
that numbers them differently.

#### Why this is a separate family

Metric names and their label keys are contractual
([STABILITY.md](../STABILITY.md)), so adding `target_service` to the
existing L7 families would change the identity of every series already being
queried. Those families are also per-container and per-status-class, so
multiplying them by peer count would multiply the whole surface.

Costed instead as its own family: roughly workloads × peers × outcomes.
Twenty workloads talking to ten services each is about 400 series per node,
against the 40,000 budget. Edges are admitted through the same chokepoint as
every other family, so they cannot bypass the budget, and the reaper evicts
an edge whose workload goes away exactly as it does elsewhere.

#### Resolution cost

The agent watches EndpointSlices and Services cluster-wide, because an edge
points anywhere and a node-scoped cache cannot resolve it. Both are trimmed
on the way into the cache to the addresses, the ports and the identity. Resolutions are cached with a TTL so the hot path pays a map
lookup rather than an index query per event, and the cache is bounded so a
workload talking to many addresses cannot grow it without limit.

If the agent cannot read EndpointSlices and Services, the families are
**not registered at all** rather than exposed and left empty, so an absent
capability does not read as a broken one.

#### Every edge is a per-node observation

An agent only sees calls made by pods on its own node, so an edge exists on
the node where the *caller* runs. Prometheus scrapes each agent separately,
which is exactly right for the metric, but it means the shape of the data is
per-node, and only some questions survive aggregation.

Safe, because Prometheus sums across nodes:

```
# Total request rate on an edge, wherever the callers live
sum by (namespace, workload, target_namespace, target_service) (
  rate(podtrace_workload_edge_requests_total[5m])
)
```

Not safe, because the answer is only ever about one node's callers:

```
# WRONG: reads as "this workload's dependencies", but it is
# "this workload's dependencies as seen from one node"
podtrace_workload_edge_requests_total{workload="checkout"}
```

The practical consequences:

- **A missing edge does not mean the call does not happen.** It may mean no
  replica of the caller is scheduled on the node you are looking at.
- **Fan-out counts must be aggregated first.** Counting distinct
  `target_service` values on a single agent under-reports a workload's
  dependencies whenever its replicas are spread across nodes.
- **Topology reasoning belongs after `sum by`.** Building a graph from one
  agent's series gives a subgraph, not the graph.

This is a property of where the observation happens, not a limitation to be
fixed: an agent that resolved edges for pods on other nodes would be
duplicating what Prometheus already does correctly.

### Network, DNS, filesystem, CPU, TLS

| Metric | Type | Extra labels |
|---|---|---|
| `podtrace_workload_network_latency_seconds` | Histogram | `direction`, `transport` |
| `podtrace_workload_network_bytes_total` | Counter | `direction`, `transport` |
| `podtrace_workload_network_connections_total` | Counter | `transport`, `outcome` |
| `podtrace_workload_network_retransmits_total` | Counter | — |
| `podtrace_workload_network_device_errors_total` | Counter | — |
| `podtrace_workload_network_rtt_seconds` | Histogram | — |
| `podtrace_workload_dns_latency_seconds` | Histogram | — |
| `podtrace_workload_dns_lookups_total` | Counter | `rcode` |
| `podtrace_workload_filesystem_latency_seconds` | Histogram | `operation` |
| `podtrace_workload_filesystem_bytes_total` | Counter | `operation` |
| `podtrace_workload_cpu_blocked_seconds` | Histogram | — |
| `podtrace_workload_cpu_runqueue_latency_seconds` | Histogram | — |
| `podtrace_workload_lock_contention_seconds` | Histogram | — |
| `podtrace_workload_tls_handshake_duration_seconds` | Histogram | — |
| `podtrace_workload_errors_total` | Counter | `kind` |

`direction` is `ingress` or `egress`; `transport` is `tcp` or `udp`.
`operation` is `read`, `write`, `fsync`, `open`, `close`, `unlink` or
`rename`, on regular files only; `fsync` includes `fdatasync`. An open that
fails is counted too, since it has no file to check. A failed operation adds
to `errors_total` with `kind="filesystem"`, except an open that found no file
(`ENOENT`): that is a lookup that answered no, and the loader of a dynamically
linked program makes several on every start. `kind` groups failures as `l7`, `dns`, `network`, `filesystem`,
`tls`, `lock` or `other`. `outcome` is `ok` or `error`, and for
`network_connections_total` also `unreachable` (see below).

`rcode` is the answer a DNS lookup got: `NOERROR`, `NXDOMAIN`, `SERVFAIL`,
`REFUSED`, `other` for any other rcode or resolver error, or `timeout` for a
query still unanswered five seconds after its latest send. The set is fixed,
so the label adds at most six series per workload. A failed lookup adds to
`errors_total` with `kind="dns"`, except `NXDOMAIN`: a name that does not
exist is an answer, and the `ndots:5` search path answers it several times on
every lookup of a short name. A timeout has no answer time, so it is counted
here and not in `dns_latency_seconds`.

Both DNS families count each query on the wire once, read from the packets.
A libc lookup is the same lookup seen a second time, and one call can stand
for several queries, so it is counted only when packet capture is off
(`TracerConfig.spec.agent.dnsPacketCapture: false`). libc's lookups are then
read from `getaddrinfo`, `gethostbyname` and `gethostbyname2` and their `_r`
forms; their results map onto the same answers. A name that does not exist
(`EAI_NONAME`, `HOST_NOT_FOUND`) is `NXDOMAIN`, a name with no address of the
asked family is `NOERROR`, and a temporary failure (`EAI_AGAIN`, `TRY_AGAIN`)
is `SERVFAIL`, since libc reports a server failure and a timeout alike. A
program that resolves on its own, such as busybox or Go's pure-Go resolver,
calls none of them, so without packet capture its lookups are not seen; the
agent says so in its log when it starts. A connection to an encrypted
resolver (DoT, or DoH to a well-known resolver) is not a lookup: its answer
cannot be read.

`network_connections_total` is the denominator `errors_total` never had. A
connection failure count on its own cannot say whether ten failures in a
minute is a broken dependency or a rounding error against ten thousand
successes, which is why `net.connection_failure_rate` could not be evaluated
continuously before this family existed.

Each attempt is counted once, when its outcome is known. `connect()` returns 0
as soon as the SYN is queued, so the family takes the outcome from the
handshake instead: `ok` when the socket reaches `ESTABLISHED`, `error` when it
closes from `SYN_SENT` with an error set, which is how a peer refusing the
connection (`ECONNREFUSED`) or never answering it (`ETIMEDOUT`) shows up. A
`connect()` that fails before any SYN is sent, such as `EHOSTUNREACH`, is
counted as an `error` from its return value. An attempt the application
abandons itself, as a dialer racing IPv4 against IPv6 does with the losing
socket, closes without an error and is counted as neither.

One synchronous failure is counted as `unreachable` instead: `ENETUNREACH` or
`EAFNOSUPPORT`, meaning the pod has no route for the destination's address
family at all. A client resolving a dual-stack name from an IPv4-only pod
tries every IPv6 address first and gets this from the kernel without sending
a packet, then succeeds over IPv4. Counted as errors, a healthy pod doing that
read as an 89% failure rate. `net.connection_failure_rate` leaves `unreachable`
out of both sides of its ratio, and `errors_total` still records the failed
syscalls. `EADDRNOTAVAIL` stays an `error`, because it is also what
ephemeral-port exhaustion looks like.

`network_retransmits_total` and `network_device_errors_total` separate two
things that both land in `errors_total{kind="network"}`: a segment the kernel
had to send again, and a transmit the device refused outright. Retransmits
climbing while the workload's own request duration stays flat is the clearest
signal podtrace has that a problem is on the wire rather than in the
application.

`cpu_runqueue_latency_seconds` is the one that means contention.
`cpu_blocked_seconds` counts every departure from the CPU, voluntary sleeps
included, so a pod parked in `epoll_wait` scores enormously on it while doing
nothing at all: on an idle node an nginx serving no traffic measured a 2825ms
mean there, against 102ms for a pod actually serving requests. The run-queue
family counts only intervals that began with a preemption, where `prev_state`
at `sched_switch` said the task was still runnable. That is the workload
wanting a CPU and not getting one. Alert on that one.

`lock_contention_seconds` is the companion to `cpu_blocked_seconds`. Both mean
the workload is not running, and they need opposite fixes: one is waiting for
a CPU, the other for a lock another thread holds. `cpu.contention` reports
which.

### `network_rtt_seconds` is the only real round-trip time here

`network_latency_seconds` is measured around a syscall: enter a kprobe on
`tcp_sendmsg`, leave on its kretprobe, subtract. That is a real number, but on
a receive it is mostly the time the peer took to answer and on a send it is
mostly how long the socket buffer was full. It is not the wire.

`network_rtt_seconds` is `srtt_us` from the kernel's own `tcp_sock`, the value
congestion control actually uses. Reading it needs a `sock_ops` program, which
no kprobe, uprobe, tracepoint or `cgroup_skb` hook can substitute for.

Enable it with `agent.sockOpsRTT: true` in the chart, or `spec.agent.sockOpsRTT`
on the TracerConfig. Setting the env var on the DaemonSet by hand does not
survive: the operator reconciles the agent's environment. It is on by default.
`BPF_SOCK_OPS_RTT_CB` fires on roughly every ACK, which is affordable only
because `agent.metrics.kernelAggregation`, also on by default, folds those into
histogram buckets so the cost stays O(series). If you turn kernel aggregation
off, turn this off with it, or each ACK becomes a ring-buffer event. It needs kernel 5.10 or newer
and cgroup v2, attaches only to the cgroups podtrace already targets, and
observes only — no sockmap, no redirect, no payload access. Where it cannot
attach the family is simply absent, and `net.rtt_spike_rate` falls back to
`network_latency_seconds` and says so in its message.

### Saturation

Latency, traffic and errors tell you a workload is unhealthy. Saturation is
the signal that tells you *why*, and it is the one that moves first, a
workload at its CPU limit or out of pool connections shows up as latency and
errors everywhere else, with nothing in either family saying what ran out.

| Metric | Type | Extra labels |
|---|---|---|
| `podtrace_workload_resource_utilization_percent` | Gauge | `resource` |
| `podtrace_workload_db_connections_opened_total` | Counter | `db_system` |
| `podtrace_workload_db_connections_closed_total` | Counter | `db_system` |
| `podtrace_workload_db_connection_acquire_seconds` | Histogram | — |
| `podtrace_workload_db_pool_utilization_percent` | Gauge | — |
| `podtrace_workload_db_pool_connections_open` | Gauge | — |

`resource` is `cpu`, `memory`, `io` or `other`. `db_system` is `postgresql`,
`mysql`, `sqlite` or `other`, following OpenTelemetry's `db.system` vocabulary.

#### Utilization holds its peak

A gauge collapses. The other families on this surface are counters and
histograms, which sum correctly when several replicas of a workload land on the
same node, but a gauge does not sum, it overwrites. Two replicas write the
same series, because the label set here is workload-scoped like the rest of the
surface, so a plain last-write-wins would let a healthy replica erase a
saturated one.

It is worse for [inspections](continuous-inspections.md): two replicas
alternating 98% and 5% make the series oscillate, and a rule that requires its
condition to hold continuously would restart its hold timer every other
evaluation and never fire at all.

So every gauge in this section reports the **highest reading seen in the last
30 seconds** rather than the most recent one. Once that window passes without a higher
reading, the newer value wins, that decay is what lets a genuinely recovered
workload stop looking saturated. The window is driven by the clock rather than
by a scrape, so a Prometheus scrape and the inspection engine's own gather
cannot steal resets from each other.

The alternative was to add a `pod` label to this family. That was rejected:
pod labels on this surface are opt-in precisely because each one multiplies
series count, and quietly forcing one onto a new family would break a
documented compatibility contract. Set `agent.metrics.labels.pod=true` if you
want per-replica saturation, and the peak-hold then applies per pod.

The `podtrace_workload_db_pool_connections_open` count holds its peak for the
same reason, even though a count is normally a "right now" number. Reporting a
held 95% utilization beside a current 2 connections would put two readings of
the same pool, taken at different moments, next to each other on one dashboard.

#### Database connections

These two counters are named for exactly what the probes observe. The eBPF
side hooks connection *lifecycle* symbols, so it sees connections being opened
and closed:

| Library | Opened | Closed |
|---|---|---|
| libpq | `PQconnectdb`, `PQconnectdbParams`, `PQconnectStart` | `PQfinish` |
| libmysqlclient | `mysql_real_connect` | `mysql_close` |
| libsqlite3 | `sqlite3_prepare*` | `sqlite3_finalize` |

All three libpq entry points are hooked, not just one. `PQconnectStart` is the
asynchronous API; synchronous clients, which is nearly all of them, `psql` and
`pgbench` included, reach libpq through `PQconnectdb` or `PQconnectdbParams`
and never call it. They do not double count, because they do not call one
another; they share a lower-level internal (`PQconnectStartParams`) which is
deliberately left unhooked.

```
# Connections currently open
podtrace_workload_db_connections_opened_total
  - podtrace_workload_db_connections_closed_total
```

A difference that only ever grows is a connection leak. Compare *rates* rather
than trusting that difference absolutely: a process that exits without calling
`PQfinish` is never counted as closing, so the close counter undercounts on
abnormal termination.

#### Connection acquisition, for Go only

`podtrace_workload_db_connection_acquire_seconds` records the time a caller
spent obtaining a pooled database connection before its query could start:

- `_count` — acquisitions that took longer than 1ms
- `_sum` — the total time callers lost to getting a connection

**It is not `DBStats.WaitCount`.** The probe times
`database/sql.(*DB).conn` end to end, and that function covers two different
causes which it cannot separate:

| Cause | When | `DBStats.WaitCount` counts it |
|---|---|---|
| queueing for a free slot | the pool is at `SetMaxOpenConns` | yes |
| establishing a new connection | the pool is below its maximum | **no** |

Both block the caller for real, which is why they share a metric, but they
have different fixes, so the metric is named for what it measures rather than
for one of its causes. Measured on a kind cluster:

```
workload      DBStats.WaitCount    this metric      cause
poolstarve    203 waits / 97.6s    200 / 95.5s      real slot contention
poolopen        0 waits / 0s       119 / 11.9s      connection churn
```

`poolopen` sets a generous `SetMaxOpenConns` but leaves `SetMaxIdleConns` at
its default of 2 while eight callers run concurrently, so six connections are
closed and re-established every round. `DBStats` reports no waits, correctly;
the callers are still blocked, and this metric reports that. **When the two
disagree, the gap is connection churn**, raise `SetMaxIdleConns`.

Separating the two would mean reading `numOpen` and `maxOpen` out of the `*DB`
struct. The pool capacity gauges below do read them, but they are a different
measurement rather than a split of this one: they sample what the pool looks
like, they do not attribute an individual acquisition to a cause. The
end-to-end duration needs no struct layout at all, which is what keeps this
probe correct on stripped binaries and on every Go version, at the cost of not
attributing the cause.

```promql
# Acquisitions per second slower than 1ms
rate(podtrace_workload_db_connection_acquire_seconds_count[5m])

# Mean time lost per acquisition
rate(podtrace_workload_db_connection_acquire_seconds_sum[5m])
  / rate(podtrace_workload_db_connection_acquire_seconds_count[5m])
```

**This is Go `database/sql` only.** Pooling happens inside the application, and
a caller waiting for a slot is parked on an in-process queue no kernel probe
can see. How reachable that is depends on the runtime:

| Runtime | Acquisition is | Instrumented? |
|---|---|---|
| Go `database/sql` | a call into `(*DB).conn` | **yes** |
| Java (HikariCP) | `LockSupport.park` under JIT | no, practically |
| Node (`pg-pool`) | a JavaScript promise queue | no |
| Python | `Condition.wait` on a futex | only with interpreter frame walking |

So absence of the series means a fast pool **or** a runtime this cannot see,
not a healthy pool on its own. For anything but Go, export pool metrics from
the application (HikariCP's JMX beans, Go's own `sql.DBStats`) and correlate
by workload.

The probe is an entry-and-return uprobe on `database/sql.(*DB).conn`, resolved
through `.gopclntab` so it works on stripped binaries. The symbol is absent
when a program never queries, and absence is treated as "not applicable"
rather than as a failure.

#### Pool capacity, for Go only

`podtrace_workload_db_connection_acquire_seconds` tells you callers already
wait. These two gauges tell you how close the pool is to making them wait,
which is the reading worth alerting on:

| Metric | Reads | Absent when |
|---|---|---|
| `podtrace_workload_db_pool_connections_open` | `database/sql.DB.numOpen` | the binary carries no DWARF |
| `podtrace_workload_db_pool_utilization_percent` | connections in use, `numOpen` minus the idle ones in `freeConn`, as a percentage of `maxOpen` | the same, or the pool is unlimited |

An unlimited pool `SetMaxOpenConns` unset or zero, reports the count but no
percentage. There is no ceiling for the count to be a fraction of, and
publishing 0% would read as an idle pool rather than an unbounded one. The
count still carries the leak signal there.

```promql
# Pools within 10% of their ceiling, before anyone queues for a slot
podtrace_workload_db_pool_utilization_percent > 90
```

Both come from the same `database/sql.(*DB).conn` probe that times acquisition.
Each acquisition samples the pool as it arrives, and the utilization is the
mean of those samples over a second: the pool as callers meet it. Callers
spread evenly over time see the share of time the connections are busy;
callers arriving in bursts find them busy more often than that, which is the
contention those bursts really hit. A pool every caller finds full reads 100;
a pool whose one connection sits idle between occasional fast queries reads
near 0. Counting open connections alone read that pool as full, since an idle
connection stays open. The open count keeps its peak over the second, so a
leak still shows.
Every call is read; one reading per second per process is emitted, and it is
the **highest** occupancy seen since the last one. Emitting whatever the pool
happened to hold at one arbitrary instant per second reads the trough of a
workload that queries in bursts -- measured on kind, a pool pinned at its
ceiling of 4 reported 50% that way. A pool nobody uses emits nothing rather
than zeros, and its series is reaped like any other once the workload stops
being observed.

##### This half needs DWARF, and says nothing without it

`numOpen` and `maxOpen` are unexported fields of an unexported struct. There is
no symbol to hook and no accessor to call, so the probe reads them at a byte
offset from the `*DB` receiver, and it gets that offset from the target
binary's own DWARF at attach time, per process, published into a BPF map keyed
by pid.

Reading the offsets out of the binary in front of us, rather than out of a
table of Go releases, is what makes this tractable: Go emits DWARF by default,
so any application not built with `-ldflags=-w` describes its own struct layout
and no table needs maintaining as Go changes.

**There is no fallback when DWARF is missing, deliberately.** A wrong offset
here does not fail, it returns a plausible connection count, and nothing
downstream can tell it from a real one. A missing percentage is recoverable; a
confident wrong one is not. So a stripped binary gets no pool capacity at all,
while the acquisition histogram above keeps working on it through
`.gopclntab`. The kernel side additionally refuses negative or absurd readings
as evidence the offsets are not describing the struct it expected.

Earlier versions of this document listed `pool_connections`,
`pool_utilization` and `pool_wait_time_seconds`. None of those names ever
existed; the two above are what capacity is reported under.


Note the BPF side also emits an internal "pool exhausted" event, which this
surface deliberately drops: it fires on any query more than 10ms after the
connection opened and never refreshes its timestamp, so it reports the
connection's *age* rather than any wait. Exporting it under a pool name would
be a false claim.

#### Saturation is always on the event path

Unlike the latency families, no saturation family is ever served from the
kernel aggregation map. The map keys on latency buckets and byte counts, which
is the wrong shape for a utilization gauge, and the resource and connection
probes submit unconditionally rather than through the ring-buffer bypass.
Saturation therefore reports identically in both modes.

The two connection families do carry one extra requirement: they come from
uprobes on the client library, so they populate only for containers whose
processes have `libpq`, `libmysqlclient` or `libsqlite3` mapped. A process too
short-lived to be seen by target reconciliation — a per-request CLI invocation,
for instance — will not be instrumented. The acquisition histogram and the two
pool capacity gauges carry the same requirement against the Go binary itself,
plus DWARF for the gauges. `resource_utilization_percent` has no such caveat:
it comes from a kernel-side probe.

## Plane internals

These describe the metrics plane's own behaviour rather than the workload, so
they **carry no compatibility promise**, same tier as the collector
internals in [metrics.md](metrics.md).

| Metric | Description |
|---|---|
| `podtrace_workload_metrics_events_total` | Events reaching the plane, labeled `outcome`: `aggregated`, `unattributed`, `excluded` (namespace in `excludeNamespaces`), or `ignored` |
| `podtrace_workload_metrics_series_dropped_total` | Observations refused because a new series would exceed the budget, labeled `family` |
| `podtrace_workload_metrics_series_active` | Distinct label combinations currently held, counted against the budget |
| `podtrace_workload_metrics_series_reaped_total` | Series removed after their workload stopped being observed, freeing budget |

`unattributed` is worth an alert. It counts events that arrived with no pod
metadata, which means the identity join failed and those observations were
discarded rather than filed under a wrong or placeholder workload. A steadily
rising `unattributed` means the plane is running but measuring nothing.

## Pushing the plane over OTLP

The plane is a scrape target by default. It can also be pushed, as a second
signal on an `ExporterConfig` that already carries spans:

```yaml
apiVersion: podtrace.io/v1alpha1
kind: ExporterConfig
metadata:
  name: collector
spec:
  type: otlp
  otlp:
    endpoint: otel-collector.observability:4318
    metrics:
      enabled: true
      interval: 60s
```

Same object, same endpoint, same headers: metrics authenticate exactly as
the spans do. That reaches every OTLP-compatible backend without a
per-vendor metrics SDK, and it is deliberately **not** Prometheus
remote-write — a Collector does remote-write better, and forwarding rather
than storing keeps podtrace out of the storage business.

Two conditions have to hold for anything to be sent. The plane must be on
(`TracerConfig.spec.agent.metrics.enabled`), because the push republishes
the surface rather than producing a second one; and a PodTrace must
reference the `ExporterConfig`, because that is what tells the agent to
build the exporter at all.

`interval` defaults to 60s, matching a conventional scrape period, and is
clamped to 10s–10m: below the floor the cost outruns what a cumulative
counter can reveal, and above the ceiling a dashboard reads the gap as an
outage.

### What the push looks like on the wire

The Prometheus registry stays the single source of truth. The push reads
the surface that already exists rather than recording a second copy of it,
so the series budget, the cardinality bound and the reaper apply to both
paths identically and cannot drift apart.

Names differ between the two paths, in one direction only:

| Surface | Scrape | OTLP |
|---|---|---|
| Convention families | `http_server_request_duration_seconds` | `http.server.request.duration` |
| Convention attributes | `http_request_method` | `http.request.method` |
| podtrace's own families | `podtrace_workload_l7_requests_total` | unchanged |

The convention families get their dotted names back because that is what an
OTLP-native backend recognises, and dropping to the Prometheus rendering
there would undo the point of emitting them. podtrace's own names have no
convention to honour, so they travel verbatim — the same thing a
Collector's `prometheus` receiver does with a scrape. Rename them in the
Collector if you want something else.

Workload identity arrives as data-point attributes, not as the OTLP
Resource. A Resource belongs to the exporting provider and one provider
serves every workload on the node, so `service.name` on the Resource is
`podtrace` (with `k8s.node.name` beside it) while the observed workload
travels as the `service.name` **attribute**. That is again what the
Collector's Prometheus receiver produces, so both paths agree.

All instruments are cumulative, because the underlying Prometheus counters
are. Native histograms cross as OTLP exponential histograms; classic
buckets cross as explicit-bucket histograms.

### One stream per collector, not per CR

Spans are per-CR: a span belongs to the trace some CR asked for. A counter
does not. So several PodTraces pointing at one collector share a single
metric stream — pushing one per CR would send the same counters two or
three times and make every sum across them wrong. Two CRs pointing at
*different* collectors get one stream each, which is fan-out and correct.

### The push is scoped to the CR's namespaces

The agent holds the series of every namespace on its node, but a push
carries only the namespaces its CRs are entitled to: the PodTrace's own
namespace, or — when it sets `spec.namespaceSelector` — exactly the target
namespaces the operator resolved for it, which only ever includes
namespaces that consented through `podtrace.io/allow-tracing-from`. A
selector that matched nothing pushes nothing. When several CRs share a
collector, the shared stream carries the union of their namespaces, and a
namespace leaves the stream when the last CR that contributed it goes away.

A series belongs to the namespace in its `namespace` attribute, or
`k8s.namespace.name` on the convention families. Service-map edges are
judged by their source `namespace` only: an edge from another namespace
into yours is that namespace's series and is not pushed to you. Node-wide
self-observability series (`metrics_events_total`,
`metrics_series_active`, `metrics_series_dropped_total`,
`metrics_series_reaped_total`, …) carry no namespace and are never pushed;
they remain available to cluster operators on the agent's `/metrics`
endpoint.

A metrics receiver that cannot be reached does not take tracing down with
it: spans keep flowing and the failure is reported through the exporter's
own init-failure metric.

## Histograms

Latency families are exposed as native histograms *and* classic buckets, so
scrapers without native-histogram support still get usable quantiles. Set
`PODTRACE_WORKLOAD_METRICS_NATIVE_HISTOGRAMS=false` to emit classic buckets
only.

The classic layout is twelve buckets spanning 500µs to 30s. The count is
deliberate: the diagnostic surface uses `ExponentialBuckets(0.0001, 2, 20)`,
which is 22 series per label combination, and at this surface's family count
that layout alone would exceed the per-node budget. Query quantiles with
`histogram_quantile` rather than depending on specific `le` values — bucket
boundaries are explicitly outside the compatibility promise.

## Exemplars: from a metric to the trace behind it

The continuous plane tells you *which* workload is unhealthy. The diagnostic
plane tells you *why*. Exemplars are the link between them: when a request
carries a W3C `traceparent`, the agent attaches that trace id to the
observation, so a p99 spike on a dashboard is clickable straight through to
the trace that caused it.

Without this the handoff is manual — you see the spike, author a `PodTrace`,
and hope the problem recurs while you are watching.

Exemplars are attached to:

| Family | Why |
|---|---|
| `podtrace_workload_l7_requests_total` | jump from an error-rate spike to a failing request |
| `podtrace_workload_l7_request_duration_seconds` | jump from a latency bucket to a slow request |
| `podtrace_workload_network_latency_seconds` | jump from a connect-latency spike to the call |
| `podtrace_workload_dns_latency_seconds` | jump from a slow resolution to its caller |
| `podtrace_workload_edge_requests_total` | jump from a slow dependency *on the map* into a trace |

The edge family matters most in practice: the service map is where an
operator starts, so a slow dependency there has to be clickable into a trace,
not just into a name.

### Scraping them

Exemplars are only representable in the OpenMetrics exposition format, so the
scraper has to ask for it:

```yaml
# Prometheus
scrape_configs:
  - job_name: podtrace-agent
    # Prometheus negotiates OpenMetrics by default; keep exemplar storage on.
```

```
--enable-feature=exemplar-storage
```

A plain `text/plain; version=0.0.4` scrape still works and simply carries no
exemplars — a strict 0.0.4 parser would reject the exemplar syntax, so it is
omitted rather than risking the whole response.

In Grafana, point the Prometheus data source's *Exemplars* config at your
tracing data source with `trace_id` as the label name. That name is
conventional, not ours, so it is not something podtrace will rename.

### They are sparse by design

Only traffic carrying a `traceparent` produces an exemplar, and Prometheus
keeps at most one exemplar per bucket per scrape. Both facts point the same
way: a handful of sampled requests per interval is exactly enough, and
untraced traffic is still counted in full.

### Interaction with kernel-side aggregation

An exemplar needs a per-request trace id. Under
`kernelAggregation` (below) with the ring-buffer bypass armed, the counts come
from a BPF map and no per-request identity reaches userspace — so the L7,
network and DNS families carry **no exemplars** in that mode.

That is the trade `kernelAggregation`, on by default, makes. It is also
less costly than it first appears: the bypass only arms while no `PodTrace`
exists, so the moment anyone is actually diagnosing, events flow again and
exemplars come back with them. The gap is real only when your traces come
from the application's own OpenTelemetry SDK rather than from podtrace, and
you want the metric-to-trace jump while nobody is running a session.

## Kernel-side aggregation

By default the plane costs one ring-buffer crossing per observation, so a busy
node pays O(events) to produce metrics whose cost should be O(series). At 100
pods per node serving 10k requests per second that is roughly a million
kernel-to-userspace crossings a second, sampled or not — `samplePercent` is
applied after the crossing, so sampling reduces export cost while leaving the
expensive part intact.

With kernel aggregation, on by default, the probes fold each observation into
a BPF map instead. To turn it off, set it on the TracerConfig:

```yaml
apiVersion: podtrace.io/v1alpha1
kind: TracerConfig
metadata:
  name: default
spec:
  agent:
    metrics:
      enabled: true
      kernelAggregation: false
```

or `--set agent.metrics.kernelAggregation=false` at install. Turn
`agent.sockOpsRTT` off with it, for the reason given under network RTT.

### What changes, and what does not

Nothing about the exported surface. The same metric names carry the same label
keys, and a dashboard cannot tell which path served it, a test asserts both
paths produce identical series identities.

Not every probe aggregates in the kernel: some still ship each event through
the ring buffer. Each event records whether the kernel counted it, and the
agent counts exactly the ones it did not, into the same series. A family whose
emitters are mixed stays whole, and an event the kernel both counted and
shipped (while a PodTrace keeps the ring buffer open) is counted once.

Two differences are observable. The first is exemplars: they need a
per-request trace id, which no longer reaches userspace once the bypass is
armed. See
[Interaction with kernel-side aggregation](#interaction-with-kernel-side-aggregation).

The second is timing. The agent drains the kernel map every 10 seconds
(`PODTRACE_WORKLOAD_METRICS_DRAIN_INTERVAL`), so the aggregated counters and
histograms move in steps: flat between drains, then up by everything the drain
brought. Query them with `rate()` or `increase()` over at least a minute. Over
windows shorter than about two drain intervals, and with `irate()`, which only
looks at the last two samples, a steady workload reads as zero followed by a
spike. The totals are exact; only their timing is coarse. Shortening the drain
interval makes the steps smaller, at the cost of draining more often.
`podtrace status` times its reads to the drains, so its rates are
exact over any window.

Latency distributions are recorded as **Prometheus native-histogram schema-3
buckets**, indexed in the kernel with integer arithmetic. Schema 3 is the
schema a bucket factor of 1.1 resolves to, so the buckets are the ones the
event path would have produced.

The kernel indexes durations in units of 2^-30 seconds rather than
nanoseconds. One second is 10^9 ns, which is not a power of two, so no whole
number of buckets separates a nanosecond index from a seconds one; in 2^-30 s
units a second is exactly 2^30 and the two scales are 30 octaves apart, which
the agent removes on export. A test checks, across durations from 100ns to an
hour, that each one is exported in the bucket that actually contains it in
seconds. Below about 100ns integer rounding can place a duration one bucket
low; no probe measures anything that short.

Counters are simpler: a drained delta is an `Add` into the counter the event
path already owns.

### Draining

The map holds **deltas, not totals**. It is an LRU, so a node that meets more
peers than it holds evicts the coldest rows; if it carried running totals an
eviction would look like a counter reset and corrupt every `rate()` spanning
it. Draining means an eviction costs at most one partial interval.

`PODTRACE_WORKLOAD_METRICS_DRAIN_INTERVAL` (default `10s`) bounds how long an
observation waits before it is scrapeable. `podtrace_agent_kernel_agg_rows_total`
reports rows drained by outcome, `applied`, `unattributed`, `drain_failed`.

### The ring-buffer bypass

While no `PodTrace` CR is routing events, the probes skip the ring buffer
entirely for anything the map absorbed, so a metrics-only node generates no
per-event kernel-to-userspace traffic at all.

Two properties make that safe. Only an event the map actually recorded may be
skipped, so families the aggregation does not cover keep flowing to userspace
and turning the bypass on cannot silently lose an event type. And the bypass
lifts the instant a CR starts routing, the router notifies the agent on
publish rather than the agent waiting for a drain tick, so a diagnose session
never loses its opening seconds.

### The service map still works

Edges are fed from the kernel too. The peer address travels in the map key and
is resolved to a Service name at scrape time, the same join the event path
performs, so bypassing the ring buffer does not darken the topology on
exactly the nodes the bypass is meant to help.

## The series budget

The budget is a hard cap on distinct label combinations per node, enforced at
a single chokepoint that every observation passes through. When it is
reached, new series are refused and counted in
`podtrace_workload_metrics_series_dropped_total`; series already admitted keep
recording. A documented cap that is not enforced is not a cap.

The budget is shared by every namespace on the node, first come, first
served, with one exception: once it is spent, a namespace still holding less
than an equal share of it may draw on a reserve of a quarter of the budget.
Without that, one tenant with many small workloads, or a server answering
with many distinct status codes, could take the whole budget and blind every
namespace scheduled onto the node after it. A node running a single
namespace never touches the reserve, so the cap there is exactly
`seriesBudget`; across namespaces the ceiling is `1.25 × seriesBudget`.

The `40000` default is derived rather than guessed. Roughly 20 workloads ×
1.5 containers × 3 per-family variants is about 90 label combinations per
family, which across this surface's families lands near 7,000 series per node
with native histograms. The headroom above that covers the second name per
metric that OpenTelemetry-convention naming will add.

Sizing it for your own cluster:

```promql
# Series this plane holds, per node
podtrace_workload_metrics_series_active

# Whether anything is being refused
sum by (family) (rate(podtrace_workload_metrics_series_dropped_total[5m]))
```

### Series are evicted when their workload goes away

A series whose workload stops being observed is deleted after
`PODTRACE_WORKLOAD_METRICS_SERIES_TTL` (default 15 minutes), and
`podtrace_workload_metrics_series_reaped_total` counts the removals.

This is not a tidiness feature. Without it the plane leaks: a deleted
Deployment's series stay registered forever, so a cluster with ordinary
rollout churn accumulates dead series until the budget fills — and then
refuses new series for *live* workloads while still holding the dead ones.
The budget would end up spent on history.

Deleting rather than merely stopping updates also matters to the consumer:
a series that goes quiet keeps answering instant queries with its last
value until Prometheus staleness handling takes over.

If drops are non-zero, either raise the budget or narrow what the plane
observes — do not ignore it, because which series get refused depends on
arrival order and is therefore arbitrary.

The agent also logs once, at error level, on the transition into
exhaustion. There is deliberately **no** `TracerConfig` status condition for
this: `status.conditions` is keyed by type alone, so every agent on every
node would contend for the same entry and flap it as their individual
budgets filled at different times. A per-node status array would be needed
to express it correctly, and a rate-shaped signal like this is better served
by the counter above.

## Example queries

```promql
# Request rate per workload
sum by (namespace, workload) (
    rate(podtrace_workload_l7_requests_total[5m])
)

# Error ratio per workload
sum by (namespace, workload) (
    rate(podtrace_workload_l7_requests_total{outcome="error"}[5m])
) / sum by (namespace, workload) (
    rate(podtrace_workload_l7_requests_total[5m])
)

# p99 request duration, by protocol
histogram_quantile(0.99,
    sum by (namespace, workload, protocol, le) (
        rate(podtrace_workload_l7_request_duration_seconds_bucket[5m])
    )
)

# p99 for HTTP/3 traffic only — the query no other eBPF tool can answer
histogram_quantile(0.99,
    sum by (namespace, workload, le) (
        rate(podtrace_workload_l7_request_duration_seconds_bucket{protocol="http3"}[5m])
    )
)

# Egress throughput per workload
sum by (namespace, workload) (
    rate(podtrace_workload_network_bytes_total{direction="egress"}[5m])
)
```

## Related documents

- [continuous-inspections.md](continuous-inspections.md), the rules that act on this surface
- [metrics.md](metrics.md), the diagnostic surface and its naming rules
- [STABILITY.md](../STABILITY.md), what a version promises about metric names
- [crd-tracerconfig.md](crd-tracerconfig.md), agent fleet configuration
