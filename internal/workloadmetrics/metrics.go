// Package workloadmetrics aggregates observed traffic into the continuous
// Prometheus surface documented in docs/continuous-metrics.md.
package workloadmetrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

const metricPrefix = "podtrace_workload_"

const defaultAttributeCardinality = 50

// latencyBuckets spans 500us to 30s in twelve buckets.
var latencyBuckets = []float64{
	0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5, 30,
}

var defaultBaseLabels = []string{"namespace", "workload", "workload_kind", "container"}

// baseLabelNames returns the base label set for the given options.
func baseLabelNames(opts Options) []string {
	names := make([]string, 0, len(defaultBaseLabels)+2)
	names = append(names, defaultBaseLabels...)
	if opts.IncludePodLabel {
		names = append(names, "pod")
	}
	if opts.IncludeProcessLabel {
		names = append(names, "process")
	}
	return names
}

// collectors is the complete set of metrics this package exposes.
type collectors struct {
	l7Requests *prometheus.CounterVec
	l7Duration *prometheus.HistogramVec

	networkLatency *prometheus.HistogramVec
	networkBytes   *prometheus.CounterVec

	networkConnections  *prometheus.CounterVec
	networkRetransmits  *prometheus.CounterVec
	networkDeviceErrors *prometheus.CounterVec

	networkRTT *prometheus.HistogramVec

	lockContention *prometheus.HistogramVec

	dnsLatency *prometheus.HistogramVec
	dnsLookups *prometheus.CounterVec

	filesystemLatency *prometheus.HistogramVec
	filesystemBytes   *prometheus.CounterVec

	cpuBlocked  *prometheus.HistogramVec
	cpuRunqueue *prometheus.HistogramVec

	tlsHandshakeDuration *prometheus.HistogramVec

	errors *prometheus.CounterVec

	eventsTotal   *prometheus.CounterVec
	seriesDropped *prometheus.CounterVec
	seriesActive  prometheus.Gauge
	seriesReaped  prometheus.Counter

	sat saturationCollectors

	kernelAggregation bool
}

// familyLookup resolves the short family name recorded against an admitted
// series back to the collector that owns it, so the series can be deleted
// when the workload behind it is gone.
func (c *collectors) histogramFor(family string) (*prometheus.HistogramVec, bool) {
	switch family {
	case "l7_request_duration_seconds":
		return c.l7Duration, true
	case "network_latency_seconds":
		return c.networkLatency, true
	case "dns_latency_seconds":
		return c.dnsLatency, true
	case "filesystem_latency_seconds":
		return c.filesystemLatency, true
	case "cpu_blocked_seconds":
		return c.cpuBlocked, true
	case "cpu_runqueue_latency_seconds":
		return c.cpuRunqueue, true
	case "lock_contention_seconds":
		return c.lockContention, true
	case "network_rtt_seconds":
		return c.networkRTT, true
	case "tls_handshake_duration_seconds":
		return c.tlsHandshakeDuration, true
	default:
		return c.sat.histogramFor(family)
	}
}

func (c *collectors) counterFor(family string) (*prometheus.CounterVec, bool) {
	switch family {
	case "l7_requests_total":
		return c.l7Requests, true
	case "network_bytes_total":
		return c.networkBytes, true
	case "network_connections_total":
		return c.networkConnections, true
	case "network_retransmits_total":
		return c.networkRetransmits, true
	case "network_device_errors_total":
		return c.networkDeviceErrors, true
	case "filesystem_bytes_total":
		return c.filesystemBytes, true
	case "dns_lookups_total":
		return c.dnsLookups, true
	case "errors_total":
		return c.errors, true
	default:
		return c.sat.counterFor(family)
	}
}

func histogramOpts(name, help string, native bool) prometheus.HistogramOpts {
	opts := prometheus.HistogramOpts{
		Name:    metricPrefix + name,
		Help:    help,
		Buckets: latencyBuckets,
	}
	if native {
		opts.NativeHistogramBucketFactor = 1.1
		opts.NativeHistogramMaxBucketNumber = 160
	}
	return opts
}

func newCollectors(opts Options) *collectors {
	native := opts.NativeHistograms
	kernelAgg := opts.KernelAggregation
	base := baseLabelNames(opts)
	withBase := func(extra ...string) []string {
		out := make([]string, 0, len(base)+len(extra))
		out = append(out, base...)
		out = append(out, extra...)
		return out
	}
	return &collectors{
		kernelAggregation: kernelAgg,
		sat:               newSaturationCollectors(native, withBase),
		l7Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "l7_requests_total",
			Help: "Application-layer requests observed, by protocol and outcome. Use rate() for throughput and the status_class label for error ratio.",
		}, withBase("protocol", "status_class", "outcome")),

		l7Duration: prometheus.NewHistogramVec(
			histogramOpts("l7_request_duration_seconds",
				"Distribution of application-layer request durations, by protocol.", native),
			withBase("protocol"),
		),

		networkLatency: prometheus.NewHistogramVec(
			histogramOpts("network_latency_seconds",
				"Distribution of socket send and receive latency.", native),
			withBase("direction", "transport"),
		),

		networkBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "network_bytes_total",
			Help: "Bytes transferred over sockets. Use rate() for bytes per second.",
		}, withBase("direction", "transport")),

		networkConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "network_connections_total",
			Help: "Outbound connection attempts, by transport and outcome, each counted once when its handshake completes or fails. A peer refusing the connection is an error here even though connect() itself returned 0. The denominator the connection failure rate needs.",
		}, withBase("transport", "outcome")),

		networkRetransmits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "network_retransmits_total",
			Help: "TCP segments retransmitted, from the tcp_retransmit_skb tracepoint. Rising here while the application's own latency is flat is the wire, not the workload.",
		}, withBase()),

		networkDeviceErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "network_device_errors_total",
			Help: "Transmits the network device rejected, from net_dev_xmit with a non-zero return. Counted in errors_total as well; this family is what separates them from connection failures.",
		}, withBase()),

		networkRTT: prometheus.NewHistogramVec(
			histogramOpts("network_rtt_seconds",
				"Distribution of the kernel's own smoothed round-trip time, read from tcp_sock via sock_ops. Unlike network_latency_seconds this excludes time the peer or the application spent thinking, so it is the wire and nothing else. Absent unless the sock_ops hook is enabled and attached.", native),
			withBase(),
		),

		cpuRunqueue: prometheus.NewHistogramVec(
			histogramOpts("cpu_runqueue_latency_seconds",
				"Distribution of time a workload spent runnable but not running, measured only across preemptions. This is CPU contention: the workload had work to do and no CPU to do it on. cpu_blocked_seconds counts every departure from the CPU including voluntary sleeps, so an idle process scores high there and zero here.", native),
			withBase(),
		),

		lockContention: prometheus.NewHistogramVec(
			histogramOpts("lock_contention_seconds",
				"Distribution of time spent waiting on a futex or pthread mutex. Read alongside cpu_blocked_seconds: one is waiting for a lock, the other for a CPU, and they need different fixes.", native),
			withBase(),
		),

		dnsLatency: prometheus.NewHistogramVec(
			histogramOpts("dns_latency_seconds",
				"Distribution of DNS resolution latency.", native),
			withBase(),
		),

		dnsLookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "dns_lookups_total",
			Help: "DNS lookups, by answer: NOERROR, NXDOMAIN, SERVFAIL, REFUSED, other (any other rcode or resolver error), or timeout (no answer). NXDOMAIN is an answer, not a failure: search-domain expansion makes several per lookup.",
		}, withBase("rcode")),

		filesystemLatency: prometheus.NewHistogramVec(
			histogramOpts("filesystem_latency_seconds",
				"Distribution of filesystem operation latency, by operation.", native),
			withBase("operation"),
		),

		filesystemBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "filesystem_bytes_total",
			Help: "Bytes read from and written to the filesystem. Use rate() for bytes per second.",
		}, withBase("operation")),

		cpuBlocked: prometheus.NewHistogramVec(
			histogramOpts("cpu_blocked_seconds",
				"Distribution of time spent off-CPU waiting to be scheduled.", native),
			withBase(),
		),

		tlsHandshakeDuration: prometheus.NewHistogramVec(
			histogramOpts("tls_handshake_duration_seconds",
				"Distribution of TLS handshake durations.", native),
			withBase(),
		),

		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "errors_total",
			Help: "Observed operations that failed, by event kind.",
		}, withBase("kind")),

		eventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "metrics_events_total",
			Help: "Events reaching this plane, by outcome: aggregated, unattributed (no pod metadata), excluded (namespace in excludeNamespaces), or ignored (no family maps to the event type).",
		}, []string{"outcome"}),

		seriesDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "metrics_series_dropped_total",
			Help: "Observations discarded because admitting a new series would exceed the per-node budget, by family.",
		}, []string{"family"}),

		seriesActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: metricPrefix + "metrics_series_active",
			Help: "Distinct label combinations currently held by this plane, counted against the per-node budget.",
		}),

		seriesReaped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricPrefix + "metrics_series_reaped_total",
			Help: "Series removed after their workload stopped being observed, freeing budget.",
		}),
	}
}

func (c *collectors) all() []prometheus.Collector {
	out := []prometheus.Collector{
		c.l7Requests,
		c.networkBytes,
		c.networkConnections,
		c.networkRetransmits,
		c.networkDeviceErrors,
		c.filesystemBytes,
		c.dnsLookups,
		c.errors,
		c.eventsTotal,
		c.seriesDropped,
		c.seriesActive,
		c.seriesReaped,
	}
	if !c.kernelAggregation {
		out = append(out,
			c.l7Duration,
			c.networkLatency,
			c.dnsLatency,
			c.filesystemLatency,
			c.cpuBlocked,
			c.cpuRunqueue,
			c.networkRTT,
			c.lockContention,
			c.tlsHandshakeDuration,
		)
		out = append(out, c.sat.histograms()...)
	}
	return append(out, c.sat.all()...)
}

func (c *collectors) register(reg prometheus.Registerer) error {
	for _, collector := range c.all() {
		if err := reg.Register(collector); err != nil {
			return fmt.Errorf("register workload metrics: %w", err)
		}
	}
	return nil
}
