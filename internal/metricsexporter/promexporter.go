package metricsexporter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	pprofhttp "net/http/pprof"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type EventType uint32

var (
	rttHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_rtt_seconds",
			Help:    "RTT observed by Podtrace.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name", "namespace", "target_pod", "target_service"},
	)

	latencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_latency_seconds",
			Help:    "Latency observed by Podtrace.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name", "namespace", "target_pod", "target_service"},
	)

	dnsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_dns_latency_seconds_gauge",
			Help: "Latest DNS query latency per process.",
		},
		[]string{"type", "process_name", "namespace"},
	)
	dnsHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_dns_latency_seconds_histogram",
			Help:    "Distribution of DNS query latencies per process.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name", "namespace"},
	)

	fsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_fs_latency_seconds_gauge",
			Help: "Latest file system operation latency per process.",
		},
		[]string{"type", "process_name", "namespace"},
	)
	fsHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_fs_latency_seconds_histogram",
			Help:    "Distribution of file system latencies per process and type.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name", "namespace"},
	)

	cpuGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_cpu_block_seconds_gauge",
			Help: "Latest CPU block time per process.",
		},
		[]string{"type", "process_name", "namespace"},
	)
	cpuHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_cpu_block_seconds_histogram",
			Help:    "Distribution of CPU block times per process.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name", "namespace"},
	)
	rttGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_rtt_latest_seconds",
			Help: "Most recent RTT observed by Podtrace.",
		},
		[]string{"type", "process_name", "namespace", "target_pod", "target_service"},
	)

	latencyGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_latency_latest_seconds",
			Help: "Most recent latency observed by Podtrace.",
		},
		[]string{"type", "process_name", "namespace", "target_pod", "target_service"},
	)

	networkBytesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_network_bytes_total",
			Help: "Total bytes transferred over network (TCP/UDP send/receive). Use rate() to get bytes/second.",
		},
		[]string{"type", "process_name", "direction", "namespace", "target_pod", "target_service"},
	)

	filesystemBytesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_filesystem_bytes_total",
			Help: "Total bytes transferred via filesystem operations (read/write). Use rate() to get bytes/second.",
		},
		[]string{"type", "process_name", "operation", "namespace"},
	)

	ringBufferDropsCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "podtrace_ring_buffer_drops_total",
			Help: "Total number of events dropped due to ring buffer being full.",
		},
	)

	dnsDropsCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "podtrace_dns_drops_total",
			Help: "Total DNS records dropped.",
		},
	)

	l7DecoderDropsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_l7_decoder_drops_total",
			Help: "Header records or decoded sections the userspace L7 decoders discarded, " +
				"per decoder and reason.",
		},
		[]string{"decoder", "reason"},
	)

	l7DecoderRetainedBytesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_l7_decoder_retained_bytes",
			Help: "Bytes of traffic-controlled state an L7 decoder holds (HPACK windows, " +
				"partial header blocks, out-of-order records).",
		},
		[]string{"decoder"},
	)

	filteredEventDropsCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "podtrace_filtered_event_drops_total",
			Help: "Total events dropped because the userspace filtered-event channel was full.",
		},
	)

	teeAuxDropsCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "podtrace_event_tee_aux_drops_total",
			Help: "Total events dropped for a secondary consumer (metrics/tracing/profiling) because its fan-out channel was full. A non-zero rate means those consumers undercount relative to the primary diagnose report.",
		},
	)

	processCacheHitsCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "podtrace_process_cache_hits_total",
			Help: "Total number of process cache hits.",
		},
	)

	processCacheMissesCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "podtrace_process_cache_misses_total",
			Help: "Total number of process cache misses.",
		},
	)

	pidCacheHitsCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "podtrace_pid_cache_hits_total",
			Help: "Total number of PID cache hits.",
		},
	)

	pidCacheMissesCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "podtrace_pid_cache_misses_total",
			Help: "Total number of PID cache misses.",
		},
	)

	eventProcessingLatencyHistogram = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "podtrace_event_processing_latency_seconds",
			Help:    "Time taken to process events from ring buffer to event channel.",
			Buckets: prometheus.ExponentialBuckets(0.000001, 2, 20),
		},
	)

	errorRateCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_errors_total",
			Help: "Total number of errors by event type.",
		},
		[]string{"event_type", "error_code"},
	)

	attributionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_attribution_total",
			Help: "Process-identity attribution outcomes at event ingest, per source. " +
				"event_comm = comm arrived in the kernel event (kprobe/uprobe producers); " +
				"correlator = filled from the pid→comm table fed by kernel-context events; " +
				"proc_fallback = resolved by reading /proc at ingest (racy for short-lived processes); " +
				"none = unattributed. The event label buckets dns/quic (cgroup_skb producers, " +
				"the attribution gap) against everything else.",
		},
		[]string{"source", "event"},
	)

	attributionPidReuseCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "podtrace_attribution_pid_reuse_suspected_total",
			Help: "Attribution lookups rejected because the pid's cached identity " +
				"belonged to a different cgroup — the strongest observable signal " +
				"that the pid was recycled between capture and ingest.",
		},
	)

	tlsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_tls_handshake_latency_latest_seconds",
			Help: "Latest TLS handshake latency per process.",
		},
		[]string{"type", "process_name", "namespace"},
	)

	tlsHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_tls_handshake_latency_seconds",
			Help:    "Distribution of TLS handshake latencies per process.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name", "namespace"},
	)

	tlsHandshakesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_tls_handshakes_total",
			Help: "Total number of TLS handshakes.",
		},
		[]string{"type", "process_name", "namespace"},
	)

	resourceLimitBytesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_resource_limit_bytes",
			Help: "Resource limit in bytes (or CPU quota in microseconds).",
		},
		[]string{"resource_type", "namespace"},
	)

	resourceUsageBytesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_resource_usage_bytes",
			Help: "Current resource usage in bytes (or CPU time in microseconds).",
		},
		[]string{"resource_type", "namespace"},
	)

	resourceUtilizationPercentGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_resource_utilization_percent",
			Help: "Resource utilization percentage (usage/limit * 100).",
		},
		[]string{"resource_type", "namespace"},
	)

	resourceAlertLevelGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_resource_alert_level",
			Help: "Resource alert level: 0=none, 1=warning (80%), 2=critical (90%), 3=emergency (95%).",
		},
		[]string{"resource_type", "namespace"},
	)

	poolAcquiresCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_pool_acquires_total",
			Help: "Total number of connection pool acquires.",
		},
		[]string{"pool_id", "process_name", "namespace"},
	)

	poolReleasesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_pool_releases_total",
			Help: "Total number of connection pool releases.",
		},
		[]string{"pool_id", "process_name", "namespace"},
	)

	poolExhaustedCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_pool_exhausted_total",
			Help: "Total number of pool exhaustion events.",
		},
		[]string{"pool_id", "process_name", "namespace"},
	)

	poolWaitTimeHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_pool_wait_seconds",
			Help:    "Time waiting for connection during pool exhaustion.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		},
		[]string{"pool_id", "process_name", "namespace"},
	)

	eventChannelDepthGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_event_channel_depth",
			Help: "Current number of events buffered in the event processing channels.",
		},
		[]string{"channel"},
	)

	bpfMapUtilizationGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_bpf_map_utilization_ratio",
			Help: "Fill ratio of BPF hash maps (0.0–1.0). Values near 1.0 indicate map pressure.",
		},
		[]string{"map"},
	)

	redisLatencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_redis_latency_seconds",
			Help:    "Distribution of Redis command latencies.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15),
		},
		[]string{"command", "process_name", "namespace"},
	)

	memcachedLatencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_memcached_latency_seconds",
			Help:    "Distribution of Memcached operation latencies.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15),
		},
		[]string{"operation", "process_name", "namespace"},
	)

	fastcgiLatencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_fastcgi_latency_seconds",
			Help:    "Distribution of FastCGI request latencies.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15),
		},
		[]string{"method", "process_name", "namespace"},
	)

	grpcLatencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_grpc_latency_seconds",
			Help:    "Distribution of gRPC method call latencies.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15),
		},
		[]string{"method", "process_name", "namespace"},
	)

	kafkaLatencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_kafka_latency_seconds",
			Help:    "Distribution of Kafka produce/consume latencies.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15),
		},
		[]string{"operation", "topic", "process_name", "namespace"},
	)

	kafkaBytesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_kafka_bytes_total",
			Help: "Total bytes in Kafka produce/consume operations.",
		},
		[]string{"operation", "topic", "process_name", "namespace"},
	)

	// Profiling integration metrics.
	profilingGoroutinesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_profiling_goroutines",
			Help: "Number of goroutines observed in the last pprof goroutine profile of the target pod.",
		},
		[]string{"pod_ip", "state"}, // state: total | blocked
	)

	profilingAutoTriggersTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_profiling_auto_triggers_total",
			Help: "Number of times profiling was automatically triggered by a latency spike.",
		},
		[]string{"pod_ip"},
	)

	profilingFetchErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "podtrace_profiling_fetch_errors_total",
			Help: "Number of failed pprof endpoint fetch attempts.",
		},
		[]string{"pod_ip", "profile_type"},
	)
)

// allCollectors is this package's complete metric surface.
func allCollectors() []prometheus.Collector {
	return []prometheus.Collector{
		rttHistogram,
		latencyHistogram,
		rttGauge,
		latencyGauge,
		dnsHistogram,
		fsHistogram,
		cpuHistogram,
		dnsGauge,
		fsGauge,
		cpuGauge,
		networkBytesCounter,
		filesystemBytesCounter,
		ringBufferDropsCounter,
		dnsDropsCounter,
		filteredEventDropsCounter,
		l7DecoderDropsCounter,
		l7DecoderRetainedBytesGauge,
		teeAuxDropsCounter,
		processCacheHitsCounter,
		processCacheMissesCounter,
		pidCacheHitsCounter,
		pidCacheMissesCounter,
		eventProcessingLatencyHistogram,
		errorRateCounter,
		attributionCounter,
		attributionPidReuseCounter,
		tlsGauge,
		tlsHistogram,
		tlsHandshakesCounter,
		resourceLimitBytesGauge,
		resourceUsageBytesGauge,
		resourceUtilizationPercentGauge,
		resourceAlertLevelGauge,
		poolAcquiresCounter,
		poolReleasesCounter,
		poolExhaustedCounter,
		poolWaitTimeHistogram,
		eventChannelDepthGauge,
		bpfMapUtilizationGauge,
		redisLatencyHistogram,
		memcachedLatencyHistogram,
		fastcgiLatencyHistogram,
		grpcLatencyHistogram,
		kafkaLatencyHistogram,
		kafkaBytesCounter,
		profilingGoroutinesGauge,
		profilingAutoTriggersTotal,
		profilingFetchErrorsTotal,
	}
}

func init() {
	for _, c := range allCollectors() {
		prometheus.MustRegister(c)
	}
}

// RecordProfilingGoroutines records goroutine counts from the last pprof fetch.
func RecordProfilingGoroutines(podIP string, total, blocked int) {
	podIP = podIPCardinality.bound(podIP)
	profilingGoroutinesGauge.WithLabelValues(podIP, "total").Set(float64(total))
	profilingGoroutinesGauge.WithLabelValues(podIP, "blocked").Set(float64(blocked))
}

// RecordProfilingAutoTrigger increments the auto-trigger counter.
func RecordProfilingAutoTrigger(podIP string) {
	profilingAutoTriggersTotal.WithLabelValues(podIPCardinality.bound(podIP)).Inc()
}

// RecordProfilingFetchError increments the fetch error counter.
func RecordProfilingFetchError(podIP, profileType string) {
	profilingFetchErrorsTotal.WithLabelValues(podIPCardinality.bound(podIP), profileType).Inc()
}

func HandleEvents(ch <-chan *events.Event) {
	for e := range ch {
		if e == nil {
			continue
		}
		handleEventRecovered(e)
	}
}

// handleEventRecovered isolates a panic to the one event that caused it.
// A function-scope recover around the whole consumer loop meant a single
// poisoned event killed metrics consumption permanently — the gauges froze
// and every producer blocked on the full channel.
func handleEventRecovered(e *events.Event) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in metrics event handler; event skipped",
				zap.Any("panic", r),
				zap.String("event_type", e.TypeString()),
				zap.ByteString("stack", debug.Stack()))
		}
	}()
	HandleEvent(e)
}

func HandleEvent(e *events.Event) {
	HandleEventWithContext(e, nil)
}

// labelCardinalityLimiter caps the number of distinct values a
// traffic-derived label can mint. Labels like command/method/topic come
// straight off the traced wire (arbitrary URL paths, Redis command words,
// Kafka topics) and target_pod/pod_ip churn with the cluster — and Prometheus
// keeps one series (x 20 histogram buckets) per distinct value forever, since
// nothing here ever calls DeleteLabelValues. Without a cap a long-lived agent
// is a textbook exporter memory explosion. Values beyond the cap collapse
// into "other"; bounded staleness in exchange for bounded memory.
type labelCardinalityLimiter struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	limit int
}

func newLabelCardinalityLimiter(limit int) *labelCardinalityLimiter {
	return &labelCardinalityLimiter{seen: make(map[string]struct{}), limit: limit}
}

func (l *labelCardinalityLimiter) bound(value string) string {
	if value == "" {
		return value
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[value]; ok {
		return value
	}
	if len(l.seen) >= l.limit {
		return "other"
	}
	l.seen[value] = struct{}{}
	return value
}

var (
	commandCardinality   = newLabelCardinalityLimiter(config.MetricsLabelLimit)
	methodCardinality    = newLabelCardinalityLimiter(config.MetricsLabelLimit)
	topicCardinality     = newLabelCardinalityLimiter(config.MetricsLabelLimit)
	podCardinality       = newLabelCardinalityLimiter(config.MetricsPodLabelLimit)
	serviceCardinality   = newLabelCardinalityLimiter(config.MetricsPodLabelLimit)
	podIPCardinality     = newLabelCardinalityLimiter(config.MetricsPodLabelLimit)
	poolCardinality      = newLabelCardinalityLimiter(config.MetricsLabelLimit)
	processCardinality   = newLabelCardinalityLimiter(config.MetricsLabelLimit)
	errorCodeCardinality = newLabelCardinalityLimiter(config.MetricsLabelLimit)
)

func HandleEventWithContext(e *events.Event, k8sContext map[string]interface{}) {
	if e == nil {
		return
	}
	namespace := getLabel(k8sContext, "namespace", "")
	targetPod := podCardinality.bound(getLabel(k8sContext, "target_pod", ""))
	targetService := serviceCardinality.bound(getLabel(k8sContext, "target_service", ""))

	switch e.Type {
	case events.EventConnect:
		ExportTCPMetricWithContext(e, namespace, targetPod, targetService)

	case events.EventTCPSend:
		ExportRTTMetricWithContext(e, namespace, targetPod, targetService)
		ExportNetworkBandwidthMetricWithContext(e, "send", namespace, targetPod, targetService)

	case events.EventTCPRecv:
		ExportRTTMetricWithContext(e, namespace, targetPod, targetService)
		ExportNetworkBandwidthMetricWithContext(e, "recv", namespace, targetPod, targetService)

	case events.EventDNS:
		ExportDNSMetricWithContext(e, namespace)

	case events.EventWrite:
		ExportFileSystemMetricWithContext(e, namespace)
		ExportFilesystemBandwidthMetricWithContext(e, "write", namespace)

	case events.EventRead:
		ExportFileSystemMetricWithContext(e, namespace)
		ExportFilesystemBandwidthMetricWithContext(e, "read", namespace)

	case events.EventFsync:
		ExportFileSystemMetricWithContext(e, namespace)

	case events.EventUDPSend:
		ExportNetworkBandwidthMetricWithContext(e, "send", namespace, targetPod, targetService)

	case events.EventUDPRecv:
		ExportNetworkBandwidthMetricWithContext(e, "recv", namespace, targetPod, targetService)

	case events.EventSchedSwitch:
		ExportSchedSwitchMetricWithContext(e, namespace)

	case events.EventTLSHandshake:
		ExportTLSMetricWithContext(e, namespace)

	case events.EventResourceLimit:
		ExportResourceLimitMetricWithContext(e, namespace)

	case events.EventPoolAcquire:
		ExportPoolAcquireMetricWithContext(e, namespace)

	case events.EventPoolRelease:
		ExportPoolReleaseMetricWithContext(e, namespace)

	case events.EventPoolExhausted:
		ExportPoolExhaustedMetricWithContext(e, namespace)

	case events.EventRedisCmd:
		latSec := float64(e.LatencyNS) / 1e9
		cmd := commandCardinality.bound(e.Details)
		if cmd == "" {
			cmd = "unknown"
		}
		redisLatencyHistogram.WithLabelValues(cmd, boundProcessName(e), namespace).Observe(latSec)

	case events.EventMemcachedCmd:
		latSec := float64(e.LatencyNS) / 1e9
		op := commandCardinality.bound(e.Details)
		if op == "" {
			op = "unknown"
		}
		memcachedLatencyHistogram.WithLabelValues(op, boundProcessName(e), namespace).Observe(latSec)

	case events.EventFastCGIResp:
		latSec := float64(e.LatencyNS) / 1e9
		method := methodCardinality.bound(e.Details)
		if method == "" {
			method = "unknown"
		}
		fastcgiLatencyHistogram.WithLabelValues(method, boundProcessName(e), namespace).Observe(latSec)

	case events.EventGRPCMethod:
		latSec := float64(e.LatencyNS) / 1e9
		method := methodCardinality.bound(e.Target)
		if method == "" {
			method = "unknown"
		}
		grpcLatencyHistogram.WithLabelValues(method, boundProcessName(e), namespace).Observe(latSec)

	case events.EventKafkaProduce:
		latSec := float64(e.LatencyNS) / 1e9
		topic := topicCardinality.bound(e.Details)
		if topic == "" {
			topic = "unknown"
		}
		procName := boundProcessName(e)
		kafkaLatencyHistogram.WithLabelValues("produce", topic, procName, namespace).Observe(latSec)
		if e.Bytes > 0 {
			kafkaBytesCounter.WithLabelValues("produce", topic, procName, namespace).Add(float64(e.Bytes))
		}

	case events.EventKafkaFetch:
		latSec := float64(e.LatencyNS) / 1e9
		topic := topicCardinality.bound(e.Details)
		if topic == "" {
			topic = "unknown"
		}
		procName := boundProcessName(e)
		kafkaLatencyHistogram.WithLabelValues("fetch", topic, procName, namespace).Observe(latSec)
		if e.Bytes > 0 {
			kafkaBytesCounter.WithLabelValues("fetch", topic, procName, namespace).Add(float64(e.Bytes))
		}
	}
}

func getLabel(ctx map[string]interface{}, key, defaultValue string) string {
	if ctx == nil {
		return defaultValue
	}
	if val, ok := ctx[key].(string); ok && val != "" {
		return val
	}
	return defaultValue
}

func ExportRTTMetric(e *events.Event) {
	ExportRTTMetricWithContext(e, "", "", "")
}

func ExportRTTMetricWithContext(e *events.Event, namespace, targetPod, targetService string) {
	rttSec := float64(e.LatencyNS) / 1e9
	procName := boundProcessName(e)
	rttHistogram.WithLabelValues(e.TypeString(), procName, namespace, targetPod, targetService).Observe(rttSec)
	rttGauge.WithLabelValues(e.TypeString(), procName, namespace, targetPod, targetService).Set(rttSec)
}

func ExportTCPMetric(e *events.Event) {
	ExportTCPMetricWithContext(e, "", "", "")
}

func ExportTCPMetricWithContext(e *events.Event, namespace, targetPod, targetService string) {
	latencySec := float64(e.LatencyNS) / 1e9
	procName := boundProcessName(e)
	latencyHistogram.WithLabelValues(e.TypeString(), procName, namespace, targetPod, targetService).Observe(latencySec)
	latencyGauge.WithLabelValues(e.TypeString(), procName, namespace, targetPod, targetService).Set(latencySec)
}

func ExportDNSMetric(e *events.Event) {
	ExportDNSMetricWithContext(e, "")
}

func ExportDNSMetricWithContext(e *events.Event, namespace string) {
	latencySec := float64(e.LatencyNS) / 1e9
	procName := boundProcessName(e)
	dnsGauge.WithLabelValues(e.TypeString(), procName, namespace).Set(latencySec)
	dnsHistogram.WithLabelValues(e.TypeString(), procName, namespace).Observe(latencySec)
}

func ExportFileSystemMetric(e *events.Event) {
	ExportFileSystemMetricWithContext(e, "")
}

func ExportFileSystemMetricWithContext(e *events.Event, namespace string) {
	latencySec := float64(e.LatencyNS) / 1e9
	procName := boundProcessName(e)
	fsGauge.WithLabelValues(e.TypeString(), procName, namespace).Set(latencySec)
	fsHistogram.WithLabelValues(e.TypeString(), procName, namespace).Observe(latencySec)
}

func ExportSchedSwitchMetric(e *events.Event) {
	ExportSchedSwitchMetricWithContext(e, "")
}

func ExportSchedSwitchMetricWithContext(e *events.Event, namespace string) {
	blockSec := float64(e.LatencyNS) / 1e9
	procName := boundProcessName(e)
	cpuGauge.WithLabelValues(e.TypeString(), procName, namespace).Set(blockSec)
	cpuHistogram.WithLabelValues(e.TypeString(), procName, namespace).Observe(blockSec)
}

func ExportNetworkBandwidthMetric(e *events.Event, direction string) {
	ExportNetworkBandwidthMetricWithContext(e, direction, "", "", "")
}

func ExportNetworkBandwidthMetricWithContext(e *events.Event, direction, namespace, targetPod, targetService string) {
	if e.Bytes > 0 {
		networkBytesCounter.WithLabelValues(e.TypeString(), boundProcessName(e), direction, namespace, targetPod, targetService).Add(float64(e.Bytes))
	}
}

func ExportFilesystemBandwidthMetric(e *events.Event, operation string) {
	ExportFilesystemBandwidthMetricWithContext(e, operation, "")
}

func ExportFilesystemBandwidthMetricWithContext(e *events.Event, operation, namespace string) {
	if e.Bytes > 0 {
		filesystemBytesCounter.WithLabelValues(e.TypeString(), boundProcessName(e), operation, namespace).Add(float64(e.Bytes))
	}
}

func RecordRingBufferDrop() {
	ringBufferDropsCounter.Inc()
}

// RecordFilteredEventDrop counts an event dropped because the userspace
// filtered-event channel was full. This is a different failure mode from
// a kernel ring-buffer drop and must not inflate that metric.
func RecordFilteredEventDrop() {
	filteredEventDropsCounter.Inc()
}

// L7DecoderCollectors returns the L7 decoder metrics so a process serving its
// own registry (the agent) can expose them too.
func L7DecoderCollectors() []prometheus.Collector {
	return []prometheus.Collector{l7DecoderDropsCounter, l7DecoderRetainedBytesGauge}
}

// RecordL7DecoderDrops counts n records or sections an L7 decoder discarded.
func RecordL7DecoderDrops(decoder, reason string, n uint64) {
	if n == 0 {
		return
	}
	l7DecoderDropsCounter.WithLabelValues(decoder, reason).Add(float64(n))
}

// RecordL7DecoderRetainedBytes sets the traffic-controlled bytes a decoder holds.
func RecordL7DecoderRetainedBytes(decoder string, n int) {
	l7DecoderRetainedBytesGauge.WithLabelValues(decoder).Set(float64(n))
}

func RecordTeeAuxDrop() {
	teeAuxDropsCounter.Inc()
}

func AddDNSDrops(delta uint64) {
	if delta > 0 {
		dnsDropsCounter.Add(float64(delta))
	}
}

func RecordProcessCacheHit() {
	processCacheHitsCounter.Inc()
}

func RecordProcessCacheMiss() {
	processCacheMissesCounter.Inc()
}

func RecordPIDCacheHit() {
	pidCacheHitsCounter.Inc()
}

func RecordPIDCacheMiss() {
	pidCacheMissesCounter.Inc()
}

func RecordEventProcessingLatency(duration time.Duration) {
	eventProcessingLatencyHistogram.Observe(duration.Seconds())
}

func RecordError(eventType string, errorCode int32) {
	errorRateCounter.WithLabelValues(eventType, errorCodeCardinality.bound(fmt.Sprintf("%d", errorCode))).Inc()
}

// RecordAttribution counts one process-identity attribution outcome at
// event ingest.
func RecordAttribution(source, eventKind string) {
	attributionCounter.WithLabelValues(source, eventKind).Inc()
}

// RecordAttributionPidReuseSuspected counts one attribution lookup that
// was rejected on a cgroup mismatch.
func RecordAttributionPidReuseSuspected() {
	attributionPidReuseCounter.Inc()
}

func RecordChannelDepths(eventLen, filteredLen int) {
	eventChannelDepthGauge.WithLabelValues("event").Set(float64(eventLen))
	eventChannelDepthGauge.WithLabelValues("filtered").Set(float64(filteredLen))
}

func RecordBPFMapUtilization(mapName string, ratio float64) {
	bpfMapUtilizationGauge.WithLabelValues(mapName).Set(ratio)
}

var (
	limiter        = rate.NewLimiter(rate.Every(time.Second/time.Duration(config.RateLimitPerSec)), config.RateLimitBurst)
	maxRequestSize = int64(config.MaxRequestSize)
)

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxRequestSize {
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// addrIsLoopback reports whether the listen address is confined to the
// loopback interface. The previous guard only fired when the host parsed
// as a non-loopback IP — ":9090" (empty host = ALL interfaces), hostnames,
// and unparsable addresses all skipped it and bound publicly.
func addrIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false // empty host means listen on every interface
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

type Server struct {
	server   *http.Server
	stop     chan struct{}
	stopOnce sync.Once
}

const resetLatestGaugeInterval = 5 * time.Minute

// ResetLatestGauges clears the "latest value" gauges so a dead process's last
// sample stops being reported as the current value.
func ResetLatestGauges() {
	dnsGauge.Reset()
	fsGauge.Reset()
	cpuGauge.Reset()
	rttGauge.Reset()
	latencyGauge.Reset()
	tlsGauge.Reset()
}

// gaugeResetLoop clears the "latest" gauges on a fixed interval so a
// series whose source has gone away stops reporting its last value
// forever. Split out of StartServer so the interval is a parameter.
func gaugeResetLoop(stop <-chan struct{}, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ResetLatestGauges()
		}
	}
}

func StartServer() *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", securityHeadersMiddleware(rateLimitMiddleware(promhttp.Handler())))
	if config.MetricsEnablePprof() {
		wrap := func(h http.HandlerFunc) http.Handler {
			return securityHeadersMiddleware(rateLimitMiddleware(h))
		}
		mux.Handle("/debug/pprof/", wrap(pprofhttp.Index))
		mux.Handle("/debug/pprof/cmdline", wrap(pprofhttp.Cmdline))
		mux.Handle("/debug/pprof/profile", wrap(pprofhttp.Profile))
		mux.Handle("/debug/pprof/symbol", wrap(pprofhttp.Symbol))
		mux.Handle("/debug/pprof/trace", wrap(pprofhttp.Trace))
	}

	addr := config.GetMetricsAddress()

	if !addrIsLoopback(addr) && !config.AllowNonLoopbackMetrics() {
		logger.Warn("Rejecting non-loopback metrics address, falling back to default",
			zap.String("requested_addr", addr),
			zap.String("fallback", fmt.Sprintf("%s:%d", config.DefaultMetricsHost, config.DefaultMetricsPort)))
		addr = config.DefaultMetricsHost + ":" + fmt.Sprintf("%d", config.DefaultMetricsPort)
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  config.DefaultMetricsReadTimeout,
		WriteTimeout: config.DefaultMetricsWriteTimeout,
	}

	srv := &Server{server: server, stop: make(chan struct{})}

	go gaugeResetLoop(srv.stop, resetLatestGaugeInterval)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in metrics server",
					zap.Any("panic", r),
					zap.ByteString("stack", debug.Stack()))
			}
		}()
		if config.MetricsEnablePprof() {
			logger.Info("Prometheus metrics server includes /debug/pprof (PODTRACE_METRICS_ENABLE_PPROF=1)",
				zap.String("addr", addr))
		}
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Metrics server error", zap.Error(err))
		}
	}()

	return srv
}

func (s *Server) Shutdown() {
	s.stopOnce.Do(func() {
		if s.stop != nil {
			close(s.stop)
		}
	})
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultMetricsShutdownTimeout)
		defer cancel()
		_ = s.server.Shutdown(ctx)
	}
}

func ExportTLSMetric(e *events.Event) {
	ExportTLSMetricWithContext(e, "")
}

func ExportTLSMetricWithContext(e *events.Event, namespace string) {
	latencySec := float64(e.LatencyNS) / 1e9
	procName := boundProcessName(e)
	tlsGauge.WithLabelValues(e.TypeString(), procName, namespace).Set(latencySec)
	tlsHistogram.WithLabelValues(e.TypeString(), procName, namespace).Observe(latencySec)
	tlsHandshakesCounter.WithLabelValues(e.TypeString(), procName, namespace).Inc()
}

func ExportResourceLimitMetric(e *events.Event) {
	ExportResourceLimitMetricWithContext(e, "")
}

func ExportResourceLimitMetricWithContext(e *events.Event, namespace string) {
	if e == nil {
		return
	}

	resourceType := e.TCPState
	var resourceTypeLabel string
	switch resourceType {
	case 0:
		resourceTypeLabel = "cpu"
	case 1:
		resourceTypeLabel = "memory"
	case 2:
		resourceTypeLabel = "io"
	default:
		resourceTypeLabel = "unknown"
	}

	utilization := float64(e.Error)

	usageBytes := float64(e.Bytes)

	var limitBytes float64
	if utilization > 0 {
		limitBytes = (usageBytes * 100.0) / utilization
	}

	// Set metrics
	resourceLimitBytesGauge.WithLabelValues(resourceTypeLabel, namespace).Set(limitBytes)
	resourceUsageBytesGauge.WithLabelValues(resourceTypeLabel, namespace).Set(usageBytes)
	resourceUtilizationPercentGauge.WithLabelValues(resourceTypeLabel, namespace).Set(utilization)

	// Determine alert level
	var alertLevel float64
	if utilization >= 95 {
		alertLevel = 3 // Emergency
	} else if utilization >= 90 {
		alertLevel = 2 // Critical
	} else if utilization >= 80 {
		alertLevel = 1 // Warning
	} else {
		alertLevel = 0 // None
	}
	resourceAlertLevelGauge.WithLabelValues(resourceTypeLabel, namespace).Set(alertLevel)
}

// ExportResourceMetrics exports metrics directly from ResourceMonitor
// This allows periodic updates even when no events are emitted
func ExportResourceMetrics(resourceType string, namespace string, limitBytes, usageBytes uint64, utilizationPercent float64, alertLevel uint32) {
	resourceLimitBytesGauge.WithLabelValues(resourceType, namespace).Set(float64(limitBytes))
	resourceUsageBytesGauge.WithLabelValues(resourceType, namespace).Set(float64(usageBytes))
	resourceUtilizationPercentGauge.WithLabelValues(resourceType, namespace).Set(utilizationPercent)
	resourceAlertLevelGauge.WithLabelValues(resourceType, namespace).Set(float64(alertLevel))
}

// boundProcessName caps process_name label cardinality.
func boundProcessName(e *events.Event) string {
	return processCardinality.bound(e.ProcessName)
}

// poolLabels resolves the (bounded) pool_id and process_name label values so
// arbitrary pool identifiers and process names cannot grow series without
// bound, matching how every other traffic-derived label is capped.
func poolLabels(e *events.Event) (poolID, processName string) {
	poolID = e.Target
	if poolID == "" {
		poolID = "default"
	}
	return poolCardinality.bound(poolID), boundProcessName(e)
}

func ExportPoolAcquireMetricWithContext(e *events.Event, namespace string) {
	poolID, processName := poolLabels(e)
	poolAcquiresCounter.WithLabelValues(poolID, processName, namespace).Inc()
}

func ExportPoolReleaseMetricWithContext(e *events.Event, namespace string) {
	poolID, processName := poolLabels(e)
	poolReleasesCounter.WithLabelValues(poolID, processName, namespace).Inc()
}

func ExportPoolExhaustedMetricWithContext(e *events.Event, namespace string) {
	poolID, processName := poolLabels(e)
	waitTimeSec := float64(e.LatencyNS) / 1e9
	poolExhaustedCounter.WithLabelValues(poolID, processName, namespace).Inc()
	poolWaitTimeHistogram.WithLabelValues(poolID, processName, namespace).Observe(waitTimeSec)
}
