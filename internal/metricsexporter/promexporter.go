package metricsexporter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type EventType uint32

var (
	rttHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_rtt_seconds",
			Help:    "RTT observed by podtrace.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name", "namespace", "target_pod", "target_service"},
	)

	latencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_latency_seconds",
			Help:    "Latency observed by podtrace.",
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
			Help: "Most recent RTT observed by podtrace.",
		},
		[]string{"type", "process_name", "namespace", "target_pod", "target_service"},
	)

	latencyGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_latency_latest_seconds",
			Help: "Most recent latency observed by podtrace.",
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
)

func init() {

	prometheus.MustRegister(rttHistogram)
	prometheus.MustRegister(latencyHistogram)
	prometheus.MustRegister(rttGauge)
	prometheus.MustRegister(latencyGauge)
	prometheus.MustRegister(dnsHistogram)
	prometheus.MustRegister(fsHistogram)
	prometheus.MustRegister(cpuHistogram)
	prometheus.MustRegister(dnsGauge)
	prometheus.MustRegister(fsGauge)
	prometheus.MustRegister(cpuGauge)
	prometheus.MustRegister(networkBytesCounter)
	prometheus.MustRegister(filesystemBytesCounter)
	prometheus.MustRegister(ringBufferDropsCounter)
	prometheus.MustRegister(processCacheHitsCounter)
	prometheus.MustRegister(processCacheMissesCounter)
	prometheus.MustRegister(pidCacheHitsCounter)
	prometheus.MustRegister(pidCacheMissesCounter)
	prometheus.MustRegister(eventProcessingLatencyHistogram)
	prometheus.MustRegister(errorRateCounter)
	prometheus.MustRegister(tlsGauge)
	prometheus.MustRegister(tlsHistogram)
	prometheus.MustRegister(tlsHandshakesCounter)
	prometheus.MustRegister(resourceLimitBytesGauge)
	prometheus.MustRegister(resourceUsageBytesGauge)
	prometheus.MustRegister(resourceUtilizationPercentGauge)
	prometheus.MustRegister(resourceAlertLevelGauge)
}

func HandleEvents(ch <-chan *events.Event) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in metrics event handler", zap.Any("panic", r))
		}
	}()
	for e := range ch {
		if e == nil {
			continue
		}
		HandleEvent(e)
	}
}

func HandleEvent(e *events.Event) {
	HandleEventWithContext(e, nil)
}

func HandleEventWithContext(e *events.Event, k8sContext map[string]interface{}) {
	if e == nil {
		return
	}
	namespace := getLabel(k8sContext, "namespace", "")
	targetPod := getLabel(k8sContext, "target_pod", "")
	targetService := getLabel(k8sContext, "target_service", "")

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
	rttHistogram.WithLabelValues(e.TypeString(), e.ProcessName, namespace, targetPod, targetService).Observe(rttSec)
	rttGauge.WithLabelValues(e.TypeString(), e.ProcessName, namespace, targetPod, targetService).Set(rttSec)
}

func ExportTCPMetric(e *events.Event) {
	ExportTCPMetricWithContext(e, "", "", "")
}

func ExportTCPMetricWithContext(e *events.Event, namespace, targetPod, targetService string) {
	latencySec := float64(e.LatencyNS) / 1e9
	latencyHistogram.WithLabelValues(e.TypeString(), e.ProcessName, namespace, targetPod, targetService).Observe(latencySec)
	latencyGauge.WithLabelValues(e.TypeString(), e.ProcessName, namespace, targetPod, targetService).Set(latencySec)
}

func ExportDNSMetric(e *events.Event) {
	ExportDNSMetricWithContext(e, "")
}

func ExportDNSMetricWithContext(e *events.Event, namespace string) {
	latencySec := float64(e.LatencyNS) / 1e9
	dnsGauge.WithLabelValues(e.TypeString(), e.ProcessName, namespace).Set(latencySec)
	dnsHistogram.WithLabelValues(e.TypeString(), e.ProcessName, namespace).Observe(latencySec)
}

func ExportFileSystemMetric(e *events.Event) {
	ExportFileSystemMetricWithContext(e, "")
}

func ExportFileSystemMetricWithContext(e *events.Event, namespace string) {
	latencySec := float64(e.LatencyNS) / 1e9
	fsGauge.WithLabelValues(e.TypeString(), e.ProcessName, namespace).Set(latencySec)
	fsHistogram.WithLabelValues(e.TypeString(), e.ProcessName, namespace).Observe(latencySec)
}

func ExportSchedSwitchMetric(e *events.Event) {
	ExportSchedSwitchMetricWithContext(e, "")
}

func ExportSchedSwitchMetricWithContext(e *events.Event, namespace string) {
	blockSec := float64(e.LatencyNS) / 1e9
	cpuGauge.WithLabelValues(e.TypeString(), e.ProcessName, namespace).Set(blockSec)
	cpuHistogram.WithLabelValues(e.TypeString(), e.ProcessName, namespace).Observe(blockSec)
}

func ExportNetworkBandwidthMetric(e *events.Event, direction string) {
	ExportNetworkBandwidthMetricWithContext(e, direction, "", "", "")
}

func ExportNetworkBandwidthMetricWithContext(e *events.Event, direction, namespace, targetPod, targetService string) {
	if e.Bytes > 0 {
		networkBytesCounter.WithLabelValues(e.TypeString(), e.ProcessName, direction, namespace, targetPod, targetService).Add(float64(e.Bytes))
	}
}

func ExportFilesystemBandwidthMetric(e *events.Event, operation string) {
	ExportFilesystemBandwidthMetricWithContext(e, operation, "")
}

func ExportFilesystemBandwidthMetricWithContext(e *events.Event, operation, namespace string) {
	if e.Bytes > 0 {
		filesystemBytesCounter.WithLabelValues(e.TypeString(), e.ProcessName, operation, namespace).Add(float64(e.Bytes))
	}
}

func RecordRingBufferDrop() {
	ringBufferDropsCounter.Inc()
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
	errorRateCounter.WithLabelValues(eventType, fmt.Sprintf("%d", errorCode)).Inc()
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

type Server struct {
	server *http.Server
}

func StartServer() *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", securityHeadersMiddleware(rateLimitMiddleware(promhttp.Handler())))

	addr := config.GetMetricsAddress()

	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
			if !config.AllowNonLoopbackMetrics() {
				logger.Warn("Rejecting non-loopback metrics address, falling back to default",
					zap.String("requested_addr", addr),
					zap.String("fallback", fmt.Sprintf("%s:%d", config.DefaultMetricsHost, config.DefaultMetricsPort)))
				addr = config.DefaultMetricsHost + ":" + fmt.Sprintf("%d", config.DefaultMetricsPort)
			}
		}
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  config.DefaultMetricsReadTimeout,
		WriteTimeout: config.DefaultMetricsWriteTimeout,
	}

	srv := &Server{server: server}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in metrics server", zap.Any("panic", r))
			}
		}()
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Metrics server error", zap.Error(err))
		}
	}()

	return srv
}

func (s *Server) Shutdown() {
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
	tlsGauge.WithLabelValues(e.TypeString(), e.ProcessName, namespace).Set(latencySec)
	tlsHistogram.WithLabelValues(e.TypeString(), e.ProcessName, namespace).Observe(latencySec)
	tlsHandshakesCounter.WithLabelValues(e.TypeString(), e.ProcessName, namespace).Inc()
}

func ExportResourceLimitMetric(e *events.Event) {
	ExportResourceLimitMetricWithContext(e, "")
}

func ExportResourceLimitMetricWithContext(e *events.Event, namespace string) {
	if e == nil {
		return
	}

	// Resource type is stored in TCPState field
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

	// Utilization percentage is stored in Error field
	utilization := float64(e.Error)

	// Current usage is stored in Bytes field
	usageBytes := float64(e.Bytes)

	// Calculate limit from usage and utilization
	// limit = (usage * 100) / utilization
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
