package metricsexporter

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"golang.org/x/time/rate"

	"github.com/podtrace/podtrace/internal/events"
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
		[]string{"type", "process_name"},
	)

	latencyHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_latency_seconds",
			Help:    "Latency observed by podtrace.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name"},
	)

	dnsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_dns_latency_seconds_gauge",
			Help: "Latest DNS query latency per process.",
		},
		[]string{"type", "process_name"},
	)
	dnsHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_dns_latency_seconds_histogram",
			Help:    "Distribution of DNS query latencies per process.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name"},
	)

	fsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_fs_latency_seconds_gauge",
			Help: "Latest file system operation latency per process.",
		},
		[]string{"type", "process_name"},
	)
	fsHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_fs_latency_seconds_histogram",
			Help:    "Distribution of file system latencies per process and type.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name"},
	)

	cpuGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_cpu_block_seconds_gauge",
			Help: "Latest CPU block time per process.",
		},
		[]string{"type", "process_name"},
	)
	cpuHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "podtrace_cpu_block_seconds_histogram",
			Help:    "Distribution of CPU block times per process.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 20),
		},
		[]string{"type", "process_name"},
	)
	rttGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_rtt_latest_seconds",
			Help: "Most recent RTT observed by podtrace.",
		},
		[]string{"type", "process_name"},
	)

	latencyGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "podtrace_latency_latest_seconds",
			Help: "Most recent latency observed by podtrace.",
		},
		[]string{"type", "process_name"},
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
}

func HandleEvents(ch <-chan *events.Event) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Panic in metrics event handler: %v\n", r)
		}
	}()
	for e := range ch {
		if e == nil {
			continue
		}
		switch e.Type {
		case events.EventConnect:
			ExportTCPMetric(e)

		case events.EventTCPSend:
			ExportRTTMetric(e)

		case events.EventTCPRecv:
			ExportRTTMetric(e)

		case events.EventDNS:
			ExportDNSMetric(e)

		case events.EventWrite:
			ExportFileSystemMetric(e)

		case events.EventFsync:
			ExportFileSystemMetric(e)

		case events.EventSchedSwitch:
			ExportSchedSwitchMetric(e)
		}
	}
}

func ExportRTTMetric(e *events.Event) {
	rttSec := float64(e.LatencyNS) / 1e9
	rttHistogram.WithLabelValues(e.TypeString(), e.ProcessName).Observe(rttSec)
	rttGauge.WithLabelValues(e.TypeString(), e.ProcessName).Set(rttSec)
}

func ExportTCPMetric(e *events.Event) {
	latencySec := float64(e.LatencyNS) / 1e9
	latencyHistogram.WithLabelValues(e.TypeString(), e.ProcessName).Observe(latencySec)
	latencyGauge.WithLabelValues(e.TypeString(), e.ProcessName).Set(latencySec)
}

func ExportDNSMetric(e *events.Event) {

	latencySec := float64(e.LatencyNS) / 1e9
	dnsGauge.WithLabelValues(e.TypeString(), e.ProcessName).Set(latencySec)
	dnsHistogram.WithLabelValues(e.TypeString(), e.ProcessName).Observe(latencySec)
}

func ExportFileSystemMetric(e *events.Event) {

	latencySec := float64(e.LatencyNS) / 1e9
	fsGauge.WithLabelValues(e.TypeString(), e.ProcessName).Set(latencySec)
	fsHistogram.WithLabelValues(e.TypeString(), e.ProcessName).Observe(latencySec)

}

func ExportSchedSwitchMetric(e *events.Event) {

	blockSec := float64(e.LatencyNS) / 1e9
	cpuGauge.WithLabelValues(e.TypeString(), e.ProcessName).Set(blockSec)
	cpuHistogram.WithLabelValues(e.TypeString(), e.ProcessName).Observe(blockSec)

}

var (
	limiter        = rate.NewLimiter(rate.Every(time.Second/10), 20)
	maxRequestSize = int64(1024 * 1024)
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

	addr := os.Getenv("PODTRACE_METRICS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:3000"
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	srv := &Server{server: server}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Panic in metrics server: %v\n", r)
			}
		}()
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Metrics server error: %v\n", err)
		}
	}()

	return srv
}

func (s *Server) Shutdown() {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)
	}
}
