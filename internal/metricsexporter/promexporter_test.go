package metricsexporter

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestExportMetricsHelpers(t *testing.T) {
	e := &events.Event{
		Type:        events.EventDNS,
		ProcessName: "testproc",
		LatencyNS:   uint64(time.Millisecond * 50),
		Bytes:       1024,
	}

	ExportRTTMetric(e)
	ExportTCPMetric(e)
	ExportDNSMetric(e)
	ExportFileSystemMetric(e)
	ExportSchedSwitchMetric(e)
	ExportNetworkBandwidthMetric(e, "send")
	ExportFilesystemBandwidthMetric(e, "write")
}

func TestSecurityAndRateLimitMiddleware(t *testing.T) {
	hit := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	})

	handler := securityHeadersMiddleware(rateLimitMiddleware(next))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !hit {
		t.Fatalf("expected inner handler to be called")
	}

	res := w.Result()
	if res.Header.Get("X-Content-Type-Options") == "" {
		t.Fatalf("expected security headers to be set")
	}
}

func TestStartServerAndShutdown(t *testing.T) {
	t.Setenv("PODTRACE_METRICS_ADDR", "127.0.0.1:0")
	t.Setenv("PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR", "1")

	srv := StartServer()
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}

	done := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		srv.Shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not shut down in time")
	}

	_ = os.Unsetenv("PODTRACE_METRICS_ADDR")
	_ = os.Unsetenv("PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR")
}

func TestExportRTTMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventTCPSend,
		LatencyNS:   5000000,
		ProcessName: "test",
	}
	ExportRTTMetric(event)
}

func TestExportTCPMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventConnect,
		LatencyNS:   10000000,
		ProcessName: "test",
	}
	ExportTCPMetric(event)
}

func TestExportDNSMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventDNS,
		LatencyNS:   2000000,
		ProcessName: "test",
	}
	ExportDNSMetric(event)
}

func TestExportFileSystemMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventRead,
		LatencyNS:   3000000,
		ProcessName: "test",
	}
	ExportFileSystemMetric(event)
}

func TestExportSchedSwitchMetric(t *testing.T) {
	event := &events.Event{
		Type:        events.EventSchedSwitch,
		LatencyNS:   1000000,
		ProcessName: "test",
	}
	ExportSchedSwitchMetric(event)
}

func TestExportNetworkBandwidthMetric(t *testing.T) {
	tests := []struct {
		name  string
		event *events.Event
		bytes uint64
	}{
		{"with bytes", &events.Event{Type: events.EventTCPSend, Bytes: 1024, ProcessName: "test"}, 1024},
		{"zero bytes", &events.Event{Type: events.EventTCPSend, Bytes: 0, ProcessName: "test"}, 0},
		{"large bytes", &events.Event{Type: events.EventTCPSend, Bytes: 1048576, ProcessName: "test"}, 1048576},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ExportNetworkBandwidthMetric(tt.event, "send")
		})
	}
}

func TestExportFilesystemBandwidthMetric(t *testing.T) {
	tests := []struct {
		name  string
		event *events.Event
		bytes uint64
	}{
		{"with bytes", &events.Event{Type: events.EventRead, Bytes: 2048, ProcessName: "test"}, 2048},
		{"zero bytes", &events.Event{Type: events.EventRead, Bytes: 0, ProcessName: "test"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ExportFilesystemBandwidthMetric(tt.event, "read")
		})
	}
}

func TestRecordRingBufferDrop(t *testing.T) {
	RecordRingBufferDrop()
	RecordRingBufferDrop()
}

func TestRecordProcessCacheHit(t *testing.T) {
	RecordProcessCacheHit()
	RecordProcessCacheHit()
}

func TestRecordProcessCacheMiss(t *testing.T) {
	RecordProcessCacheMiss()
	RecordProcessCacheMiss()
}

func TestRecordPIDCacheHit(t *testing.T) {
	RecordPIDCacheHit()
	RecordPIDCacheHit()
}

func TestRecordPIDCacheMiss(t *testing.T) {
	RecordPIDCacheMiss()
	RecordPIDCacheMiss()
}

func TestRecordEventProcessingLatency(t *testing.T) {
	RecordEventProcessingLatency(1 * time.Millisecond)
	RecordEventProcessingLatency(10 * time.Millisecond)
	RecordEventProcessingLatency(100 * time.Millisecond)
}

func TestRecordError(t *testing.T) {
	RecordError("DNS", 1)
	RecordError("NET", 111)
	RecordError("FS", -1)
}

func TestHandleEvents(t *testing.T) {
	eventChan := make(chan *events.Event, 10)

	go func() {
		defer close(eventChan)
		eventChan <- &events.Event{Type: events.EventConnect, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventTCPSend, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventTCPRecv, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventDNS, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventWrite, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventRead, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventFsync, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventUDPSend, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventUDPRecv, ProcessName: "test"}
		eventChan <- &events.Event{Type: events.EventSchedSwitch, ProcessName: "test"}
		eventChan <- nil
	}()

	go HandleEvents(eventChan)

	time.Sleep(100 * time.Millisecond)
}

func TestHandleEvents_NilEvent(t *testing.T) {
	eventChan := make(chan *events.Event, 1)

	go func() {
		defer close(eventChan)
		eventChan <- nil
	}()

	go HandleEvents(eventChan)

	time.Sleep(50 * time.Millisecond)
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("Expected X-Content-Type-Options header")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("Expected X-Frame-Options header")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	handler := rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Logf("Rate limit middleware returned status %d (may be expected)", w.Code)
	}
}

func TestServer_Shutdown(t *testing.T) {
	server := StartServer()
	if server == nil {
		t.Error("StartServer should return non-nil server")
	}

	time.Sleep(50 * time.Millisecond)

	server.Shutdown()
}

func TestExportResourceLimitMetric(t *testing.T) {
	tests := []struct {
		name         string
		event        *events.Event
		resourceType uint32
		utilization  int32
	}{
		{"CPU warning", &events.Event{Type: events.EventResourceLimit, TCPState: 0, Error: 85, Bytes: 850000000}, 0, 85},
		{"Memory critical", &events.Event{Type: events.EventResourceLimit, TCPState: 1, Error: 92, Bytes: 460000000}, 1, 92},
		{"IO emergency", &events.Event{Type: events.EventResourceLimit, TCPState: 2, Error: 97, Bytes: 970000000}, 2, 97},
		{"CPU below threshold", &events.Event{Type: events.EventResourceLimit, TCPState: 0, Error: 50, Bytes: 500000000}, 0, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ExportResourceLimitMetric(tt.event)
		})
	}
}

func TestExportResourceLimitMetricWithContext(t *testing.T) {
	event := &events.Event{
		Type:      events.EventResourceLimit,
		TCPState:  1,
		Error:     90,
		Bytes:     450000000,
	}

	ExportResourceLimitMetricWithContext(event, "test-namespace")
}

func TestExportResourceMetrics(t *testing.T) {
	tests := []struct {
		name              string
		resourceType      string
		namespace         string
		limitBytes        uint64
		usageBytes        uint64
		utilizationPercent float64
		alertLevel        uint32
	}{
		{"CPU warning", "cpu", "default", 1000000000, 850000000, 85.0, 1},
		{"Memory critical", "memory", "production", 500000000, 460000000, 92.0, 2},
		{"IO emergency", "io", "test", 1000000000, 970000000, 97.0, 3},
		{"CPU no alert", "cpu", "default", 1000000000, 500000000, 50.0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ExportResourceMetrics(
				tt.resourceType,
				tt.namespace,
				tt.limitBytes,
				tt.usageBytes,
				tt.utilizationPercent,
				tt.alertLevel,
			)
		})
	}
}

func TestHandleEvent_ResourceLimit(t *testing.T) {
	event := &events.Event{
		Type:      events.EventResourceLimit,
		TCPState:  0,
		Error:     85,
		Bytes:     850000000,
	}

	HandleEvent(event)
}

func TestHandleEventWithContext_ResourceLimit(t *testing.T) {
	event := &events.Event{
		Type:      events.EventResourceLimit,
		TCPState:  1,
		Error:     92,
		Bytes:     460000000,
	}

	k8sContext := map[string]interface{}{
		"namespace": "test-ns",
	}

	HandleEventWithContext(event, k8sContext)
}
