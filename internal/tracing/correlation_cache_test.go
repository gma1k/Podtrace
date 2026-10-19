package tracing

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func TestCorrelationCache_StoreEvictsOnlyTheOldestWhenFull(t *testing.T) {
	c := newCorrelationCache(2)
	c.store("k1", correlationEntry{traceID: "t1"})
	c.store("k2", correlationEntry{traceID: "t2"})
	c.store("k3", correlationEntry{traceID: "t3"})

	if got := len(c.m); got != 2 {
		t.Fatalf("cache size after overflow = %d, want 2", got)
	}
	if _, ok := c.loadDelete("k1"); ok {
		t.Error("oldest entry k1 should have been evicted")
	}
	for _, k := range []string{"k2", "k3"} {
		if _, ok := c.loadDelete(k); !ok {
			t.Errorf("in-flight entry %s was evicted by an overflow", k)
		}
	}
	if c.evicted != 1 {
		t.Errorf("evicted = %d, want 1", c.evicted)
	}
}

func TestCorrelationCache_SweepDropsStaleEntries(t *testing.T) {
	c := newCorrelationCache(16)
	c.store("old", correlationEntry{traceID: "t"})
	time.Sleep(5 * time.Millisecond)

	c.sweep(time.Millisecond)
	if _, ok := c.loadDelete("old"); ok {
		t.Error("sweep must drop an entry older than maxAge")
	}
}

func TestCorrelationCache_SweepKeepsFreshEntries(t *testing.T) {
	c := newCorrelationCache(16)
	c.store("fresh", correlationEntry{traceID: "t"})

	c.sweep(time.Hour)
	if _, ok := c.loadDelete("fresh"); !ok {
		t.Error("sweep must keep an entry younger than maxAge")
	}
}

func TestNewManager_DataDogAndZipkinCreationErrors(t *testing.T) {
	origTracing := config.TracingEnabled
	origDataDog := config.DataDogEndpoint
	origZipkin := config.ZipkinEndpoint
	origOTLP := config.OTLPEndpoint
	origJaeger := config.JaegerEndpoint
	origSplunk := config.SplunkEndpoint
	defer func() {
		config.TracingEnabled = origTracing
		config.DataDogEndpoint = origDataDog
		config.ZipkinEndpoint = origZipkin
		config.OTLPEndpoint = origOTLP
		config.JaegerEndpoint = origJaeger
		config.SplunkEndpoint = origSplunk
	}()

	config.TracingEnabled = true
	config.OTLPEndpoint = ""
	config.JaegerEndpoint = ""
	config.SplunkEndpoint = ""
	config.DataDogEndpoint = "ftp://bad-datadog/endpoint"
	config.ZipkinEndpoint = "ftp://bad-zipkin/endpoint"

	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if m.datadogExporter != nil {
		t.Error("a failed DataDog constructor must leave the exporter nil")
	}
	if m.zipkinExporter != nil {
		t.Error("a failed Zipkin constructor must leave the exporter nil")
	}
}

func TestManager_ExportTraces_SuccessAdvancesWatermark(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	origTracing := config.TracingEnabled
	origOTLP := config.OTLPEndpoint
	origSample := config.TracingSampleRate
	origJaeger := config.JaegerEndpoint
	origSplunk := config.SplunkEndpoint
	origDataDog := config.DataDogEndpoint
	origZipkin := config.ZipkinEndpoint
	defer func() {
		config.TracingEnabled = origTracing
		config.OTLPEndpoint = origOTLP
		config.TracingSampleRate = origSample
		config.JaegerEndpoint = origJaeger
		config.SplunkEndpoint = origSplunk
		config.DataDogEndpoint = origDataDog
		config.ZipkinEndpoint = origZipkin
	}()

	config.TracingEnabled = true
	config.TracingSampleRate = 1.0
	config.OTLPEndpoint = srv.URL
	config.JaegerEndpoint = ""
	config.SplunkEndpoint = ""
	config.DataDogEndpoint = ""
	config.ZipkinEndpoint = ""

	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if m.otlpExporter == nil {
		t.Fatal("expected an OTLP exporter for a loopback endpoint")
	}

	m.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "00f067aa0ba902b7",
	}, nil)

	m.exportTraces(true)
	if got := m.traceTracker.SnapshotForExport(m.exportInterval, true, "otlp"); len(got) != 0 {
		t.Errorf("a successful export must advance the watermark; re-export snapshot = %d traces", len(got))
	}
}

func TestManager_ExportTraces_SplunkFailureAlertSuppressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	origTracing := config.TracingEnabled
	origSplunk := config.SplunkEndpoint
	origSplunkEnabled := config.AlertSplunkEnabled
	origSample := config.TracingSampleRate
	origOTLP := config.OTLPEndpoint
	origJaeger := config.JaegerEndpoint
	origDataDog := config.DataDogEndpoint
	origZipkin := config.ZipkinEndpoint
	defer func() {
		config.TracingEnabled = origTracing
		config.SplunkEndpoint = origSplunk
		config.AlertSplunkEnabled = origSplunkEnabled
		config.TracingSampleRate = origSample
		config.OTLPEndpoint = origOTLP
		config.JaegerEndpoint = origJaeger
		config.DataDogEndpoint = origDataDog
		config.ZipkinEndpoint = origZipkin
	}()

	config.TracingEnabled = true
	config.TracingSampleRate = 1.0
	config.SplunkEndpoint = srv.URL
	config.AlertSplunkEnabled = true
	config.OTLPEndpoint = ""
	config.JaegerEndpoint = ""
	config.DataDogEndpoint = ""
	config.ZipkinEndpoint = ""

	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if m.splunkExporter == nil {
		t.Fatal("expected a Splunk exporter for a loopback endpoint")
	}

	m.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "00f067aa0ba902b7",
	}, nil)

	m.exportTraces(true)
	if got := m.traceTracker.SnapshotForExport(m.exportInterval, true, "splunk"); len(got) == 0 {
		t.Error("a failed export must not advance the watermark; the trace should remain exportable")
	}
}
