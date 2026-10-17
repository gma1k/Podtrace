package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

type captureServer struct {
	mu      sync.Mutex
	server  *httptest.Server
	hits    int
	lastReq capturedReq
}

type capturedReq struct {
	path    string
	method  string
	headers http.Header
	body    []byte
}

func newCaptureServer() *captureServer {
	cs := &captureServer{}
	cs.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cs.mu.Lock()
		defer cs.mu.Unlock()
		cs.hits++
		cs.lastReq = capturedReq{
			path:    r.URL.Path,
			method:  r.Method,
			headers: r.Header.Clone(),
			body:    body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	return cs
}

func (cs *captureServer) lastPath() string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.lastReq.path
}

func (cs *captureServer) lastMethod() string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.lastReq.method
}

func (cs *captureServer) lastBodyLen() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.lastReq.body)
}

func (cs *captureServer) endpointHostPort() string {
	return strings.TrimPrefix(cs.server.URL, "http://")
}

func (cs *captureServer) hitCount() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.hits
}

func (cs *captureServer) lastHeader(name string) string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.lastReq.headers.Get(name)
}

func (cs *captureServer) close() {
	cs.server.Close()
}

func sendOneEventAndShutdown(t *testing.T, exp interface {
	Export(context.Context, []*events.Event) error
	Close(context.Context) error
}) {
	t.Helper()
	if err := exp.Export(context.Background(), []*events.Event{
		{Type: events.EventDNS, Timestamp: uint64(time.Now().UnixNano()), Target: "test.example"},
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exp.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSDKEventExporter_OTLPSendsToReceiver(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:     "otlp",
		Endpoint: cs.endpointHostPort(),
		Insecure: true,
	}
	exp, err := newOTLPEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if cs.hitCount() == 0 {
		t.Fatal("captureServer received no OTLP request")
	}
}

func TestSDKEventExporter_JaegerSendsToReceiver(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:     "jaeger",
		Endpoint: cs.endpointHostPort(),
		Insecure: true,
	}
	exp, err := newJaegerEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if cs.hitCount() == 0 {
		t.Fatal("captureServer received no request from Jaeger exporter")
	}
}

func TestSDKEventExporter_DataDogAppliesAPIKeyHeader(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:       "datadog",
		Endpoint:   cs.endpointHostPort(),
		Insecure:   true,
		HeaderName: "DD-API-KEY",
		Credential: []byte("sekret-api-key"),
	}
	exp, err := newDataDogEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if got := cs.lastHeader("Dd-Api-Key"); got != "sekret-api-key" {
		t.Errorf("DD-API-KEY header = %q, want %q", got, "sekret-api-key")
	}
}

func TestSDKEventExporter_SplunkAppliesTokenHeader(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:       "splunk",
		Endpoint:   cs.endpointHostPort(),
		Insecure:   true,
		HeaderName: "X-SF-TOKEN",
		Credential: []byte("hec-token"),
	}
	exp, err := newSplunkEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if got := cs.lastHeader("X-Sf-Token"); got != "hec-token" {
		t.Errorf("X-SF-TOKEN header = %q, want %q", got, "hec-token")
	}
}

// TestSDKEventExporter_GoldenOTLPWire is the golden-payload assertion for
// the agent's OTLP-only design.
func TestSDKEventExporter_GoldenOTLPWire(t *testing.T) {
	cases := []struct {
		name  string
		build func(CRKey, *BundlePayload) (interface {
			Export(context.Context, []*events.Event) error
			Close(context.Context) error
			Name() string
		}, error)
		headerName  string
		credential  string
		extraAssert func(t *testing.T, cs *captureServer)
	}{
		{
			name: "otlp",
			build: func(k CRKey, b *BundlePayload) (interface {
				Export(context.Context, []*events.Event) error
				Close(context.Context) error
				Name() string
			}, error) {
				return newOTLPEventExporter(k, b)
			},
		},
		{
			name: "jaeger",
			build: func(k CRKey, b *BundlePayload) (interface {
				Export(context.Context, []*events.Event) error
				Close(context.Context) error
				Name() string
			}, error) {
				return newJaegerEventExporter(k, b)
			},
		},
		{
			name: "datadog",
			build: func(k CRKey, b *BundlePayload) (interface {
				Export(context.Context, []*events.Event) error
				Close(context.Context) error
				Name() string
			}, error) {
				return newDataDogEventExporter(k, b)
			},
			headerName: "DD-API-KEY",
			credential: "dd-api-key-golden",
			extraAssert: func(t *testing.T, cs *captureServer) {
				if got := cs.lastHeader("Dd-Api-Key"); got != "dd-api-key-golden" {
					t.Errorf("DD-API-KEY = %q, want %q", got, "dd-api-key-golden")
				}
			},
		},
		{
			name: "splunk",
			build: func(k CRKey, b *BundlePayload) (interface {
				Export(context.Context, []*events.Event) error
				Close(context.Context) error
				Name() string
			}, error) {
				return newSplunkEventExporter(k, b)
			},
			headerName: "X-SF-TOKEN",
			credential: "splunk-token-golden",
			extraAssert: func(t *testing.T, cs *captureServer) {
				if got := cs.lastHeader("X-Sf-Token"); got != "splunk-token-golden" {
					t.Errorf("X-SF-TOKEN = %q, want %q", got, "splunk-token-golden")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := newCaptureServer()
			defer cs.close()

			b := &BundlePayload{
				Type:       bundleType(tc.name),
				Endpoint:   cs.endpointHostPort(),
				Insecure:   true,
				HeaderName: tc.headerName,
				Credential: []byte(tc.credential),
			}
			exp, err := tc.build(CRKey{"ns", "cr"}, b)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			sendOneEventAndShutdown(t, exp)

			if cs.hitCount() == 0 {
				t.Fatal("captureServer received no request")
			}
			if got := cs.lastPath(); got != "/v1/traces" {
				t.Errorf("path = %q, want %q (proves OTLP/HTTP wire)", got, "/v1/traces")
			}
			if got := cs.lastMethod(); got != http.MethodPost {
				t.Errorf("method = %q, want POST", got)
			}
			if got := cs.lastHeader("Content-Type"); got != "application/x-protobuf" {
				t.Errorf("Content-Type = %q, want application/x-protobuf", got)
			}
			if cs.lastBodyLen() == 0 {
				t.Error("body is empty; expected serialized span data")
			}
			if tc.extraAssert != nil {
				tc.extraAssert(t, cs)
			}
		})
	}
}

// TestSDKEventExporter_LiteralHeadersPropagate confirms that
// bundle.Headers reach the receiver.
func TestSDKEventExporter_LiteralHeadersPropagate(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	b := &BundlePayload{
		Type:     bundle.TypeOTLP,
		Endpoint: cs.endpointHostPort(),
		Insecure: true,
		Headers: map[string]string{
			"X-Env":    "prod",
			"X-Tenant": "team-a",
		},
	}
	exp, err := newOTLPEventExporter(CRKey{"ns", "cr"}, b)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sendOneEventAndShutdown(t, exp)

	if got := cs.lastHeader("X-Env"); got != "prod" {
		t.Errorf("X-Env = %q, want prod", got)
	}
	if got := cs.lastHeader("X-Tenant"); got != "team-a" {
		t.Errorf("X-Tenant = %q, want team-a", got)
	}
}

func bundleType(name string) bundle.Type {
	switch name {
	case "otlp":
		return bundle.TypeOTLP
	case "jaeger":
		return bundle.TypeJaeger
	case "datadog":
		return bundle.TypeDataDog
	case "splunk":
		return bundle.TypeSplunk
	}
	return bundle.Type(name)
}

func TestSDKEventExporter_NameIncludesBackend(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	cases := []struct {
		name    string
		build   func(CRKey, *BundlePayload) (interface{ Name() string }, error)
		wantSub string
	}{
		{
			"otlp",
			func(k CRKey, b *BundlePayload) (interface{ Name() string }, error) {
				e, err := newOTLPEventExporter(k, b)
				return e, err
			},
			"otlp",
		},
		{
			"jaeger",
			func(k CRKey, b *BundlePayload) (interface{ Name() string }, error) {
				e, err := newJaegerEventExporter(k, b)
				return e, err
			},
			"jaeger",
		},
		{
			"datadog",
			func(k CRKey, b *BundlePayload) (interface{ Name() string }, error) {
				e, err := newDataDogEventExporter(k, b)
				return e, err
			},
			"datadog",
		},
		{
			"splunk",
			func(k CRKey, b *BundlePayload) (interface{ Name() string }, error) {
				e, err := newSplunkEventExporter(k, b)
				return e, err
			},
			"splunk",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &BundlePayload{Type: "otlp", Endpoint: cs.endpointHostPort(), Insecure: true, HeaderName: "X-Auth", Credential: []byte("test-token")}
			exp, err := tc.build(CRKey{"ns", "cr"}, b)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if !strings.Contains(exp.Name(), tc.wantSub) {
				t.Errorf("Name() = %q; want substring %q", exp.Name(), tc.wantSub)
			}
		})
	}
}

// noopSpanExporter is the minimal sdktrace.SpanExporter the threshold
// tests use: it discards every batch silently so the SDK pipeline
// completes without a network.
type noopSpanExporter struct{}

func (n *noopSpanExporter) ExportSpans(_ context.Context, _ []sdktrace.ReadOnlySpan) error {
	return nil
}
func (n *noopSpanExporter) Shutdown(_ context.Context) error { return nil }

// counterValue reads a single labeled counter cell, returning 0 if no
// observation has been made yet.
func counterValue(t *testing.T, cv *prometheus.CounterVec, labels prometheus.Labels) float64 {
	t.Helper()
	m, err := cv.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	var pb dto.Metric
	if err := m.Write(&pb); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return pb.GetCounter().GetValue()
}

func gaugeValue(t *testing.T, gv *prometheus.GaugeVec, labels prometheus.Labels) float64 {
	t.Helper()
	g, err := gv.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	var pb dto.Metric
	if err := g.Write(&pb); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return pb.GetGauge().GetValue()
}

// TestSDKEventExporter_ThresholdTripsCounter is the agent-side
// end-to-end gate on threshold wiring: a bundle carrying an
// FS-slow threshold yields a Prometheus counter increment for an FS
// event whose latency exceeds the threshold, and no increment for one
// that doesn't.
func TestSDKEventExporter_ThresholdTripsCounter(t *testing.T) {
	fsMs := int32(10)
	b := &bundle.Payload{
		Type:     bundle.TypeOTLP,
		Endpoint: "x:4318",
		Insecure: true,
		Thresholds: &bundle.Thresholds{
			FilesystemLatencyMs: &fsMs,
		},
	}
	cr := CRKey{Namespace: "ns", Name: "cr"}
	m := NewMetrics()

	exp, err := newSDKEventExporter("otlp", cr, b, &noopSpanExporter{}, withMetrics(m))
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}
	defer func() { _ = exp.Close(context.Background()) }()

	tripping := &events.Event{
		Type:      events.EventWrite,
		Timestamp: uint64(time.Now().UnixNano()),
		LatencyNS: 50 * 1_000_000,
	}
	clean := &events.Event{
		Type:      events.EventWrite,
		Timestamp: uint64(time.Now().UnixNano()),
		LatencyNS: 1 * 1_000_000,
	}
	wrongKind := &events.Event{
		Type:      events.EventDNS,
		Timestamp: uint64(time.Now().UnixNano()),
		LatencyNS: 50 * 1_000_000,
	}

	if err := exp.Export(context.Background(), []*events.Event{tripping, clean, wrongKind}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	got := counterValue(t, m.ThresholdTripped, prometheus.Labels{
		"cr_namespace": cr.Namespace,
		"cr_name":      cr.Name,
		"threshold":    "fs_slow",
	})
	if got != 1 {
		t.Errorf("fs_slow trip count = %v, want 1 (only the 50ms write should have tripped)", got)
	}
	for _, kind := range []string{"rtt_spike", "error_rate"} {
		got := counterValue(t, m.ThresholdTripped, prometheus.Labels{
			"cr_namespace": cr.Namespace,
			"cr_name":      cr.Name,
			"threshold":    kind,
		})
		if got != 0 {
			t.Errorf("%s trip count = %v, want 0", kind, got)
		}
	}
}

// TestSDKEventExporter_EffectiveSampleRateGauge verifies the per-CR
// sample-rate gauge and the policy_generation gauge are emitted at
// constructor time.
func TestSDKEventExporter_EffectiveSampleRateGauge(t *testing.T) {
	b := &bundle.Payload{
		Type:             bundle.TypeOTLP,
		Endpoint:         "x:4318",
		Insecure:         true,
		Sample:           samplePtrSDK(0.25),
		PolicyGeneration: 3,
	}
	cr := CRKey{Namespace: "ns", Name: "cr"}
	m := NewMetrics()

	exp, err := newSDKEventExporter("otlp", cr, b, &noopSpanExporter{}, withMetrics(m))
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}
	defer func() { _ = exp.Close(context.Background()) }()

	if got := gaugeValue(t, m.EffectiveSampleRate, prometheus.Labels{
		"cr_namespace": cr.Namespace,
		"cr_name":      cr.Name,
	}); got != 0.25 {
		t.Errorf("effective_sample_rate gauge = %v, want 0.25", got)
	}
	if got := gaugeValue(t, m.PolicyGeneration, prometheus.Labels{
		"cr_namespace": cr.Namespace,
		"cr_name":      cr.Name,
	}); got != 3 {
		t.Errorf("policy_generation gauge = %v, want 3", got)
	}
}

// TestSDKEventExporter_ErrorRateRollingWindowBreach exercises the
// end-to-end: configure an error_rate threshold, push enough
// error events to cross the rolling-window threshold, and assert the
// per-CR error_rate_breached_total counter increments exactly once
// (edge-triggered) regardless of how many error events follow.
func TestSDKEventExporter_ErrorRateRollingWindowBreach(t *testing.T) {
	errPct := int32(10)
	b := &bundle.Payload{
		Type:     bundle.TypeOTLP,
		Endpoint: "x:4318",
		Insecure: true,
		Thresholds: &bundle.Thresholds{
			ErrorRatePercent: &errPct,
		},
	}
	cr := CRKey{Namespace: "ns", Name: "cr"}
	m := NewMetrics()

	exp, err := newSDKEventExporter("otlp", cr, b, &noopSpanExporter{}, withMetrics(m))
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}
	defer func() { _ = exp.Close(context.Background()) }()

	batch := make([]*events.Event, 30)
	for i := range batch {
		batch[i] = &events.Event{
			Type:      events.EventHTTPResp,
			Timestamp: uint64(time.Now().UnixNano()),
			Error:     503,
			Details:   "503",
		}
	}
	if err := exp.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	got := counterValue(t, m.ErrorRateBreached, prometheus.Labels{
		"cr_namespace": cr.Namespace,
		"cr_name":      cr.Name,
	})
	if got != 1 {
		t.Errorf("error_rate_breached_total = %v, want 1 (edge-triggered)", got)
	}

	// Hammering the same exporter with more error events stays at 1.
	if err := exp.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export 2: %v", err)
	}
	got = counterValue(t, m.ErrorRateBreached, prometheus.Labels{
		"cr_namespace": cr.Namespace,
		"cr_name":      cr.Name,
	})
	if got != 1 {
		t.Errorf("sustained breach should not double-count, got %v", got)
	}
}

// TestSDKEventExporter_ErrorRateBelowMinSampleNoBreach guards the
// startup-noise contract end-to-end: a single error event with an
// active error_rate policy must not breach.
func TestSDKEventExporter_ErrorRateBelowMinSampleNoBreach(t *testing.T) {
	errPct := int32(10)
	b := &bundle.Payload{
		Type:     bundle.TypeOTLP,
		Endpoint: "x:4318",
		Insecure: true,
		Thresholds: &bundle.Thresholds{
			ErrorRatePercent: &errPct,
		},
	}
	cr := CRKey{Namespace: "ns", Name: "cr"}
	m := NewMetrics()

	exp, err := newSDKEventExporter("otlp", cr, b, &noopSpanExporter{}, withMetrics(m))
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}
	defer func() { _ = exp.Close(context.Background()) }()

	if err := exp.Export(context.Background(), []*events.Event{
		{Type: events.EventTCPSend, Error: -5},
		{Type: events.EventTCPSend, Error: -5},
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := counterValue(t, m.ErrorRateBreached, prometheus.Labels{
		"cr_namespace": cr.Namespace,
		"cr_name":      cr.Name,
	}); got != 0 {
		t.Errorf("expected no breach below min sample, got %v", got)
	}
}

// TestSDKEventExporter_NoThresholdsNoMetricChurn ensures the
// nil-thresholds fast-path doesn't accidentally tag spans or bump
// counters — important because most CRs won't set thresholds.
func TestSDKEventExporter_NoThresholdsNoMetricChurn(t *testing.T) {
	b := &bundle.Payload{
		Type:     bundle.TypeOTLP,
		Endpoint: "x:4318",
		Insecure: true,
	}
	cr := CRKey{Namespace: "ns", Name: "cr"}
	m := NewMetrics()
	exp, err := newSDKEventExporter("otlp", cr, b, &noopSpanExporter{}, withMetrics(m))
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}
	defer func() { _ = exp.Close(context.Background()) }()

	if err := exp.Export(context.Background(), []*events.Event{
		{Type: events.EventWrite, LatencyNS: 1_000_000_000},
		{Type: events.EventTCPRecv, LatencyNS: 1_000_000_000, Error: -5},
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	for _, kind := range []string{"fs_slow", "rtt_spike", "error_rate"} {
		got := counterValue(t, m.ThresholdTripped, prometheus.Labels{
			"cr_namespace": cr.Namespace,
			"cr_name":      cr.Name,
			"threshold":    kind,
		})
		if got != 0 {
			t.Errorf("unexpected %s trip when no thresholds set: %v", kind, got)
		}
	}
}

// fakeSpanExporter lets us drive the deliveryObservingExporter's error path.
type fakeSpanExporter struct{ err error }

func (f *fakeSpanExporter) ExportSpans(_ context.Context, _ []sdktrace.ReadOnlySpan) error {
	return f.err
}
func (f *fakeSpanExporter) Shutdown(_ context.Context) error { return nil }

func TestDeliveryObservingExporter_RecordsFailures(t *testing.T) {
	m := NewMetrics()
	cr := CRKey{Namespace: "ns", Name: "cr"}

	// Failing inner exporter: ExportSpans must propagate the error AND the
	// dropped span count must land on export_delivery_dropped_total.
	failing := &deliveryObservingExporter{
		inner:   &fakeSpanExporter{err: context.DeadlineExceeded},
		cr:      cr,
		name:    "otlp",
		metrics: m,
	}
	spans := make([]sdktrace.ReadOnlySpan, 3)
	if err := failing.ExportSpans(context.Background(), spans); err == nil {
		t.Fatal("expected the inner export error to propagate")
	}
	got := counterValue(t, m.ExportDeliveryDropped, prometheus.Labels{
		"cr_namespace": cr.Namespace,
		"cr_name":      cr.Name,
		"reason":       ClassifyExporterError(context.DeadlineExceeded),
	})
	if got != 3 {
		t.Fatalf("export_delivery_dropped_total = %v, want 3", got)
	}

	// Success path: no error, nothing added.
	ok := &deliveryObservingExporter{inner: &fakeSpanExporter{err: nil}, cr: cr, name: "otlp", metrics: m}
	if err := ok.ExportSpans(context.Background(), make([]sdktrace.ReadOnlySpan, 5)); err != nil {
		t.Fatalf("unexpected error on success path: %v", err)
	}
	if v := counterValue(t, m.ExportDeliveryDropped, prometheus.Labels{
		"cr_namespace": cr.Namespace, "cr_name": cr.Name,
		"reason": ClassifyExporterError(context.DeadlineExceeded),
	}); v != 3 {
		t.Fatalf("counter changed on success path: got %v want 3", v)
	}
}

func samplePtrSDK(v float64) *float64 { return &v }
