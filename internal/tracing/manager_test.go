package tracing

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/tracing/extractor"
	"github.com/podtrace/podtrace/internal/tracing/graph"
)

func TestNewManager_Disabled(t *testing.T) {
	original := config.TracingEnabled
	config.TracingEnabled = false
	defer func() { config.TracingEnabled = original }()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}
	if manager.enabled {
		t.Error("Manager should be disabled when TracingEnabled is false")
	}
}

func TestManager_ProcessEvent_Disabled(t *testing.T) {
	manager := &Manager{enabled: false}
	event := &events.Event{Type: events.EventHTTPReq}
	manager.ProcessEvent(event, nil)
}

func TestManager_ProcessEvent_NoTraceID(t *testing.T) {
	manager := &Manager{
		enabled:      true,
		extractor:    extractor.NewHTTPExtractor(),
		traceTracker: tracker.NewTraceTracker(),
	}
	event := &events.Event{
		Type:      events.EventHTTPReq,
		TraceID:   "",
		Details:   "",
		Timestamp: uint64(time.Now().UnixNano()),
	}
	manager.ProcessEvent(event, nil)
	if manager.GetTraceCount() != 0 {
		t.Error("Event without trace ID should not create trace")
	}
}

func TestManager_ProcessEvent_WithTraceID(t *testing.T) {
	manager := &Manager{
		enabled:      true,
		extractor:    extractor.NewHTTPExtractor(),
		traceTracker: tracker.NewTraceTracker(),
	}
	event := &events.Event{
		Type:      events.EventHTTPReq,
		TraceID:   "trace123",
		SpanID:    "span123",
		Timestamp: uint64(time.Now().UnixNano()),
	}
	manager.ProcessEvent(event, nil)
	if manager.GetTraceCount() != 1 {
		t.Errorf("Expected 1 trace, got %d", manager.GetTraceCount())
	}
}

func TestManager_ProcessEvent_ExtractFromDetails(t *testing.T) {
	manager := &Manager{
		enabled:      true,
		extractor:    extractor.NewHTTPExtractor(),
		traceTracker: tracker.NewTraceTracker(),
	}
	event := &events.Event{
		Type:      events.EventHTTPReq,
		Details:   "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		Timestamp: uint64(time.Now().UnixNano()),
	}
	manager.ProcessEvent(event, nil)
	if event.TraceID == "" {
		t.Error("TraceID should be extracted from Details")
	}
}

func TestManager_GetTraceCount(t *testing.T) {
	manager := &Manager{enabled: false}
	if manager.GetTraceCount() != 0 {
		t.Error("Disabled manager should return 0 trace count")
	}

	manager.enabled = true
	manager.traceTracker = tracker.NewTraceTracker()
	if manager.GetTraceCount() != 0 {
		t.Error("Empty tracker should return 0 trace count")
	}
}

func TestManager_GetRequestFlowGraph(t *testing.T) {
	manager := &Manager{enabled: false}
	flowGraph := manager.GetRequestFlowGraph()
	if flowGraph != nil {
		t.Error("Disabled manager should return nil graph")
	}

	manager.enabled = true
	manager.graphBuilder = graph.NewGraphBuilder()
	manager.traceTracker = tracker.NewTraceTracker()
	flowGraph = manager.GetRequestFlowGraph()
	if flowGraph == nil {
		t.Error("Enabled manager should return graph (even if empty)")
	}
}

func TestManager_Start_Disabled(t *testing.T) {
	manager := &Manager{enabled: false}
	ctx := context.Background()
	err := manager.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}
}

func TestManager_Shutdown_Disabled(t *testing.T) {
	manager := &Manager{enabled: false}
	ctx := context.Background()
	err := manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_Shutdown_Enabled(t *testing.T) {
	original := config.TracingEnabled
	config.TracingEnabled = true
	defer func() { config.TracingEnabled = original }()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_Start_Enabled(t *testing.T) {
	original := config.TracingEnabled
	config.TracingEnabled = true
	defer func() { config.TracingEnabled = original }()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = manager.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)
}

func TestManager_Start_StopCh(t *testing.T) {
	original := config.TracingEnabled
	config.TracingEnabled = true
	defer func() { config.TracingEnabled = original }()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	ctx := context.Background()
	err = manager.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	close(manager.stopCh)
	time.Sleep(10 * time.Millisecond)
}

func TestManager_ExportLoop_Ticker(t *testing.T) {
	original := config.TracingEnabled
	config.TracingEnabled = true
	defer func() { config.TracingEnabled = original }()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.exportInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = manager.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	time.Sleep(30 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)
}

func TestManager_CleanupLoop_Ticker(t *testing.T) {
	original := config.TracingEnabled
	config.TracingEnabled = true
	defer func() { config.TracingEnabled = original }()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.cleanupInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = manager.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	time.Sleep(30 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)
}

func TestManager_ExportTraces_Empty(t *testing.T) {
	manager := &Manager{
		enabled:      true,
		traceTracker: tracker.NewTraceTracker(),
	}

	manager.exportTraces()
}

func TestManager_ExportTraces_WithOTLPExporter(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.OTLPEndpoint = "http://localhost:4317"
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_WithJaegerExporter(t *testing.T) {
	originalJaeger := config.JaegerEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.JaegerEndpoint = "http://localhost:14268/api/traces"
	defer func() {
		config.JaegerEndpoint = originalJaeger
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_WithSplunkExporter(t *testing.T) {
	originalSplunk := config.SplunkEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.SplunkEndpoint = "http://localhost:8088/services/collector"
	defer func() {
		config.SplunkEndpoint = originalSplunk
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_AllExporters(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalJaeger := config.JaegerEndpoint
	originalSplunk := config.SplunkEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.OTLPEndpoint = "http://localhost:4317"
	config.JaegerEndpoint = "http://localhost:14268/api/traces"
	config.SplunkEndpoint = "http://localhost:8088/services/collector"
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.JaegerEndpoint = originalJaeger
		config.SplunkEndpoint = originalSplunk
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_OTLPError(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalTracing := config.TracingEnabled
	originalAlerting := alerting.GetGlobalManager()
	config.TracingEnabled = true
	config.OTLPEndpoint = "http://invalid-endpoint:4317"
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.TracingEnabled = originalTracing
		alerting.SetGlobalManager(originalAlerting)
	}()

	alertManager, _ := alerting.NewManager()
	alerting.SetGlobalManager(alertManager)
	defer alerting.SetGlobalManager(nil)

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_JaegerError(t *testing.T) {
	originalJaeger := config.JaegerEndpoint
	originalTracing := config.TracingEnabled
	originalAlerting := alerting.GetGlobalManager()
	config.TracingEnabled = true
	config.JaegerEndpoint = "http://invalid-endpoint:14268/api/traces"
	defer func() {
		config.JaegerEndpoint = originalJaeger
		config.TracingEnabled = originalTracing
		alerting.SetGlobalManager(originalAlerting)
	}()

	alertManager, _ := alerting.NewManager()
	alerting.SetGlobalManager(alertManager)
	defer alerting.SetGlobalManager(nil)

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_SplunkError_AlertingDisabled(t *testing.T) {
	originalSplunk := config.SplunkEndpoint
	originalSplunkEnabled := config.AlertSplunkEnabled
	originalTracing := config.TracingEnabled
	originalAlerting := alerting.GetGlobalManager()
	config.TracingEnabled = true
	config.SplunkEndpoint = "http://invalid-endpoint:8088/services/collector"
	config.AlertSplunkEnabled = false
	defer func() {
		config.SplunkEndpoint = originalSplunk
		config.AlertSplunkEnabled = originalSplunkEnabled
		config.TracingEnabled = originalTracing
		alerting.SetGlobalManager(originalAlerting)
	}()

	alertManager, _ := alerting.NewManager()
	alerting.SetGlobalManager(alertManager)
	defer alerting.SetGlobalManager(nil)

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_SplunkError_NoAlertManager(t *testing.T) {
	originalSplunk := config.SplunkEndpoint
	originalSplunkEnabled := config.AlertSplunkEnabled
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.SplunkEndpoint = "http://invalid-endpoint:8088/services/collector"
	config.AlertSplunkEnabled = false
	defer func() {
		config.SplunkEndpoint = originalSplunk
		config.AlertSplunkEnabled = originalSplunkEnabled
		config.TracingEnabled = originalTracing
	}()

	alerting.SetGlobalManager(nil)

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_OTLPError_NoAlertManager(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.OTLPEndpoint = "http://invalid-endpoint:4317"
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.TracingEnabled = originalTracing
	}()

	alerting.SetGlobalManager(nil)

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_JaegerError_NoAlertManager(t *testing.T) {
	originalJaeger := config.JaegerEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.JaegerEndpoint = "http://invalid-endpoint:14268/api/traces"
	defer func() {
		config.JaegerEndpoint = originalJaeger
		config.TracingEnabled = originalTracing
	}()

	alerting.SetGlobalManager(nil)

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_Shutdown_WithExporters(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalJaeger := config.JaegerEndpoint
	originalSplunk := config.SplunkEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.OTLPEndpoint = "http://localhost:4317"
	config.JaegerEndpoint = "http://localhost:14268/api/traces"
	config.SplunkEndpoint = "http://localhost:8088/services/collector"
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.JaegerEndpoint = originalJaeger
		config.SplunkEndpoint = originalSplunk
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	err = manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_Shutdown_ExportTracesOnShutdown(t *testing.T) {
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	defer func() { config.TracingEnabled = originalTracing }()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_Shutdown_ExporterShutdownErrors(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalJaeger := config.JaegerEndpoint
	originalSplunk := config.SplunkEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.OTLPEndpoint = "http://localhost:4317"
	config.JaegerEndpoint = "http://localhost:14268/api/traces"
	config.SplunkEndpoint = "http://localhost:8088/services/collector"
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.JaegerEndpoint = originalJaeger
		config.SplunkEndpoint = originalSplunk
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_ProcessEvent_NilEvent(t *testing.T) {
	manager := &Manager{
		enabled: true,
	}
	manager.ProcessEvent(nil, nil)
}

func TestManager_ProcessEvent_InvalidTraceContext(t *testing.T) {
	manager := &Manager{
		enabled:      true,
		extractor:    extractor.NewHTTPExtractor(),
		traceTracker: tracker.NewTraceTracker(),
	}
	event := &events.Event{
		Type:      events.EventHTTPReq,
		Details:   "invalid-trace-context",
		Timestamp: uint64(time.Now().UnixNano()),
	}
	manager.ProcessEvent(event, nil)
}

func TestManager_ProcessEvent_WithK8sContext(t *testing.T) {
	manager := &Manager{
		enabled:      true,
		extractor:    extractor.NewHTTPExtractor(),
		traceTracker: tracker.NewTraceTracker(),
	}
	event := &events.Event{
		Type:      events.EventHTTPReq,
		TraceID:   "test-trace",
		SpanID:    "test-span",
		Timestamp: uint64(time.Now().UnixNano()),
	}
	k8sContext := map[string]interface{}{
		"namespace": "test-ns",
		"pod":       "test-pod",
	}
	manager.ProcessEvent(event, k8sContext)
}

func TestNewManager_WithAllExporters(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalJaeger := config.JaegerEndpoint
	originalSplunk := config.SplunkEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.OTLPEndpoint = "http://localhost:4317"
	config.JaegerEndpoint = "http://localhost:14268/api/traces"
	config.SplunkEndpoint = "http://localhost:8088/services/collector"
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.JaegerEndpoint = originalJaeger
		config.SplunkEndpoint = originalSplunk
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}
	if !manager.enabled {
		t.Error("Manager should be enabled when TracingEnabled is true")
	}
}

func TestNewManager_ExporterCreationErrors(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalJaeger := config.JaegerEndpoint
	originalSplunk := config.SplunkEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.OTLPEndpoint = "invalid://endpoint"
	config.JaegerEndpoint = "invalid://endpoint"
	config.SplunkEndpoint = "invalid://endpoint"
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.JaegerEndpoint = originalJaeger
		config.SplunkEndpoint = originalSplunk
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() should not return error even if exporters fail: %v", err)
	}
	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}
}

func TestManager_ExportTraces_SplunkError_AlertingEnabled(t *testing.T) {
	originalSplunk := config.SplunkEndpoint
	originalSplunkEnabled := config.AlertSplunkEnabled
	originalTracing := config.TracingEnabled
	originalAlerting := alerting.GetGlobalManager()
	config.TracingEnabled = true
	config.SplunkEndpoint = "http://invalid-endpoint:8088/services/collector"
	config.AlertSplunkEnabled = true
	defer func() {
		config.SplunkEndpoint = originalSplunk
		config.AlertSplunkEnabled = originalSplunkEnabled
		config.TracingEnabled = originalTracing
		alerting.SetGlobalManager(originalAlerting)
	}()

	alertManager, _ := alerting.NewManager()
	alerting.SetGlobalManager(alertManager)
	defer alerting.SetGlobalManager(nil)

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_SuccessfulExport(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.OTLPEndpoint = ""
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_Shutdown_WithStartedManager(t *testing.T) {
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	defer func() { config.TracingEnabled = originalTracing }()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = manager.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	err = manager.Shutdown(shutdownCtx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_Shutdown_WithNilExporters(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalJaeger := config.JaegerEndpoint
	originalSplunk := config.SplunkEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.OTLPEndpoint = ""
	config.JaegerEndpoint = ""
	config.SplunkEndpoint = ""
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.JaegerEndpoint = originalJaeger
		config.SplunkEndpoint = originalSplunk
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_Shutdown_ExporterShutdownWithError(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalJaeger := config.JaegerEndpoint
	originalSplunk := config.SplunkEndpoint
	originalTracing := config.TracingEnabled
	config.TracingEnabled = true
	config.OTLPEndpoint = "http://localhost:4317"
	config.JaegerEndpoint = "http://localhost:14268/api/traces"
	config.SplunkEndpoint = "http://localhost:8088/services/collector"
	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.JaegerEndpoint = originalJaeger
		config.SplunkEndpoint = originalSplunk
		config.TracingEnabled = originalTracing
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_ExportTraces_OTLPExporterNil(t *testing.T) {
	manager := &Manager{
		enabled:      true,
		traceTracker: tracker.NewTraceTracker(),
		otlpExporter: nil,
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_JaegerExporterNil(t *testing.T) {
	manager := &Manager{
		enabled:        true,
		traceTracker:   tracker.NewTraceTracker(),
		jaegerExporter: nil,
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}

func TestManager_ExportTraces_SplunkExporterNil(t *testing.T) {
	manager := &Manager{
		enabled:        true,
		traceTracker:   tracker.NewTraceTracker(),
		splunkExporter: nil,
	}

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "test-trace",
		SpanID:  "test-span",
	}, nil)

	manager.exportTraces()
}
