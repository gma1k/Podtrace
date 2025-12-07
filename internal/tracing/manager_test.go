package tracing

import (
	"context"
	"testing"
	"time"

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
