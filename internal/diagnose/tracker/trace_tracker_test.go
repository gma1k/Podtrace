package tracker

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestNewTraceTracker(t *testing.T) {
	tt := NewTraceTracker()
	if tt == nil {
		t.Fatal("NewTraceTracker returned nil")
	}
	if tt.GetTraceCount() != 0 {
		t.Error("New tracker should have 0 traces")
	}
}

func TestTraceTracker_ProcessEvent(t *testing.T) {
	tt := NewTraceTracker()

	event := &events.Event{
		TraceID:      "trace123",
		SpanID:       "span123",
		ParentSpanID: "",
		Type:         events.EventHTTPReq,
		Timestamp:    uint64(time.Now().UnixNano()),
		ProcessName:  "test-process",
		Target:       "http://example.com",
	}

	tt.ProcessEvent(event, nil)

	if tt.GetTraceCount() != 1 {
		t.Errorf("Expected 1 trace, got %d", tt.GetTraceCount())
	}

	trace := tt.GetTrace("trace123")
	if trace == nil {
		t.Fatal("Trace not found")
	}
	if len(trace.Spans) != 1 {
		t.Errorf("Expected 1 span, got %d", len(trace.Spans))
	}
}

func TestTraceTracker_ProcessEvent_WithK8sContext(t *testing.T) {
	tt := NewTraceTracker()

	event := &events.Event{
		TraceID:     "trace123",
		SpanID:      "span123",
		Type:        events.EventHTTPReq,
		Timestamp:   uint64(time.Now().UnixNano()),
		ProcessName: "test-process",
	}

	k8sCtx := map[string]interface{}{
		"target_service":   "test-service",
		"target_namespace": "default",
		"target_pod":       "test-pod",
		"target_labels":    map[string]string{"app": "test"},
	}

	tt.ProcessEvent(event, k8sCtx)

	trace := tt.GetTrace("trace123")
	if trace == nil {
		t.Fatal("Trace not found")
	}

	if len(trace.Services) == 0 {
		t.Error("Services should be populated")
	}
}

func TestTraceTracker_ProcessEvent_NoTraceID(t *testing.T) {
	tt := NewTraceTracker()

	event := &events.Event{
		TraceID: "",
		SpanID:  "span123",
		Type:    events.EventHTTPReq,
	}

	tt.ProcessEvent(event, nil)

	if tt.GetTraceCount() != 0 {
		t.Error("Event without TraceID should not create trace")
	}
}

func TestTraceTracker_GetAllTraces(t *testing.T) {
	tt := NewTraceTracker()

	event1 := &events.Event{
		TraceID:   "trace1",
		SpanID:    "span1",
		Timestamp: uint64(time.Now().UnixNano()),
		Type:      events.EventHTTPReq,
	}

	event2 := &events.Event{
		TraceID:   "trace2",
		SpanID:    "span2",
		Timestamp: uint64(time.Now().UnixNano()),
		Type:      events.EventHTTPReq,
	}

	tt.ProcessEvent(event1, nil)
	tt.ProcessEvent(event2, nil)

	traces := tt.GetAllTraces()
	if len(traces) != 2 {
		t.Errorf("Expected 2 traces, got %d", len(traces))
	}
}

func TestTraceTracker_CleanupOldTraces(t *testing.T) {
	tt := NewTraceTracker()

	oldTime := time.Now().Add(-15 * time.Minute)
	event := &events.Event{
		TraceID:   "old-trace",
		SpanID:    "span1",
		Timestamp: uint64(oldTime.UnixNano()),
		Type:      events.EventHTTPReq,
	}

	tt.ProcessEvent(event, nil)

	tt.CleanupOldTraces(10 * time.Minute)

	if tt.GetTraceCount() != 0 {
		t.Error("Old traces should be cleaned up")
	}
}

func TestSpan_UpdateDuration(t *testing.T) {
	span := &Span{
		TraceID:   "trace1",
		SpanID:    "span1",
		StartTime: time.Now(),
		Events: []*events.Event{
			{
				Timestamp: uint64(time.Now().UnixNano()),
				Type:      events.EventHTTPReq,
			},
			{
				Timestamp: uint64(time.Now().Add(100 * time.Millisecond).UnixNano()),
				Type:      events.EventHTTPResp,
			},
		},
	}

	span.UpdateDuration()

	if span.Duration == 0 {
		t.Error("Duration should be updated")
	}
}
