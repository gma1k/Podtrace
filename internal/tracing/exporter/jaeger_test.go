package exporter

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

func TestNewJaegerExporter(t *testing.T) {
	exporter, err := NewJaegerExporter("", 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	if exporter == nil {
		t.Fatal("NewJaegerExporter() returned nil")
	}
	if exporter.endpoint != config.DefaultJaegerEndpoint {
		t.Errorf("Expected endpoint %s, got %s", config.DefaultJaegerEndpoint, exporter.endpoint)
	}
}

func TestJaegerExporter_ExportTraces_Disabled(t *testing.T) {
	exporter := &JaegerExporter{enabled: false}
	err := exporter.ExportTraces([]*tracker.Trace{})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestJaegerExporter_ExportTraces_Empty(t *testing.T) {
	exporter := &JaegerExporter{enabled: true}
	err := exporter.ExportTraces([]*tracker.Trace{})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestJaegerExporter_shouldSample(t *testing.T) {
	tests := []struct {
		name       string
		sampleRate float64
	}{
		{"rate 1.0", 1.0},
		{"rate 0.0", 0.0},
		{"rate 0.5", 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := &JaegerExporter{sampleRate: tt.sampleRate}
			trace := &tracker.Trace{TraceID: "test"}
			result := exporter.shouldSample(trace)
			if tt.sampleRate == 1.0 && !result {
				t.Error("Sample rate 1.0 should always sample")
			}
			if tt.sampleRate == 0.0 && result {
				t.Error("Sample rate 0.0 should never sample")
			}
		})
	}
}

func TestJaegerExporter_exportTrace_NoSpans(t *testing.T) {
	exporter := &JaegerExporter{enabled: true}
	trace := &tracker.Trace{
		TraceID: "test",
		Spans:   []*tracker.Span{},
	}
	err := exporter.exportTrace(trace)
	if err != nil {
		t.Errorf("exportTrace() error = %v", err)
	}
}

func TestJaegerExporter_exportTrace_WithSpans(t *testing.T) {
	exporter, err := NewJaegerExporter("http://localhost:14268/api/traces", 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	trace := &tracker.Trace{
		TraceID: "test123",
		Spans: []*tracker.Span{
			{
				TraceID:   "test123",
				SpanID:    "span123",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
				Events: []*events.Event{
					{
						Type:      events.EventHTTPReq,
						Target:    "http://example.com",
						Timestamp: uint64(time.Now().UnixNano()),
					},
				},
			},
		},
	}
	exportErr := exporter.exportTrace(trace)
	if exportErr != nil {
		t.Logf("exportTrace() error (expected for test without server): %v", exportErr)
	}
}

func TestJaegerExporter_Shutdown(t *testing.T) {
	exporter := &JaegerExporter{}
	ctx := context.Background()
	err := exporter.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestJaegerExporter_ExportTraces_WithSampledTrace(t *testing.T) {
	exporter, err := NewJaegerExporter("http://localhost:14268/api/traces", 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	
	trace := &tracker.Trace{
		TraceID: "test123",
		Spans: []*tracker.Span{
			{
				TraceID:   "test123",
				SpanID:    "span123",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
			},
		},
	}
	
	err = exporter.ExportTraces([]*tracker.Trace{trace})
	if err != nil {
		t.Logf("ExportTraces() error (expected for test without server): %v", err)
	}
}

func TestJaegerExporter_ExportTraces_WithNotSampledTrace(t *testing.T) {
	exporter, err := NewJaegerExporter("http://localhost:14268/api/traces", 0.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	
	trace := &tracker.Trace{
		TraceID: "test123",
		Spans: []*tracker.Span{
			{
				TraceID:   "test123",
				SpanID:    "span123",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
			},
		},
	}
	
	err = exporter.ExportTraces([]*tracker.Trace{trace})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestJaegerExporter_exportTrace_WithErrorSpan(t *testing.T) {
	exporter, err := NewJaegerExporter("http://localhost:14268/api/traces", 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	
	trace := &tracker.Trace{
		TraceID: "test123",
		Spans: []*tracker.Span{
			{
				TraceID:   "test123",
				SpanID:    "span123",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
				Error:     true,
				Attributes: map[string]string{"key": "value"},
			},
		},
	}
	
	err = exporter.exportTrace(trace)
	if err != nil {
		t.Logf("exportTrace() error (expected for test without server): %v", err)
	}
}

func TestJaegerExporter_exportTrace_WithEmptyServiceName(t *testing.T) {
	exporter, err := NewJaegerExporter("http://localhost:14268/api/traces", 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	
	trace := &tracker.Trace{
		TraceID: "test123",
		Spans: []*tracker.Span{
			{
				TraceID:   "test123",
				SpanID:    "span123",
				Operation: "test-op",
				Service:   "",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
			},
		},
	}
	
	err = exporter.exportTrace(trace)
	if err != nil {
		t.Logf("exportTrace() error (expected for test without server): %v", err)
	}
}

func TestJaegerExporter_exportTrace_WithEventError(t *testing.T) {
	exporter, err := NewJaegerExporter("http://localhost:14268/api/traces", 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	
	trace := &tracker.Trace{
		TraceID: "test123",
		Spans: []*tracker.Span{
			{
				TraceID:   "test123",
				SpanID:    "span123",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
				Events: []*events.Event{
					{
						Type:      events.EventHTTPReq,
						Target:    "http://example.com",
						Timestamp: uint64(time.Now().UnixNano()),
						Error:     500,
						LatencyNS: 1000000,
					},
				},
			},
		},
	}
	
	err = exporter.exportTrace(trace)
	if err != nil {
		t.Logf("exportTrace() error (expected for test without server): %v", err)
	}
}

func TestJaegerExporter_exportTrace_WithParentSpanID(t *testing.T) {
	exporter, err := NewJaegerExporter("http://localhost:14268/api/traces", 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	
	trace := &tracker.Trace{
		TraceID: "test123",
		Spans: []*tracker.Span{
			{
				TraceID:      "test123",
				SpanID:       "span123",
				ParentSpanID: "parent123",
				Operation:    "test-op",
				Service:      "test-service",
				StartTime:    time.Now(),
				Duration:     100 * time.Millisecond,
			},
		},
	}
	
	err = exporter.exportTrace(trace)
	if err != nil {
		t.Logf("exportTrace() error (expected for test without server): %v", err)
	}
}
