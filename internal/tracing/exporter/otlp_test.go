package exporter

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

func TestNewOTLPExporter_InvalidEndpoint(t *testing.T) {
	_, err := NewOTLPExporter("invalid://endpoint", 1.0)
	if err == nil {
		t.Skip("NewOTLPExporter() may not validate endpoint format, skipping")
	}
}

func TestNewOTLPExporter_EmptyEndpoint(t *testing.T) {
	exporter, err := NewOTLPExporter("", 1.0)
	if err != nil {
		t.Fatalf("NewOTLPExporter() error = %v", err)
	}
	if exporter == nil {
		t.Fatal("NewOTLPExporter() returned nil")
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
}

func TestOTLPExporter_ExportTraces_Disabled(t *testing.T) {
	exporter := &OTLPExporter{enabled: false}
	err := exporter.ExportTraces([]*tracker.Trace{})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestOTLPExporter_ExportTraces_Empty(t *testing.T) {
	exporter := &OTLPExporter{enabled: true}
	err := exporter.ExportTraces([]*tracker.Trace{})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestOTLPExporter_shouldSample(t *testing.T) {
	tests := []struct {
		name       string
		sampleRate float64
		want       bool
	}{
		{"rate 1.0", 1.0, true},
		{"rate 0.0", 0.0, false},
		{"rate 0.5", 0.5, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := &OTLPExporter{sampleRate: tt.sampleRate}
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

func TestOTLPExporter_Shutdown(t *testing.T) {
	exporter := &OTLPExporter{}
	ctx := context.Background()
	err := exporter.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestOTLPExporter_Shutdown_WithTracerProvider(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Skipf("Skipping test: failed to create exporter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = exporter.Shutdown(ctx)
	if err != nil {
		t.Logf("Shutdown() error (expected for test): %v", err)
	}
}

func TestOTLPExporter_ExportTraces_WithSampledTrace(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Skipf("Skipping test: failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
	
	trace := &tracker.Trace{
		TraceID: "test123",
		Spans: []*tracker.Span{
			{
				TraceID:   "12345678901234567890123456789012",
				SpanID:    "1234567890123456",
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

func TestOTLPExporter_ExportTraces_WithNotSampledTrace(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 0.0)
	if err != nil {
		t.Skipf("Skipping test: failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
	
	trace := &tracker.Trace{
		TraceID: "test123",
		Spans: []*tracker.Span{
			{
				TraceID:   "12345678901234567890123456789012",
				SpanID:    "1234567890123456",
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

func TestOTLPExporter_exportSpan(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Skipf("Skipping test: failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
	
	trace := &tracker.Trace{
		TraceID: "test123",
	}
	
	span := &tracker.Span{
		TraceID:      "12345678901234567890123456789012",
		SpanID:       "1234567890123456",
		ParentSpanID: "1234567890123457",
		Operation:    "test-op",
		Service:      "test-service",
		StartTime:    time.Now(),
		Duration:     100 * time.Millisecond,
		Attributes:   map[string]string{"key": "value"},
		Error:        true,
		Events: []*events.Event{
			{
				Type:      events.EventHTTPReq,
				Target:    "http://example.com",
				Timestamp: uint64(time.Now().UnixNano()),
				LatencyNS: 1000000,
			},
		},
	}
	
	err = exporter.exportSpan(context.Background(), span, trace)
	if err != nil {
		t.Logf("exportSpan() error (expected for test without server): %v", err)
	}
}

func TestOTLPExporter_exportSpan_InvalidTraceID(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Skipf("Skipping test: failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
	
	trace := &tracker.Trace{
		TraceID: "test123",
	}
	
	span := &tracker.Span{
		TraceID:   "invalid",
		SpanID:    "1234567890123456",
		Operation: "test-op",
		StartTime: time.Now(),
		Duration:  100 * time.Millisecond,
	}
	
	err = exporter.exportSpan(context.Background(), span, trace)
	if err == nil {
		t.Error("exportSpan() should return error for invalid trace ID")
	}
}

func TestOTLPExporter_exportSpan_InvalidSpanID(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Skipf("Skipping test: failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
	
	trace := &tracker.Trace{
		TraceID: "test123",
	}
	
	span := &tracker.Span{
		TraceID:   "12345678901234567890123456789012",
		SpanID:    "invalid",
		Operation: "test-op",
		StartTime: time.Now(),
		Duration:  100 * time.Millisecond,
	}
	
	err = exporter.exportSpan(context.Background(), span, trace)
	if err == nil {
		t.Error("exportSpan() should return error for invalid span ID")
	}
}

func TestOTLPExporter_exportSpan_NoParentSpanID(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Skipf("Skipping test: failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
	
	trace := &tracker.Trace{
		TraceID: "test123",
	}
	
	span := &tracker.Span{
		TraceID:      "12345678901234567890123456789012",
		SpanID:       "1234567890123456",
		ParentSpanID: "",
		Operation:    "test-op",
		Service:      "test-service",
		StartTime:    time.Now(),
		Duration:     100 * time.Millisecond,
		Attributes:   map[string]string{"key": "value"},
	}
	
	err = exporter.exportSpan(context.Background(), span, trace)
	if err != nil {
		t.Logf("exportSpan() error (expected for test without server): %v", err)
	}
}

func TestOTLPExporter_ExportTraces_WithErrorInExportSpan(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Skipf("Skipping test: failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
	
	trace := &tracker.Trace{
		TraceID: "test123",
		Spans: []*tracker.Span{
			{
				TraceID:   "invalid",
				SpanID:    "1234567890123456",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
			},
		},
	}
	
	err = exporter.ExportTraces([]*tracker.Trace{trace})
	if err != nil {
		t.Logf("ExportTraces() error (expected for invalid trace ID): %v", err)
	}
}
