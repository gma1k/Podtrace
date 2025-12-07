package exporter

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

func TestNewSplunkExporter(t *testing.T) {
	exporter, err := NewSplunkExporter("", "", 1.0)
	if err != nil {
		t.Fatalf("NewSplunkExporter() error = %v", err)
	}
	if exporter == nil {
		t.Fatal("NewSplunkExporter() returned nil")
	}
	if exporter.endpoint != config.DefaultSplunkEndpoint {
		t.Errorf("Expected endpoint %s, got %s", config.DefaultSplunkEndpoint, exporter.endpoint)
	}
}

func TestSplunkExporter_ExportTraces_Disabled(t *testing.T) {
	exporter := &SplunkExporter{enabled: false}
	err := exporter.ExportTraces([]*tracker.Trace{})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestSplunkExporter_ExportTraces_Empty(t *testing.T) {
	exporter := &SplunkExporter{enabled: true}
	err := exporter.ExportTraces([]*tracker.Trace{})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestSplunkExporter_shouldSample(t *testing.T) {
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
			exporter := &SplunkExporter{sampleRate: tt.sampleRate}
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

func TestSplunkExporter_exportTrace_NoSpans(t *testing.T) {
	exporter := &SplunkExporter{enabled: true}
	trace := &tracker.Trace{
		TraceID: "test",
		Spans:   []*tracker.Span{},
	}
	err := exporter.exportTrace(trace)
	if err != nil {
		t.Errorf("exportTrace() error = %v", err)
	}
}

func TestSplunkExporter_exportTrace_WithSpans(t *testing.T) {
	exporter, err := NewSplunkExporter("http://localhost:8088/services/collector", "", 1.0)
	if err != nil {
		t.Fatalf("NewSplunkExporter() error = %v", err)
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
	err = exporter.exportTrace(trace)
	if err == nil {
		t.Log("exportTrace() succeeded (may fail in CI without server)")
	} else {
		t.Logf("exportTrace() error (expected for test without server): %v", err)
	}
}

func TestSplunkExporter_Shutdown(t *testing.T) {
	exporter := &SplunkExporter{}
	ctx := context.Background()
	err := exporter.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}
