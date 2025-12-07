package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

type JaegerExporter struct {
	endpoint   string
	client     *http.Client
	enabled    bool
	sampleRate float64
}

type JaegerSpan struct {
	TraceID       string            `json:"traceID"`
	SpanID        string            `json:"spanID"`
	ParentSpanID  string            `json:"parentSpanID,omitempty"`
	OperationName string            `json:"operationName"`
	StartTime     int64             `json:"startTime"`
	Duration      int64             `json:"duration"`
	Tags          map[string]string `json:"tags"`
	Logs          []JaegerLog       `json:"logs,omitempty"`
}

type JaegerLog struct {
	Timestamp int64             `json:"timestamp"`
	Fields    map[string]string `json:"fields"`
}

type JaegerProcess struct {
	ServiceName string            `json:"serviceName"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type JaegerSpanData struct {
	TraceID   string                   `json:"traceID"`
	Spans     []JaegerSpan             `json:"spans"`
	Processes map[string]JaegerProcess `json:"processes"`
}

func NewJaegerExporter(endpoint string, sampleRate float64) (*JaegerExporter, error) {
	if endpoint == "" {
		endpoint = config.DefaultJaegerEndpoint
	}

	return &JaegerExporter{
		endpoint:   endpoint,
		client:     &http.Client{Timeout: 10 * time.Second},
		enabled:    true,
		sampleRate: sampleRate,
	}, nil
}

func (e *JaegerExporter) ExportTraces(traces []*tracker.Trace) error {
	if !e.enabled || len(traces) == 0 {
		return nil
	}

	for _, t := range traces {
		if !e.shouldSample(t) {
			continue
		}

		if err := e.exportTrace(t); err != nil {
			continue
		}
	}

	return nil
}

func (e *JaegerExporter) shouldSample(_ *tracker.Trace) bool {
	if e.sampleRate >= 1.0 {
		return true
	}
	if e.sampleRate <= 0.0 {
		return false
	}
	return time.Now().UnixNano()%int64(1.0/e.sampleRate) == 0
}

func (e *JaegerExporter) exportTrace(t *tracker.Trace) error {
	if len(t.Spans) == 0 {
		return nil
	}

	jaegerSpans := make([]JaegerSpan, 0, len(t.Spans))
	processes := make(map[string]JaegerProcess)

	for _, span := range t.Spans {
		span.UpdateDuration()

		jaegerSpan := JaegerSpan{
			TraceID:       span.TraceID,
			SpanID:        span.SpanID,
			ParentSpanID:  span.ParentSpanID,
			OperationName: span.Operation,
			StartTime:     span.StartTime.UnixMicro(),
			Duration:      span.Duration.Microseconds(),
			Tags:          make(map[string]string),
			Logs:          make([]JaegerLog, 0),
		}

		for k, v := range span.Attributes {
			jaegerSpan.Tags[k] = v
		}

		if span.Error {
			jaegerSpan.Tags["error"] = "true"
		}

		serviceName := span.Service
		if serviceName == "" {
			serviceName = "unknown"
		}

		if _, exists := processes[serviceName]; !exists {
			processes[serviceName] = JaegerProcess{
				ServiceName: serviceName,
				Tags:        make(map[string]string),
			}
		}

		for _, event := range span.Events {
			log := JaegerLog{
				Timestamp: event.TimestampTime().UnixMicro(),
				Fields: map[string]string{
					"event":   event.TypeString(),
					"target":  event.Target,
					"latency": fmt.Sprintf("%d", event.LatencyNS),
				},
			}
			if event.Error != 0 {
				log.Fields["error"] = fmt.Sprintf("%d", event.Error)
			}
			jaegerSpan.Logs = append(jaegerSpan.Logs, log)
		}

		jaegerSpans = append(jaegerSpans, jaegerSpan)
	}

	spanData := JaegerSpanData{
		TraceID:   t.TraceID,
		Spans:     jaegerSpans,
		Processes: processes,
	}

	payload, err := json.Marshal([]JaegerSpanData{spanData})
	if err != nil {
		return fmt.Errorf("failed to marshal span data: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", e.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func (e *JaegerExporter) Shutdown(ctx context.Context) error {
	return nil
}
