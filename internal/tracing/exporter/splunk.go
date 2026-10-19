package exporter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/netguard"
)

// splunkMaxBatchBytes bounds a single HEC request body so a large export is
// split into a few sized requests rather than one unbounded POST (or, as
// before, one POST per span).
const splunkMaxBatchBytes = 512 * 1024

type SplunkExporter struct {
	endpoint   string
	token      string
	client     *http.Client
	enabled    bool
	sampleRate float64
}

type SplunkEvent struct {
	Time       int64                  `json:"time"`
	Host       string                 `json:"host,omitempty"`
	Source     string                 `json:"source,omitempty"`
	Sourcetype string                 `json:"sourcetype,omitempty"`
	Event      map[string]interface{} `json:"event"`
}

func NewSplunkExporter(endpoint, token string, sampleRate float64) (*SplunkExporter, error) {
	endpoint, err := validateExporterEndpoint(endpoint, config.DefaultSplunkEndpoint)
	if err != nil {
		return nil, fmt.Errorf("splunk: %w", err)
	}

	return &SplunkExporter{
		endpoint:   endpoint,
		token:      token,
		client:     netguard.HardenedClient(config.TracingExporterTimeout),
		enabled:    true,
		sampleRate: sampleRate,
	}, nil
}

func (e *SplunkExporter) ExportTraces(traces []*tracker.Trace) error {
	if !e.enabled || len(traces) == 0 {
		return nil
	}

	events := make([]SplunkEvent, 0)
	for _, t := range traces {
		if !e.shouldSample(t) {
			continue
		}
		events = append(events, e.buildEvents(t)...)
	}
	if len(events) == 0 {
		return nil
	}

	return e.sendBatch(events)
}

func (e *SplunkExporter) shouldSample(t *tracker.Trace) bool {
	return sampleTrace(t.TraceID, e.sampleRate)
}

func (e *SplunkExporter) buildEvents(t *tracker.Trace) []SplunkEvent {
	events := make([]SplunkEvent, 0, len(t.Spans))
	for _, span := range t.Spans {
		span.UpdateDuration()

		eventData := map[string]interface{}{
			"trace_id":       span.TraceID,
			"span_id":        span.SpanID,
			"parent_span_id": span.ParentSpanID,
			"operation":      span.Operation,
			"service":        span.Service,
			"start_time":     span.StartTime.Unix(),
			"duration_ms":    span.Duration.Milliseconds(),
			"span_count":     len(span.Events),
		}

		for k, v := range span.Attributes {
			eventData[k] = v
		}

		if span.Error {
			eventData["error"] = true
		}

		events = append(events, SplunkEvent{
			Time:       span.StartTime.Unix(),
			Sourcetype: "Podtrace:trace",
			Event:      eventData,
		})
	}
	return events
}

// sendBatch delivers events as HEC batches: JSON objects are concatenated into
// one request body (the format Splunk HEC accepts) and flushed once the body
// would exceed splunkMaxBatchBytes, so a whole export is a few sized POSTs
// instead of one request per span.
func (e *SplunkExporter) sendBatch(events []SplunkEvent) error {
	var outcome exportOutcome
	var body bytes.Buffer
	var batchTraces []string
	inBatch := map[string]struct{}{}

	flush := func() {
		if body.Len() == 0 {
			return
		}
		outcome.record(e.postBatch(body.Bytes()), batchTraces...)
		body.Reset()
		batchTraces = batchTraces[:0]
		clear(inBatch)
	}

	for _, event := range events {
		traceID, _ := event.Event["trace_id"].(string)
		payload, err := marshalJSON(event)
		if err != nil {
			outcome.record(permanent(fmt.Errorf("marshal event: %w", err)))
			continue
		}
		if body.Len() > 0 && body.Len()+len(payload)+1 > splunkMaxBatchBytes {
			flush()
		}
		body.Write(payload)
		body.WriteByte('\n')
		if _, seen := inBatch[traceID]; !seen {
			inBatch[traceID] = struct{}{}
			batchTraces = append(batchTraces, traceID)
		}
	}
	flush()

	return outcome.err()
}

func (e *SplunkExporter) postBatch(payload []byte) error {
	req, err := http.NewRequestWithContext(context.Background(), "POST", e.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if e.token != "" {
		req.Header.Set("Authorization", "Splunk "+e.token)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return statusError(resp.StatusCode)
	}
	return nil
}

func (e *SplunkExporter) Shutdown(ctx context.Context) error {
	return nil
}
