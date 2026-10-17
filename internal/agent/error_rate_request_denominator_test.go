package agent

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func TestErrorRateIsMeasuredOverRequestsNotEverySocketEvent(t *testing.T) {
	errPct := int32(20)
	b := &bundle.Payload{
		Type:       bundle.TypeOTLP,
		Endpoint:   "x:4318",
		Insecure:   true,
		Thresholds: &bundle.Thresholds{ErrorRatePercent: &errPct},
	}
	cr := CRKey{Namespace: "ns", Name: "cr"}
	m := NewMetrics()
	exp, err := newSDKEventExporter("otlp", cr, b, &noopSpanExporter{}, withMetrics(m))
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}
	defer func() { _ = exp.Close(context.Background()) }()

	now := uint64(time.Now().UnixNano())
	var batch []*events.Event
	for i := 0; i < 40; i++ {
		for j := 0; j < 10; j++ {
			batch = append(batch, &events.Event{Type: events.EventTCPSend, Timestamp: now})
		}
		status := int32(200)
		details := "200"
		if i%2 == 0 {
			status, details = 503, "503"
		}
		batch = append(batch, &events.Event{Type: events.EventHTTPResp, Timestamp: now, Error: status, Details: details})
	}
	if err := exp.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	got := counterValue(t, m.ErrorRateBreached, prometheus.Labels{"cr_namespace": cr.Namespace, "cr_name": cr.Name})
	if got != 1 {
		t.Errorf("error_rate_breached_total = %v, want 1: half the requests failed, diluted by socket events", got)
	}
}

func TestNonRequestFailuresDoNotFeedTheErrorRate(t *testing.T) {
	errPct := int32(5)
	b := &bundle.Payload{
		Type:       bundle.TypeOTLP,
		Endpoint:   "x:4318",
		Insecure:   true,
		Thresholds: &bundle.Thresholds{ErrorRatePercent: &errPct},
	}
	cr := CRKey{Namespace: "ns", Name: "cr"}
	m := NewMetrics()
	exp, err := newSDKEventExporter("otlp", cr, b, &noopSpanExporter{}, withMetrics(m))
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}
	defer func() { _ = exp.Close(context.Background()) }()

	batch := make([]*events.Event, 50)
	for i := range batch {
		batch[i] = &events.Event{Type: events.EventTCPRecv, Timestamp: uint64(time.Now().UnixNano()), Error: -11}
	}
	if err := exp.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	got := counterValue(t, m.ErrorRateBreached, prometheus.Labels{"cr_namespace": cr.Namespace, "cr_name": cr.Name})
	if got != 0 {
		t.Errorf("error_rate_breached_total = %v, want 0 for EAGAIN on recv", got)
	}
}

func TestUpstreamErrorsSeenByACallerDoNotFeedItsErrorRate(t *testing.T) {
	errPct := int32(5)
	b := &bundle.Payload{
		Type:       bundle.TypeOTLP,
		Endpoint:   "x:4318",
		Insecure:   true,
		Thresholds: &bundle.Thresholds{ErrorRatePercent: &errPct},
	}
	cr := CRKey{Namespace: "ns", Name: "cr"}
	m := NewMetrics()
	exp, err := newSDKEventExporter("otlp", cr, b, &noopSpanExporter{}, withMetrics(m))
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}
	defer func() { _ = exp.Close(context.Background()) }()

	batch := make([]*events.Event, 50)
	for i := range batch {
		batch[i] = &events.Event{
			Type:      events.EventHTTPResp,
			Timestamp: uint64(time.Now().UnixNano()),
			Error:     503,
			Details:   "503",
			TCPState:  events.HTTPRoleBits(false),
		}
	}
	if err := exp.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	got := counterValue(t, m.ErrorRateBreached, prometheus.Labels{"cr_namespace": cr.Namespace, "cr_name": cr.Name})
	if got != 0 {
		t.Errorf("error_rate_breached_total = %v, want 0 for 503s the workload received from an upstream", got)
	}
}
