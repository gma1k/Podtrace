package tracker

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func tracedEvent(typ events.EventType, ts uint64) *events.Event {
	return &events.Event{
		Type:          typ,
		Timestamp:     ts,
		TraceID:       "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:        "00f067aa0ba902b7",
		CorrelationID: 7,
	}
}

func onlySpan(t *testing.T, tt *TraceTracker) *Span {
	t.Helper()
	traces := tt.SnapshotAll()
	if len(traces) != 1 || len(traces[0].Spans) != 1 {
		t.Fatalf("want one trace with one span, got %d traces", len(traces))
	}
	return traces[0].Spans[0]
}

func TestARepeatedTraceparentCannotGrowOneSpanWithoutBound(t *testing.T) {
	tt := NewTraceTracker()
	const n = maxEventsPerSpan * 4
	for i := range n {
		tt.ProcessEvent(tracedEvent(events.EventTCPSend, uint64(1_000_000+i*1000)), nil)
	}
	last := tracedEvent(events.EventTCPSend, uint64(1_000_000+n*1000))
	last.Error = -104
	tt.ProcessEvent(last, nil)

	span := onlySpan(t, tt)
	if len(span.Events) != maxEventsPerSpan {
		t.Errorf("span kept %d events, want %d", len(span.Events), maxEventsPerSpan)
	}
	if want := time.Duration(n * 1000); span.Duration != want {
		t.Errorf("duration = %v, want %v: events past the cap must still widen the span", span.Duration, want)
	}
	if !span.Error {
		t.Error("an error past the cap did not mark the span failed")
	}
	if got := span.Attributes["podtrace.dropped_events"]; got != "385" {
		t.Errorf("podtrace.dropped_events = %q, want 385", got)
	}
}

func TestASpanAwaitingItsResponseIsNotExportedEarly(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(tracedEvent(events.EventHTTPReq, 1_000_000), nil)

	if got := tt.SnapshotForExport(0, false, "otlp"); len(got) != 0 {
		t.Fatalf("exported %d traces before the response arrived", len(got))
	}

	resp := tracedEvent(events.EventHTTPResp, 9_000_000)
	resp.Error = 503
	tt.ProcessEvent(resp, nil)

	got := tt.SnapshotForExport(0, false, "otlp")
	if len(got) != 1 || len(got[0].Spans) != 1 {
		t.Fatalf("want the completed span exported, got %d traces", len(got))
	}
	span := got[0].Spans[0]
	if len(span.Events) != 2 || !span.Error {
		t.Errorf("exported span has %d events, error=%v; want request and failed response", len(span.Events), span.Error)
	}
}

func TestAnOpenSpanIsExportedOnFlushOrAfterTheHold(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(tracedEvent(events.EventHTTPReq, 1_000_000), nil)

	if got := tt.SnapshotForExport(0, true, "otlp"); len(got) != 1 {
		t.Errorf("a shutdown flush exported %d traces, want the open span", len(got))
	}

	trace := tt.GetTrace("4bf92f3577b34da6a3ce929d0e0e4736")
	trace.mu.Lock()
	trace.Spans[0].firstSeen = time.Now().Add(-2 * maxOpenSpanHold)
	trace.mu.Unlock()
	if got := tt.SnapshotForExport(0, false, "zipkin"); len(got) != 1 {
		t.Errorf("a span past the hold exported %d traces, want 1", len(got))
	}
}

func TestARequestWithoutCorrelationIsNotHeld(t *testing.T) {
	tt := NewTraceTracker()
	ev := tracedEvent(events.EventHTTPReq, 1_000_000)
	ev.CorrelationID = 0
	tt.ProcessEvent(ev, nil)

	if got := tt.SnapshotForExport(0, false, "otlp"); len(got) != 1 {
		t.Errorf("exported %d traces; a request no response can join must not wait for one", len(got))
	}
}

func TestAnEarlierEventMovesTheSpanStartBack(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(tracedEvent(events.EventTCPSend, 5_000_000), nil)
	early := tracedEvent(events.EventTCPSend, 4_000_000)
	early.LatencyNS = 2_000_000
	tt.ProcessEvent(early, nil)

	span := onlySpan(t, tt)
	if want := 3 * time.Millisecond; span.Duration != want {
		t.Errorf("duration = %v, want %v from 2ms to 5ms", span.Duration, want)
	}
}

func TestASpanWithoutAttributesStillRecordsDroppedEvents(t *testing.T) {
	s := &Span{}
	for i := range maxEventsPerSpan + 2 {
		s.addEvent(tracedEvent(events.EventTCPSend, uint64(1_000_000+i)))
	}
	if got := s.Attributes["podtrace.dropped_events"]; got != "2" {
		t.Errorf("podtrace.dropped_events = %q, want 2", got)
	}
}

func TestEqualCountsAreOrderedByName(t *testing.T) {
	pct := NewPodCommunicationTracker("src", "ns")
	for _, pod := range []string{"zeta", "alpha", "mid"} {
		pct.ProcessEvent(&events.Event{Type: events.EventConnect, Timestamp: 1}, map[string]interface{}{"target_pod": pod, "target_namespace": "ns"})
	}
	var targets []string
	for _, s := range pct.GetSummary() {
		targets = append(targets, s.Target)
	}
	if strings.Join(targets, ",") != "alpha,mid,zeta" {
		t.Errorf("targets = %v, want name order among equal counts", targets)
	}

	pt := NewPoolTracker()
	for _, pool := range []string{"zeta", "alpha"} {
		pt.ProcessEvent(&events.Event{Type: events.EventPoolAcquire, Target: pool, Timestamp: 1})
	}
	for range 2 {
		pt.ProcessEvent(&events.Event{Type: events.EventPoolAcquire, Target: "busy", Timestamp: 1})
	}
	var ids []string
	for _, p := range pt.GetPoolSummary() {
		ids = append(ids, p.PoolID)
	}
	if strings.Join(ids, ",") != "busy,alpha,zeta" {
		t.Errorf("pools = %v, want most acquires first, then name order", ids)
	}
}
