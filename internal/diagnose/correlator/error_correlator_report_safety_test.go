package correlator

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestSuggestionsDoNotCarryTerminalEscapes(t *testing.T) {
	ec := NewErrorCorrelator(time.Minute)
	ctx := map[string]interface{}{"target_pod": "web\x1b[2J", "target_service": "svc\x1b]0;pwn\x07"}
	for i := range 3 {
		ec.AddEvent(&events.Event{Type: events.EventConnect, Error: -111, Target: "10.0.0.1:80", Timestamp: uint64(i + 1)}, ctx)
	}

	report := ec.GetErrorSummary()
	if strings.ContainsAny(report, "\x1b\x07") {
		t.Errorf("summary carries terminal controls:\n%q", report)
	}
}

func TestSuggestionsAreInAStableOrder(t *testing.T) {
	ec := NewErrorCorrelator(time.Minute)
	for i, code := range []int32{-11, -111, -110, -2, -13, -11, -11, -11, -11, -11, -111, -110} {
		ec.AddEvent(&events.Event{Type: events.EventConnect, Error: code, Target: "10.0.0.1:80", Timestamp: uint64(i + 1)}, nil)
	}

	first := ec.generateSuggestions(ec.errors)
	for range 50 {
		got := ec.generateSuggestions(ec.errors)
		if strings.Join(got, "|") != strings.Join(first, "|") {
			t.Fatalf("suggestion order changed between runs:\n%v\n%v", first, got)
		}
	}
}

func TestTotalErrorsCountsBeyondTheRetainedBuffer(t *testing.T) {
	ec := NewErrorCorrelator(time.Minute)
	const n = maxRetainedErrors + 25
	for i := range n {
		ec.AddEvent(&events.Event{Type: events.EventConnect, Error: -111, Target: "10.0.0.1:80", Timestamp: uint64(i + 1)}, nil)
	}

	report := ec.GetErrorSummary()
	if !strings.Contains(report, "Total errors: 10025") {
		t.Errorf("want the true total, got:\n%s", report[:min(len(report), 300)])
	}
	if !strings.Contains(report, "most recent 10000") {
		t.Errorf("want the retention cap stated, got:\n%s", report[:min(len(report), 300)])
	}
}
