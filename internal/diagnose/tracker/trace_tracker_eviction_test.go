package tracker

import (
	"fmt"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func withTraceCap(t *testing.T, limit int) {
	t.Helper()
	saved := config.MaxTrackedTraces
	config.MaxTrackedTraces = limit
	t.Cleanup(func() { config.MaxTrackedTraces = saved })
}

func trackTrace(tt *TraceTracker, traceID string) {
	tt.ProcessEvent(&events.Event{
		TraceID:   traceID,
		SpanID:    "s",
		Timestamp: clock.WallToBPFTimestamp(time.Now()),
		Type:      events.EventHTTPReq,
	}, nil)
}

func TestAFloodOfTraceIDsDoesNotLockOutANewTrace(t *testing.T) {
	withTraceCap(t, 8)
	tt := NewTraceTracker()
	for i := 0; i < 100; i++ {
		trackTrace(tt, fmt.Sprintf("flood-%d", i))
	}

	trackTrace(tt, "legitimate")

	if tt.GetTrace("legitimate") == nil {
		t.Fatal("a new trace was refused because the tracker was full")
	}
	if got := tt.GetTraceCount(); got != 8 {
		t.Fatalf("tracked traces = %d, want the cap 8", got)
	}
	if got := tt.EvictedTraceCount(); got != 93 {
		t.Fatalf("evicted = %d, want 93", got)
	}
}

func TestAFullTrackerEvictsTheTraceIdleLongest(t *testing.T) {
	withTraceCap(t, 3)
	tt := NewTraceTracker()
	trackTrace(tt, "a")
	trackTrace(tt, "b")
	trackTrace(tt, "c")
	trackTrace(tt, "a")

	trackTrace(tt, "d")

	if tt.GetTrace("b") != nil {
		t.Error("b was idle longest and should have been evicted")
	}
	for _, id := range []string{"a", "c", "d"} {
		if tt.GetTrace(id) == nil {
			t.Errorf("trace %s was evicted although a longer-idle trace existed", id)
		}
	}
}

func TestCleanupKeepsTheEvictionOrderConsistent(t *testing.T) {
	withTraceCap(t, 2)
	tt := NewTraceTracker()
	trackTrace(tt, "old")
	tt.traces["old"].lastUpdate = time.Now().Add(-time.Hour)
	tt.CleanupOldTraces(time.Minute)
	trackTrace(tt, "x")
	trackTrace(tt, "y")

	if tt.GetTrace("x") == nil || tt.GetTrace("y") == nil {
		t.Fatal("a cleaned-up trace still occupied an eviction slot")
	}
	if got := tt.recency.Len(); got != 2 {
		t.Fatalf("recency list holds %d entries, want 2", got)
	}
	if got := tt.EvictedTraceCount(); got != 0 {
		t.Fatalf("evicted = %d, want 0", got)
	}
}
