package analyzer

import (
	"math"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestAverageConnectionsIsWeightedByTimeHeld(t *testing.T) {
	acquires := []*events.Event{
		{Type: events.EventPoolAcquire, Target: "a", Timestamp: 0},
		{Type: events.EventPoolAcquire, Target: "b", Timestamp: 0},
	}
	releases := []*events.Event{
		{Type: events.EventPoolRelease, Target: "a", Timestamp: 10},
		{Type: events.EventPoolRelease, Target: "b", Timestamp: 100},
	}

	stats := AnalyzePool(acquires, releases, nil)
	if want := 1.1; math.Abs(stats.AvgConnections-want) > 1e-9 {
		t.Errorf("AvgConnections = %v, want %v (two held for 10, one for 90, over 100)", stats.AvgConnections, want)
	}
	if stats.PeakConnections != 1 {
		t.Errorf("PeakConnections = %d, want the per-pool peak 1", stats.PeakConnections)
	}
}
