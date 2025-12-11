package analyzer

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestAnalyzePool(t *testing.T) {
	now := time.Now()
	baseTime := now.UnixNano()

	tests := []struct {
		name            string
		acquireEvents   []*events.Event
		releaseEvents   []*events.Event
		exhaustedEvents []*events.Event
		wantAcquires    int
		wantReleases    int
		wantExhausted   int
		wantReuseRate   float64
		wantPeak        int
	}{
		{
			name:            "empty events",
			acquireEvents:   []*events.Event{},
			releaseEvents:   []*events.Event{},
			exhaustedEvents: []*events.Event{},
			wantAcquires:    0,
			wantReleases:    0,
			wantExhausted:   0,
			wantReuseRate:   0,
			wantPeak:        0,
		},
		{
			name: "balanced acquire and release",
			acquireEvents: []*events.Event{
				{Timestamp: uint64(baseTime), Type: events.EventPoolAcquire, Target: "pool1"},
				{Timestamp: uint64(baseTime + 1000000), Type: events.EventPoolAcquire, Target: "pool1"},
			},
			releaseEvents: []*events.Event{
				{Timestamp: uint64(baseTime + 5000000), Type: events.EventPoolRelease, Target: "pool1"},
				{Timestamp: uint64(baseTime + 6000000), Type: events.EventPoolRelease, Target: "pool1"},
			},
			exhaustedEvents: []*events.Event{},
			wantAcquires:    2,
			wantReleases:    2,
			wantExhausted:   0,
			wantReuseRate:   1.0,
			wantPeak:        2,
		},
		{
			name: "pool exhaustion",
			acquireEvents: []*events.Event{
				{Timestamp: uint64(baseTime), Type: events.EventPoolAcquire, Target: "pool1"},
			},
			releaseEvents: []*events.Event{},
			exhaustedEvents: []*events.Event{
				{Timestamp: uint64(baseTime + 10000000), Type: events.EventPoolExhausted, Target: "pool1", LatencyNS: 10000000},
			},
			wantAcquires:  1,
			wantReleases:  0,
			wantExhausted: 1,
			wantReuseRate: 0,
			wantPeak:      1,
		},
		{
			name: "multiple pools",
			acquireEvents: []*events.Event{
				{Timestamp: uint64(baseTime), Type: events.EventPoolAcquire, Target: "pool1"},
				{Timestamp: uint64(baseTime + 1000000), Type: events.EventPoolAcquire, Target: "pool2"},
			},
			releaseEvents: []*events.Event{
				{Timestamp: uint64(baseTime + 5000000), Type: events.EventPoolRelease, Target: "pool1"},
			},
			exhaustedEvents: []*events.Event{},
			wantAcquires:    2,
			wantReleases:    1,
			wantExhausted:   0,
			wantReuseRate:   0.5,
			wantPeak:        1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := AnalyzePool(tt.acquireEvents, tt.releaseEvents, tt.exhaustedEvents)

			if stats.TotalAcquires != tt.wantAcquires {
				t.Errorf("TotalAcquires = %d, want %d", stats.TotalAcquires, tt.wantAcquires)
			}
			if stats.TotalReleases != tt.wantReleases {
				t.Errorf("TotalReleases = %d, want %d", stats.TotalReleases, tt.wantReleases)
			}
			if stats.ExhaustedCount != tt.wantExhausted {
				t.Errorf("ExhaustedCount = %d, want %d", stats.ExhaustedCount, tt.wantExhausted)
			}
			if stats.ReuseRate != tt.wantReuseRate {
				t.Errorf("ReuseRate = %f, want %f", stats.ReuseRate, tt.wantReuseRate)
			}
			if stats.PeakConnections != tt.wantPeak {
				t.Errorf("PeakConnections = %d, want %d", stats.PeakConnections, tt.wantPeak)
			}
		})
	}
}

func TestAnalyzePool_WaitTimes(t *testing.T) {
	now := time.Now()
	baseTime := now.UnixNano()

	exhaustedEvents := []*events.Event{
		{Timestamp: uint64(baseTime), Type: events.EventPoolExhausted, Target: "pool1", LatencyNS: 10000000},
		{Timestamp: uint64(baseTime + 1000000), Type: events.EventPoolExhausted, Target: "pool1", LatencyNS: 20000000},
		{Timestamp: uint64(baseTime + 2000000), Type: events.EventPoolExhausted, Target: "pool1", LatencyNS: 30000000},
	}

	stats := AnalyzePool([]*events.Event{}, []*events.Event{}, exhaustedEvents)

	if stats.ExhaustedCount != 3 {
		t.Errorf("ExhaustedCount = %d, want 3", stats.ExhaustedCount)
	}

	expectedAvg := time.Duration(20000000)
	if stats.AvgWaitTime != expectedAvg {
		t.Errorf("AvgWaitTime = %v, want %v", stats.AvgWaitTime, expectedAvg)
	}

	expectedMax := time.Duration(30000000)
	if stats.MaxWaitTime != expectedMax {
		t.Errorf("MaxWaitTime = %v, want %v", stats.MaxWaitTime, expectedMax)
	}
}

func TestAnalyzePool_DefaultPoolID(t *testing.T) {
	now := time.Now()
	baseTime := now.UnixNano()

	acquireEvents := []*events.Event{
		{Timestamp: uint64(baseTime), Type: events.EventPoolAcquire, Target: ""},
	}

	stats := AnalyzePool(acquireEvents, []*events.Event{}, []*events.Event{})

	if stats.TotalAcquires != 1 {
		t.Errorf("TotalAcquires = %d, want 1", stats.TotalAcquires)
	}
	if stats.PeakConnections != 1 {
		t.Errorf("PeakConnections = %d, want 1", stats.PeakConnections)
	}
}
