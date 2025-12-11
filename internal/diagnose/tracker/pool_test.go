package tracker

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestNewPoolTracker(t *testing.T) {
	tracker := NewPoolTracker()
	if tracker == nil {
		t.Fatal("NewPoolTracker() returned nil")
	}
	if tracker.pools == nil {
		t.Fatal("NewPoolTracker() pools map is nil")
	}
}

func TestPoolTracker_ProcessEvent(t *testing.T) {
	tracker := NewPoolTracker()
	now := time.Now()
	baseTime := now.UnixNano()

	acquireEvent := &events.Event{
		Timestamp: uint64(baseTime),
		Type:      events.EventPoolAcquire,
		Target:    "test-pool",
	}

	tracker.ProcessEvent(acquireEvent)

	summaries := tracker.GetPoolSummary()
	if len(summaries) != 1 {
		t.Fatalf("GetPoolSummary() returned %d pools, want 1", len(summaries))
	}

	summary := summaries[0]
	if summary.PoolID != "test-pool" {
		t.Errorf("PoolID = %s, want test-pool", summary.PoolID)
	}
	if summary.AcquireCount != 1 {
		t.Errorf("AcquireCount = %d, want 1", summary.AcquireCount)
	}
	if summary.CurrentConns != 1 {
		t.Errorf("CurrentConns = %d, want 1", summary.CurrentConns)
	}
	if summary.MaxConns != 1 {
		t.Errorf("MaxConns = %d, want 1", summary.MaxConns)
	}
}

func TestPoolTracker_ProcessEvent_Release(t *testing.T) {
	tracker := NewPoolTracker()
	now := time.Now()
	baseTime := now.UnixNano()

	acquireEvent := &events.Event{
		Timestamp: uint64(baseTime),
		Type:      events.EventPoolAcquire,
		Target:    "test-pool",
	}

	releaseEvent := &events.Event{
		Timestamp: uint64(baseTime + 1000000),
		Type:      events.EventPoolRelease,
		Target:    "test-pool",
	}

	tracker.ProcessEvent(acquireEvent)
	tracker.ProcessEvent(releaseEvent)

	summaries := tracker.GetPoolSummary()
	summary := summaries[0]

	if summary.ReleaseCount != 1 {
		t.Errorf("ReleaseCount = %d, want 1", summary.ReleaseCount)
	}
	if summary.CurrentConns != 0 {
		t.Errorf("CurrentConns = %d, want 0", summary.CurrentConns)
	}
	if summary.ReuseRate != 1.0 {
		t.Errorf("ReuseRate = %f, want 1.0", summary.ReuseRate)
	}
}

func TestPoolTracker_ProcessEvent_Exhausted(t *testing.T) {
	tracker := NewPoolTracker()
	now := time.Now()
	baseTime := now.UnixNano()

	exhaustedEvent := &events.Event{
		Timestamp: uint64(baseTime),
		Type:      events.EventPoolExhausted,
		Target:    "test-pool",
		LatencyNS: 10000000,
	}

	tracker.ProcessEvent(exhaustedEvent)

	summaries := tracker.GetPoolSummary()
	summary := summaries[0]

	if summary.ExhaustedCount != 1 {
		t.Errorf("ExhaustedCount = %d, want 1", summary.ExhaustedCount)
	}
	if summary.MaxWaitTime != time.Duration(10000000) {
		t.Errorf("MaxWaitTime = %v, want %v", summary.MaxWaitTime, time.Duration(10000000))
	}
}

func TestPoolTracker_ProcessEvent_DefaultPoolID(t *testing.T) {
	tracker := NewPoolTracker()
	now := time.Now()
	baseTime := now.UnixNano()

	event := &events.Event{
		Timestamp: uint64(baseTime),
		Type:      events.EventPoolAcquire,
		Target:    "",
	}

	tracker.ProcessEvent(event)

	summaries := tracker.GetPoolSummary()
	if len(summaries) != 1 {
		t.Fatalf("GetPoolSummary() returned %d pools, want 1", len(summaries))
	}

	if summaries[0].PoolID != "default" {
		t.Errorf("PoolID = %s, want default", summaries[0].PoolID)
	}
}

func TestPoolTracker_ProcessEvent_NilEvent(t *testing.T) {
	tracker := NewPoolTracker()
	tracker.ProcessEvent(nil)

	summaries := tracker.GetPoolSummary()
	if len(summaries) != 0 {
		t.Errorf("GetPoolSummary() returned %d pools, want 0", len(summaries))
	}
}

func TestPoolTracker_MultiplePools(t *testing.T) {
	tracker := NewPoolTracker()
	now := time.Now()
	baseTime := now.UnixNano()

	tracker.ProcessEvent(&events.Event{
		Timestamp: uint64(baseTime),
		Type:      events.EventPoolAcquire,
		Target:    "pool1",
	})

	tracker.ProcessEvent(&events.Event{
		Timestamp: uint64(baseTime + 1000000),
		Type:      events.EventPoolAcquire,
		Target:    "pool2",
	})

	summaries := tracker.GetPoolSummary()
	if len(summaries) != 2 {
		t.Fatalf("GetPoolSummary() returned %d pools, want 2", len(summaries))
	}
}

func TestPoolTracker_PeakConnections(t *testing.T) {
	tracker := NewPoolTracker()
	now := time.Now()
	baseTime := now.UnixNano()

	for i := 0; i < 5; i++ {
		tracker.ProcessEvent(&events.Event{
			Timestamp: uint64(baseTime + int64(i*1000000)),
			Type:      events.EventPoolAcquire,
			Target:    "test-pool",
		})
	}

	for i := 0; i < 3; i++ {
		tracker.ProcessEvent(&events.Event{
			Timestamp: uint64(baseTime + int64((i+5)*1000000)),
			Type:      events.EventPoolRelease,
			Target:    "test-pool",
		})
	}

	summaries := tracker.GetPoolSummary()
	summary := summaries[0]

	if summary.MaxConns != 5 {
		t.Errorf("MaxConns = %d, want 5", summary.MaxConns)
	}
	if summary.CurrentConns != 2 {
		t.Errorf("CurrentConns = %d, want 2", summary.CurrentConns)
	}
}

func TestGetPoolSummaryFromEvents(t *testing.T) {
	now := time.Now()
	baseTime := now.UnixNano()

	acquireEvents := []*events.Event{
		{Timestamp: uint64(baseTime), Type: events.EventPoolAcquire, Target: "pool1"},
		{Timestamp: uint64(baseTime + 1000000), Type: events.EventPoolAcquire, Target: "pool1"},
	}

	releaseEvents := []*events.Event{
		{Timestamp: uint64(baseTime + 5000000), Type: events.EventPoolRelease, Target: "pool1"},
	}

	exhaustedEvents := []*events.Event{
		{Timestamp: uint64(baseTime + 10000000), Type: events.EventPoolExhausted, Target: "pool1", LatencyNS: 10000000},
	}

	summaries := GetPoolSummaryFromEvents(acquireEvents, releaseEvents, exhaustedEvents)

	if len(summaries) != 1 {
		t.Fatalf("GetPoolSummaryFromEvents() returned %d pools, want 1", len(summaries))
	}

	summary := summaries[0]
	if summary.AcquireCount != 2 {
		t.Errorf("AcquireCount = %d, want 2", summary.AcquireCount)
	}
	if summary.ReleaseCount != 1 {
		t.Errorf("ReleaseCount = %d, want 1", summary.ReleaseCount)
	}
	if summary.ExhaustedCount != 1 {
		t.Errorf("ExhaustedCount = %d, want 1", summary.ExhaustedCount)
	}
}

func TestGeneratePoolCorrelation(t *testing.T) {
	now := time.Now()
	baseTime := now.UnixNano()

	evs := []*events.Event{
		{Timestamp: uint64(baseTime), Type: events.EventPoolAcquire, Target: "pool1"},
		{Timestamp: uint64(baseTime + 1000000), Type: events.EventPoolRelease, Target: "pool1"},
		{Timestamp: uint64(baseTime + 2000000), Type: events.EventPoolExhausted, Target: "pool1", LatencyNS: 10000000},
	}

	result := GeneratePoolCorrelation(evs)
	if result == "" {
		t.Fatal("GeneratePoolCorrelation() returned empty string")
	}

	if !strings.Contains(result, "pool1") {
		t.Errorf("GeneratePoolCorrelation() result should contain pool1, got %q", result)
	}

	if !strings.Contains(result, "Connection Pool Tracking") {
		t.Errorf("GeneratePoolCorrelation() result should contain header, got %q", result)
	}

	result = GeneratePoolCorrelation([]*events.Event{})
	if result != "" {
		t.Errorf("GeneratePoolCorrelation() with empty events = %q, want empty string", result)
	}
}

func TestGeneratePoolCorrelation_MultiplePools(t *testing.T) {
	now := time.Now()
	baseTime := now.UnixNano()

	evs := []*events.Event{
		{Timestamp: uint64(baseTime), Type: events.EventPoolAcquire, Target: "pool1"},
		{Timestamp: uint64(baseTime + 1000000), Type: events.EventPoolAcquire, Target: "pool2"},
		{Timestamp: uint64(baseTime + 2000000), Type: events.EventPoolRelease, Target: "pool1"},
	}

	result := GeneratePoolCorrelation(evs)
	if result == "" {
		t.Fatal("GeneratePoolCorrelation() returned empty string")
	}

	if !strings.Contains(result, "Active pools: 2") {
		t.Errorf("GeneratePoolCorrelation() should show 2 pools, got %q", result)
	}
}

func TestGeneratePoolCorrelation_WithExhaustion(t *testing.T) {
	now := time.Now()
	baseTime := now.UnixNano()

	evs := []*events.Event{
		{Timestamp: uint64(baseTime), Type: events.EventPoolAcquire, Target: "pool1"},
		{Timestamp: uint64(baseTime + 10000000), Type: events.EventPoolExhausted, Target: "pool1", LatencyNS: 10000000},
		{Timestamp: uint64(baseTime + 20000000), Type: events.EventPoolRelease, Target: "pool1"},
	}

	result := GeneratePoolCorrelation(evs)
	if result == "" {
		t.Fatal("GeneratePoolCorrelation() returned empty string")
	}

	if !strings.Contains(result, "Exhaustion events: 1") {
		t.Errorf("GeneratePoolCorrelation() should show exhaustion events, got %q", result)
	}

	if !strings.Contains(result, "Avg wait time") {
		t.Errorf("GeneratePoolCorrelation() should show wait times, got %q", result)
	}
}

func TestDeterminePoolHealthFromSummary(t *testing.T) {
	tests := []struct {
		name    string
		summary PoolSummary
		want    string
	}{
		{
			name: "healthy pool",
			summary: PoolSummary{
				AcquireCount:   100,
				ReleaseCount:   100,
				ExhaustedCount: 0,
				ReuseRate:      1.0,
				MaxWaitTime:    100 * time.Millisecond,
			},
			want: "OK - Pool operating normally",
		},
		{
			name: "high exhaustion rate",
			summary: PoolSummary{
				AcquireCount:   100,
				ReleaseCount:   90,
				ExhaustedCount: 15,
				ReuseRate:      0.9,
			},
			want: "CRITICAL - High pool exhaustion rate (>10%)",
		},
		{
			name: "moderate exhaustion rate",
			summary: PoolSummary{
				AcquireCount:   100,
				ReleaseCount:   95,
				ExhaustedCount: 6,
				ReuseRate:      0.95,
			},
			want: "WARNING - Moderate pool exhaustion rate (>5%)",
		},
		{
			name: "low reuse rate",
			summary: PoolSummary{
				AcquireCount:   100,
				ReleaseCount:   40,
				ExhaustedCount: 0,
				ReuseRate:      0.4,
			},
			want: "WARNING - Low connection reuse rate (<50%)",
		},
		{
			name: "high wait times",
			summary: PoolSummary{
				AcquireCount:   100,
				ReleaseCount:   100,
				ExhaustedCount: 0,
				ReuseRate:      1.0,
				MaxWaitTime:    2000 * time.Millisecond,
			},
			want: "WARNING - High wait times detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determinePoolHealthFromSummary(tt.summary)
			if got != tt.want {
				t.Errorf("determinePoolHealthFromSummary() = %q, want %q", got, tt.want)
			}
		})
	}
}
