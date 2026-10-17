package report

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/analyzer"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/events"
)

func TestCurrentUsageIsTheLatestSampleNotTheSum(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventResourceLimit, TCPState: 1, Error: 82, Bytes: 800 << 20, Timestamp: 1},
		{Type: events.EventResourceLimit, TCPState: 1, Error: 84, Bytes: 820 << 20, Timestamp: 3},
		{Type: events.EventResourceLimit, TCPState: 1, Error: 83, Bytes: 810 << 20, Timestamp: 2},
	}}

	got := GenerateResourceSection(d)
	if !strings.Contains(got, "Current usage: "+analyzer.FormatBytes(820<<20)) {
		t.Errorf("want the latest sample (820 MiB) as current usage:\n%s", got)
	}
}

func TestResourceSectionOrderIsStable(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventResourceLimit, TCPState: 2, Error: 96, Timestamp: 1},
		{Type: events.EventResourceLimit, TCPState: 0, Error: 91, Timestamp: 2},
		{Type: events.EventResourceLimit, TCPState: 1, Error: 81, Timestamp: 3},
		{Type: events.EventResourceLimit, TCPState: 0, Error: 85, Timestamp: 4},
		{Type: events.EventResourceLimit, TCPState: 0, Error: 97, Timestamp: 5},
	}}

	first := GenerateResourceSection(d)
	for range 50 {
		if got := GenerateResourceSection(d); got != first {
			t.Fatalf("output changed between runs:\n%s\n---\n%s", first, got)
		}
	}
	cpu, mem, io := strings.Index(first, "CPU:"), strings.Index(first, "Memory:"), strings.Index(first, "I/O:")
	if cpu >= mem || mem >= io {
		t.Errorf("want CPU, Memory, I/O in order:\n%s", first)
	}
	if e, c, w := strings.Index(first, "EMERGENCY: 1"), strings.Index(first, "CRITICAL: 1"), strings.Index(first, "WARNING: 1"); e > c || c > w {
		t.Errorf("want alerts most severe first:\n%s", first)
	}
}

func TestConnectionErrnoBreakdownIsMostFrequentFirst(t *testing.T) {
	var evs []*events.Event
	for range 3 {
		evs = append(evs, &events.Event{Type: events.EventConnect, Error: -111, Target: "a:1"})
	}
	evs = append(evs,
		&events.Event{Type: events.EventConnect, Error: -110, Target: "a:1"},
		&events.Event{Type: events.EventConnect, Error: -113, Target: "a:1"},
	)
	d := &mockDiagnostician{events: evs}

	got := GenerateConnectionSection(d, time.Second)
	refused, timedOut, noRoute := strings.Index(got, "Error -111"), strings.Index(got, "Error -110"), strings.Index(got, "Error -113")
	if refused < 0 || refused > noRoute || noRoute > timedOut {
		t.Errorf("want -111 (3), then -113 and -110 by code:\n%s", got)
	}
}

func TestReleasesWithoutAcquiresAreNotALeak(t *testing.T) {
	stats := analyzer.PoolStats{TotalReleases: 4}
	if got := determinePoolHealth(stats); strings.Contains(got, "leak") {
		t.Errorf("health = %q for releases of connections acquired before tracing began", got)
	}
	summary := tracker.PoolSummary{PoolID: "db", ReleaseCount: 4}
	if got := determinePoolHealthFromSummary(summary); strings.Contains(got, "leak") {
		t.Errorf("summary health = %q for releases only", got)
	}
}
