package profiling

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/events"
)

func TestWindowCountsMatchesAScanPerWindow(t *testing.T) {
	evs := make([]*events.Event, 5000)
	for i := range evs {
		evs[i] = &events.Event{Timestamp: 1_000 + uint64(i*7919%30_000)}
	}
	origin := minEventTimestamp(evs)
	const windowNS, n = 1_000, 25

	got := windowCounts(evs, origin, windowNS, n)
	for w := range n {
		lo, hi := int64(w)*windowNS, int64(w+1)*windowNS
		want := 0
		for _, e := range evs {
			if off := eventOffsetNS(e, origin); off >= lo && off < hi {
				want++
			}
		}
		if got[w] != want {
			t.Errorf("window %d: %d events, want %d", w, got[w], want)
		}
	}
}

func TestBurstAndIODetectionOverALongSessionStaysLinear(t *testing.T) {
	duration := 8 * time.Hour
	evs := make([]*events.Event, 300_000)
	step := uint64(duration) / uint64(len(evs))
	for i := range evs {
		evs[i] = &events.Event{Type: events.EventTCPSend, Timestamp: 1 + uint64(i)*step}
	}

	began := time.Now()
	DetectBursts(evs, time.Now(), duration)
	AnalyzeIOPattern(evs, time.Now(), duration)
	if took := time.Since(began); took > 5*time.Second {
		t.Errorf("an 8h session took %v; the windows must be counted in one pass", took)
	}
}

func TestTimelineLabelsStartAtTheEarliestEvent(t *testing.T) {
	start := time.Now().Truncate(time.Second).Add(-time.Minute)
	first := start.Add(10 * time.Second)
	duration := 50 * time.Second

	var evs []*events.Event
	for i := range 20 {
		evs = append(evs, &events.Event{Timestamp: clock.WallToBPFTimestamp(first.Add(time.Duration(i) * time.Second))})
	}

	buckets := AnalyzeTimeline(evs, start, duration)
	if want := first.Format("15:04:05") + "-"; !strings.HasPrefix(buckets[0].Period, want) {
		t.Errorf("first bucket = %q, want it to start at the earliest event %s, not the collection start %s",
			buckets[0].Period, first.Format("15:04:05"), start.Format("15:04:05"))
	}
}

func TestBurstTimesNameWhenTheBurstHappened(t *testing.T) {
	start := time.Now().Truncate(time.Second).Add(-time.Minute)
	first := start.Add(10 * time.Second)
	duration := 40 * time.Second

	var evs []*events.Event
	for s := range 30 {
		n := 1
		if s == 20 {
			n = 200
		}
		for k := range n {
			at := first.Add(time.Duration(s)*time.Second + time.Duration(k)*time.Millisecond)
			evs = append(evs, &events.Event{Timestamp: clock.WallToBPFTimestamp(at)})
		}
	}

	bursts := DetectBursts(evs, start, duration)
	if len(bursts) != 1 {
		t.Fatalf("want one burst, got %d", len(bursts))
	}
	if want := first.Add(20 * time.Second); !bursts[0].Time.Equal(want) {
		t.Errorf("burst at %s, want %s", bursts[0].Time.Format("15:04:05"), want.Format("15:04:05"))
	}
}

func TestWindowCountsIgnoresAZeroWidthWindowAndEventsBeforeTheOrigin(t *testing.T) {
	evs := []*events.Event{{Timestamp: 100}, {Timestamp: 250}}
	if got := windowCounts(evs, 100, 0, 3); got[0]+got[1]+got[2] != 0 {
		t.Errorf("zero-width windows counted %v", got)
	}
	if got := windowCounts(evs, 200, 100, 3); got[0] != 1 || got[1]+got[2] != 0 {
		t.Errorf("counts = %v, want only the event after the origin", got)
	}
}
