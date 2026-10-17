package diagnose

import (
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/events"
)

func admit(int) int    { return 0 }
func reject(n int) int { return n - 1 }
func TestRareEventTypesAreAlwaysKept(t *testing.T) {
	for _, typ := range []events.EventType{events.EventOOMKill, events.EventPageFault, events.EventNetDevError, events.EventRequestDone} {
		if !shouldSampleEvent(&events.Event{Type: typ}, reject) {
			t.Errorf("%v was sampled out", typ)
		}
	}
}

func TestAFailureIsSampledAtItsTypesRateLikeASuccess(t *testing.T) {
	for _, ev := range []*events.Event{
		{Type: events.EventConnect, Error: -111},
		{Type: events.EventTCPRecv, Error: -11},
		{Type: events.EventDNS, Error: 1},
	} {
		if shouldSampleEvent(ev, reject) {
			t.Errorf("%v with error %d was admitted unconditionally", ev.Type, ev.Error)
		}
		if !shouldSampleEvent(ev, admit) {
			t.Errorf("%v with error %d was not admitted on a winning draw", ev.Type, ev.Error)
		}
	}
}

func TestTheDrawUsesTheTypesRate(t *testing.T) {
	for typ, want := range map[events.EventType]int{
		events.EventDNS:           10,
		events.EventTCPSend:       50,
		events.EventRead:          100,
		events.EventType(9999):    config.EventSamplingRate,
		events.EventConnectResult: 20,
	} {
		var got int
		shouldSampleEvent(&events.Event{Type: typ}, func(n int) int { got = n; return 1 })
		if got != want {
			t.Errorf("%v drew from %d, want %d", typ, got, want)
		}
	}
}

func TestNilEventIsNotSampled(t *testing.T) {
	if shouldSampleEvent(nil, admit) {
		t.Error("nil event was sampled")
	}
}

func TestAFullBufferKeepsTheConnectionFailureRate(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 2000

	for i := range 400_000 {
		ev := &events.Event{Type: events.EventConnectResult, Timestamp: uint64(i + 1), Target: "10.0.0.1:80"}
		if i%100 == 0 {
			ev.Error = -111
		}
		d.AddEvent(ev)
	}

	if d.EventsSampledOut() == 0 {
		t.Fatal("the buffer never filled")
	}
	var failed, total int
	for _, e := range d.GetEvents() {
		if e.Type != events.EventConnectResult {
			continue
		}
		total++
		if e.Error != 0 {
			failed++
		}
	}
	rate := float64(failed) / float64(total) * 100
	if rate > 3 {
		t.Errorf("retained failure rate = %.1f%% (%d/%d), want about 1%%", rate, failed, total)
	}
	for _, issue := range detector.DetectIssues(d.GetEvents(), config.DefaultErrorRateThreshold, config.DefaultRTTThreshold) {
		if issue.ID == detector.IDConnectionFailureRate {
			t.Errorf("a 1%% failure rate raised %q once the buffer wrapped", issue.Message)
		}
	}
}

func TestAnAlternatingStreamKeepsBothSides(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1000

	for i := range 200_000 {
		typ := events.EventTCPSend
		if i%2 == 1 {
			typ = events.EventTCPRecv
		}
		d.AddEvent(&events.Event{Type: typ, Timestamp: uint64(i + 1)})
	}

	send, recv := len(d.FilterEvents(events.EventTCPSend)), len(d.FilterEvents(events.EventTCPRecv))
	if send == 0 || recv == 0 {
		t.Fatalf("send=%d recv=%d: one side of an alternating stream vanished", send, recv)
	}
	if ratio := float64(send) / float64(recv); ratio < 0.7 || ratio > 1.4 {
		t.Errorf("send/recv = %.2f, want about 1", ratio)
	}
}

func TestDrawsStayInRangeAcrossRefills(t *testing.T) {
	var draws sampleDraws
	seen := make([]int, 20)
	for range 10_000 {
		v := draws.intN(20)
		if v < 0 || v >= 20 {
			t.Fatalf("intN(20) = %d", v)
		}
		seen[v]++
	}
	for v, n := range seen {
		if n < 300 || n > 700 {
			t.Errorf("value %d drawn %d times in 10000, want about 500", v, n)
		}
	}
	if got := draws.intN(1); got != 0 {
		t.Errorf("intN(1) = %d, want 0", got)
	}
}
