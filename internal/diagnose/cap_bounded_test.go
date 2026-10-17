package diagnose

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestAddEvent_BoundedPastCap(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 5
	d.sampleIntN = admit

	const total = 18
	for i := 0; i < total; i++ {
		d.AddEvent(&events.Event{Type: events.EventHTTPResp, Error: 503, Bytes: uint64(i)})
	}

	got := d.GetEvents()
	if len(got) != d.maxEvents {
		t.Fatalf("buffer must stay bounded at %d, grew to %d", d.maxEvents, len(got))
	}
	for i, e := range got {
		want := uint64(total - d.maxEvents + i)
		if e.Bytes != want {
			t.Errorf("slot %d: id=%d, want %d (recent window, in order)", i, e.Bytes, want)
		}
	}
}

func TestAddEvent_ContextsStayAligned(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 4
	d.sampleIntN = admit
	for i := 0; i < 11; i++ {
		id := uint64(i)
		d.AddEventWithContext(
			&events.Event{Type: events.EventHTTPResp, Error: 500, Bytes: id},
			map[string]interface{}{"id": id},
		)
	}
	evs := d.GetEvents()
	ctxs := d.EventContexts()
	if len(evs) != len(ctxs) || len(evs) != d.maxEvents {
		t.Fatalf("len mismatch: events=%d contexts=%d cap=%d", len(evs), len(ctxs), d.maxEvents)
	}
	for i := range evs {
		if ctxs[i]["id"] != evs[i].Bytes {
			t.Errorf("slot %d: event id=%d but context id=%v (misaligned)", i, evs[i].Bytes, ctxs[i]["id"])
		}
	}
}

func TestAddEvent_NoDropCounterUnderCap(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 100
	for i := 0; i < 50; i++ {
		d.AddEvent(&events.Event{Type: events.EventHTTPResp, Bytes: uint64(i)})
	}
	if d.droppedEvents != 0 {
		t.Errorf("no events should be dropped under cap, got droppedEvents=%d", d.droppedEvents)
	}
}
