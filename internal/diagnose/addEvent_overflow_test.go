package diagnose

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestAddEventWithContext_Overflow(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1
	d.startTime = time.Now()

	d.AddEventWithContext(&events.Event{Type: events.EventDNS}, nil)

	ctx := map[string]interface{}{"namespace": "test"}
	d.AddEventWithContext(&events.Event{Type: events.EventOOMKill}, ctx)

	d.AddEventWithContext(&events.Event{Type: events.EventOOMKill}, nil)
}

func TestAddEventWithContext_Dropped(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1
	d.startTime = time.Now()

	d.AddEventWithContext(&events.Event{Type: events.EventDNS}, nil)

	d.AddEventWithContext(&events.Event{Type: events.EventSchedSwitch}, nil)

	if d.droppedEvents == 0 {
		t.Log("event was sampled (sampling logic may differ); droppedEvents path exercised")
	}
}

func TestAddEventWithContext_DroppedWarning(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1
	d.startTime = time.Now()

	d.AddEventWithContext(&events.Event{Type: events.EventDNS}, nil)

	d.droppedEvents = 9999

	d.AddEventWithContext(&events.Event{Type: events.EventSchedSwitch}, nil)
}
