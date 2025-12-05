package main

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestFilterEvents(t *testing.T) {
	tests := []struct {
		name     string
		filter   string
		events   []*events.Event
		expected int
	}{
		{
			name:   "dns filter",
			filter: "dns",
			events: []*events.Event{
				{Type: events.EventDNS},
				{Type: events.EventConnect},
				{Type: events.EventDNS},
			},
			expected: 2,
		},
		{
			name:   "net filter",
			filter: "net",
			events: []*events.Event{
				{Type: events.EventConnect},
				{Type: events.EventTCPSend},
				{Type: events.EventDNS},
			},
			expected: 2,
		},
		{
			name:   "fs filter",
			filter: "fs",
			events: []*events.Event{
				{Type: events.EventRead},
				{Type: events.EventWrite},
				{Type: events.EventConnect},
			},
			expected: 2,
		},
		{
			name:   "cpu filter",
			filter: "cpu",
			events: []*events.Event{
				{Type: events.EventSchedSwitch},
				{Type: events.EventConnect},
			},
			expected: 1,
		},
		{
			name:   "proc filter",
			filter: "proc",
			events: []*events.Event{
				{Type: events.EventExec},
				{Type: events.EventFork},
				{Type: events.EventConnect},
			},
			expected: 2,
		},
		{
			name:   "multiple filters",
			filter: "dns,net",
			events: []*events.Event{
				{Type: events.EventDNS},
				{Type: events.EventConnect},
				{Type: events.EventRead},
			},
			expected: 2,
		},
		{
			name:   "empty filter",
			filter: "",
			events: []*events.Event{
				{Type: events.EventDNS},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := make(chan *events.Event, len(tt.events))
			out := make(chan *events.Event, len(tt.events))

			go func() {
				defer close(in)
				for _, e := range tt.events {
					in <- e
				}
			}()

			go filterEvents(in, out, tt.filter)

			count := 0
			for range out {
				count++
			}

			if count != tt.expected {
				t.Errorf("Expected %d events, got %d", tt.expected, count)
			}
		})
	}
}

func TestFilterEvents_NilEvent(t *testing.T) {
	in := make(chan *events.Event, 1)
	out := make(chan *events.Event, 1)

	go func() {
		defer close(in)
		in <- nil
		in <- &events.Event{Type: events.EventDNS}
	}()

	go filterEvents(in, out, "dns")

	count := 0
	for range out {
		count++
	}

	if count != 1 {
		t.Errorf("Expected 1 event (nil should be filtered), got %d", count)
	}
}

func TestFilterEvents_ChannelFull(t *testing.T) {
	in := make(chan *events.Event, 1)
	out := make(chan *events.Event)

	go func() {
		defer close(in)
		in <- &events.Event{Type: events.EventDNS}
	}()

	go filterEvents(in, out, "dns")

	select {
	case <-out:
	case <-time.After(100 * time.Millisecond):
	}
}

func TestFilterEvents_AllEventTypes(t *testing.T) {
	tests := []struct {
		name          string
		filter        string
		event         *events.Event
		shouldInclude bool
	}{
		{"TCPRecv with net filter", "net", &events.Event{Type: events.EventTCPRecv}, true},
		{"EventOpen with proc filter", "proc", &events.Event{Type: events.EventOpen}, true},
		{"EventClose with proc filter", "proc", &events.Event{Type: events.EventClose}, true},
		{"EventFsync with fs filter", "fs", &events.Event{Type: events.EventFsync}, true},
		{"whitespace in filter", " dns , net ", &events.Event{Type: events.EventDNS}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := make(chan *events.Event, 1)
			out := make(chan *events.Event, 1)

			go func() {
				defer close(in)
				in <- tt.event
			}()

			go filterEvents(in, out, tt.filter)

			select {
			case event := <-out:
				if !tt.shouldInclude && event != nil {
					t.Errorf("Expected event to be filtered out")
				}
				if tt.shouldInclude && event == nil {
					t.Errorf("Expected event to be included")
				}
			case <-time.After(100 * time.Millisecond):
				if tt.shouldInclude {
					t.Errorf("Expected event but got timeout")
				}
			}
		})
	}
}

func TestFilterEvents_EmptyFilterMap(t *testing.T) {
	in := make(chan *events.Event, 2)
	out := make(chan *events.Event, 2)

	go func() {
		defer close(in)
		in <- &events.Event{Type: events.EventDNS}
		in <- &events.Event{Type: events.EventConnect}
	}()

	go filterEvents(in, out, "invalid,filter")

	count := 0
	for range out {
		count++
	}

	if count != 0 {
		t.Errorf("Expected 0 events with invalid filter, got %d", count)
	}
}

func TestFilterEvents_MultipleFilters(t *testing.T) {
	in := make(chan *events.Event, 5)
	out := make(chan *events.Event, 5)

	events := []*events.Event{
		{Type: events.EventDNS},
		{Type: events.EventConnect},
		{Type: events.EventRead},
		{Type: events.EventSchedSwitch},
		{Type: events.EventExec},
	}

	go func() {
		defer close(in)
		for _, e := range events {
			in <- e
		}
	}()

	go filterEvents(in, out, "dns,net,fs,cpu,proc")

	count := 0
	for range out {
		count++
	}

	if count != 5 {
		t.Errorf("Expected 5 events, got %d", count)
	}
}
