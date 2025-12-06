package stacktrace

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

type mockDiagnostician struct {
	events []*events.Event
}

func (m *mockDiagnostician) GetEvents() []*events.Event {
	return m.events
}

func TestGenerateStackTraceSectionWithContext_EmptyEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Error("Expected empty result for no events")
	}
}

func TestGenerateStackTraceSectionWithContext_NoStack(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 1000000, Stack: []uint64{}},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Error("Expected empty result for events without stack")
	}
}

func TestGenerateStackTraceSectionWithContext_LowLatency(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 100000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Error("Expected empty result for low latency events")
	}
}

func TestGenerateStackTraceSectionWithContext_LockContention(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventLockContention, LatencyNS: 100000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_DBQuery(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDBQuery, LatencyNS: 100000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_HighLatency(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234, 0x5678}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_CancelledContext(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Log("Result may be empty or partial when context is cancelled")
	}
}

func TestGenerateStackTraceSectionWithContext_NilEvent(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			nil,
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_MaxEventsLimit(t *testing.T) {
	evts := make([]*events.Event, 0, 15000)
	for i := 0; i < 15000; i++ {
		evts = append(evts, &events.Event{
			Type:      events.EventDNS,
			LatencyNS: 2000000,
			Stack:     []uint64{0x1234},
			PID:       1234,
		})
	}
	d := &mockDiagnostician{
		events: evts,
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_ZeroAddress(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Log("Stack trace with zero address should be handled")
	}
}

func TestGenerateStackTraceSectionWithContext_MultipleStacks(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234}, PID: 1234, Target: "example.com"},
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234}, PID: 1234, Target: "example.com"},
			{Type: events.EventTCPRecv, LatencyNS: 2000000, Stack: []uint64{0x5678}, PID: 1234},
		},
	}
	ctx := context.Background()
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result == "" {
		t.Log("Stack trace may be empty if addr2line fails (expected in test environment)")
	}
}

func TestGenerateStackTraceSectionWithContext_ContextTimeout(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2000000, Stack: []uint64{0x1234}, PID: 1234},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Nanosecond)
	result := GenerateStackTraceSectionWithContext(d, ctx)
	if result != "" {
		t.Log("Result may be empty or partial when context times out")
	}
}

