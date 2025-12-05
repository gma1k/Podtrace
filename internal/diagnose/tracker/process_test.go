package tracker

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestAnalyzeProcessActivity_UsesProcessNameFromEvents(t *testing.T) {
	evs := []*events.Event{
		{PID: 1234, ProcessName: "proc-a"},
		{PID: 1234, ProcessName: "proc-a"},
		{PID: 5678, ProcessName: "proc-b"},
	}

	pids := AnalyzeProcessActivity(evs)
	if len(pids) != 2 {
		t.Fatalf("expected 2 pid entries, got %d", len(pids))
	}
	if pids[0].Name == "" || pids[1].Name == "" {
		t.Fatalf("expected names to be populated from events")
	}
}

func TestAnalyzeProcessActivity_Empty(t *testing.T) {
	result := AnalyzeProcessActivity([]*events.Event{})
	if len(result) != 0 {
		t.Errorf("Expected empty result, got %d items", len(result))
	}
}

func TestAnalyzeProcessActivity_SinglePID(t *testing.T) {
	events := []*events.Event{
		{PID: 1234, ProcessName: "test", Type: events.EventDNS},
		{PID: 1234, ProcessName: "test", Type: events.EventConnect},
		{PID: 1234, ProcessName: "test", Type: events.EventRead},
	}

	result := AnalyzeProcessActivity(events)
	if len(result) != 1 {
		t.Errorf("Expected 1 PID, got %d", len(result))
	}
	if result[0].Pid != 1234 {
		t.Errorf("Expected PID 1234, got %d", result[0].Pid)
	}
	if result[0].Count != 3 {
		t.Errorf("Expected 3 events, got %d", result[0].Count)
	}
	if result[0].Percentage != 100.0 {
		t.Errorf("Expected 100%%, got %.2f", result[0].Percentage)
	}
}

func TestAnalyzeProcessActivity_MultiplePIDs(t *testing.T) {
	events := []*events.Event{
		{PID: 1234, ProcessName: "test1", Type: events.EventDNS},
		{PID: 1234, ProcessName: "test1", Type: events.EventConnect},
		{PID: 5678, ProcessName: "test2", Type: events.EventRead},
	}

	result := AnalyzeProcessActivity(events)
	if len(result) != 2 {
		t.Errorf("Expected 2 PIDs, got %d", len(result))
	}
	if result[0].Count < result[1].Count {
		t.Error("Results should be sorted by count descending")
	}
}

func TestAnalyzeProcessActivity_NoProcessName(t *testing.T) {
	events := []*events.Event{
		{PID: 1234, Type: events.EventDNS},
	}

	result := AnalyzeProcessActivity(events)
	if len(result) != 1 {
		t.Errorf("Expected 1 PID, got %d", len(result))
	}
	if result[0].Name == "" {
		t.Log("Process name is empty (may be expected if /proc not accessible)")
	}
}
