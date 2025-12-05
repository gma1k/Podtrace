package tracker

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestConnectionTracker_ProcessEventAndSummary(t *testing.T) {
	ct := NewConnectionTracker()
	now := time.Now()

	connect := &events.Event{
		Type:      events.EventConnect,
		Target:    "example.com",
		Error:     0,
		Timestamp: uint64(now.UnixNano()),
	}
	send := &events.Event{
		Type:      events.EventTCPSend,
		Target:    "example.com",
		LatencyNS: uint64(time.Millisecond * 10),
		Timestamp: uint64(now.Add(time.Millisecond).UnixNano()),
	}
	recv := &events.Event{
		Type:      events.EventTCPRecv,
		Target:    "example.com",
		LatencyNS: uint64(time.Millisecond * 5),
		Timestamp: uint64(now.Add(2 * time.Millisecond).UnixNano()),
	}

	ct.ProcessEvent(connect)
	ct.ProcessEvent(send)
	ct.ProcessEvent(recv)

	summaries := ct.GetConnectionSummary()
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if summaries[0].TotalOps != 2 {
		t.Fatalf("expected 2 total ops, got %d", summaries[0].TotalOps)
	}
}

func TestGenerateConnectionCorrelation(t *testing.T) {
	now := time.Now()
	evs := []*events.Event{
		{
			Type:      events.EventConnect,
			Target:    "example.com",
			Error:     0,
			Timestamp: uint64(now.UnixNano()),
		},
		{
			Type:      events.EventTCPSend,
			Target:    "example.com",
			LatencyNS: uint64(time.Millisecond * 10),
			Timestamp: uint64(now.Add(time.Millisecond).UnixNano()),
		},
	}

	report := GenerateConnectionCorrelation(evs)
	if report == "" {
		t.Fatalf("expected non-empty correlation report")
	}
}

func TestConnectionTracker_ProcessEvent(t *testing.T) {
	tracker := NewConnectionTracker()

	tests := []struct {
		name  string
		event *events.Event
	}{
		{"nil event", nil},
		{"connect event", &events.Event{Type: events.EventConnect, Target: "example.com:80", Error: 0}},
		{"connect error", &events.Event{Type: events.EventConnect, Target: "example.com:80", Error: 1}},
		{"tcp send", &events.Event{Type: events.EventTCPSend, Target: "example.com:80"}},
		{"tcp recv", &events.Event{Type: events.EventTCPRecv, Target: "example.com:80"}},
		{"other event", &events.Event{Type: events.EventDNS, Target: "example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker.ProcessEvent(tt.event)
		})
	}
}

func TestConnectionTracker_SendRecvWithoutConnect(t *testing.T) {
	tracker := NewConnectionTracker()

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventTCPSend,
		Target:    "example.com:80",
		LatencyNS: 1000000,
		Timestamp: uint64(time.Now().UnixNano()),
	})

	summaries := tracker.GetConnectionSummary()
	if len(summaries) != 1 {
		t.Errorf("Expected 1 connection, got %d", len(summaries))
	}
	if summaries[0].SendCount != 1 {
		t.Errorf("Expected 1 send, got %d", summaries[0].SendCount)
	}
}

func TestGenerateConnectionCorrelation_Empty(t *testing.T) {
	result := GenerateConnectionCorrelation([]*events.Event{})
	if result != "" {
		t.Error("Expected empty string for empty events")
	}
}

func TestConnectionTracker_ProcessEvent_ConnectEmptyTarget(t *testing.T) {
	tracker := NewConnectionTracker()
	tracker.ProcessEvent(&events.Event{
		Type:   events.EventConnect,
		Target: "",
		Error:  0,
	})
	summaries := tracker.GetConnectionSummary()
	if len(summaries) != 0 {
		t.Errorf("Expected 0 connections for empty target, got %d", len(summaries))
	}
}

func TestConnectionTracker_ProcessEvent_ConnectWithError(t *testing.T) {
	tracker := NewConnectionTracker()
	tracker.ProcessEvent(&events.Event{
		Type:   events.EventConnect,
		Target: "example.com:80",
		Error:  1,
	})
	summaries := tracker.GetConnectionSummary()
	if len(summaries) != 0 {
		t.Errorf("Expected 0 connections for connect with error, got %d", len(summaries))
	}
}

func TestConnectionTracker_ProcessEvent_TCPEmptyTarget(t *testing.T) {
	tracker := NewConnectionTracker()
	tracker.ProcessEvent(&events.Event{
		Type:   events.EventTCPSend,
		Target: "",
	})
	summaries := tracker.GetConnectionSummary()
	if len(summaries) != 0 {
		t.Errorf("Expected 0 connections for empty target, got %d", len(summaries))
	}
}

func TestConnectionTracker_ProcessEvent_MultipleOperations(t *testing.T) {
	tracker := NewConnectionTracker()
	now := time.Now()
	target := "example.com:80"

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventConnect,
		Target:    target,
		Error:     0,
		Timestamp: uint64(now.UnixNano()),
	})

	for i := 0; i < 5; i++ {
		tracker.ProcessEvent(&events.Event{
			Type:      events.EventTCPSend,
			Target:    target,
			LatencyNS: 1000000,
			Timestamp: uint64(now.Add(time.Duration(i) * time.Millisecond).UnixNano()),
		})
	}

	for i := 0; i < 3; i++ {
		tracker.ProcessEvent(&events.Event{
			Type:      events.EventTCPRecv,
			Target:    target,
			LatencyNS: 2000000,
			Timestamp: uint64(now.Add(time.Duration(i+5) * time.Millisecond).UnixNano()),
		})
	}

	summaries := tracker.GetConnectionSummary()
	if len(summaries) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(summaries))
	}
	if summaries[0].SendCount != 5 {
		t.Errorf("Expected 5 sends, got %d", summaries[0].SendCount)
	}
	if summaries[0].RecvCount != 3 {
		t.Errorf("Expected 3 recvs, got %d", summaries[0].RecvCount)
	}
	if summaries[0].TotalOps != 8 {
		t.Errorf("Expected 8 total ops, got %d", summaries[0].TotalOps)
	}
}

func TestConnectionTracker_GetConnectionSummary_ZeroOps(t *testing.T) {
	tracker := NewConnectionTracker()
	now := time.Now()

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventConnect,
		Target:    "example.com:80",
		Error:     0,
		Timestamp: uint64(now.UnixNano()),
	})

	summaries := tracker.GetConnectionSummary()
	if len(summaries) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(summaries))
	}
	if summaries[0].TotalOps != 0 {
		t.Errorf("Expected 0 total ops, got %d", summaries[0].TotalOps)
	}
	if summaries[0].AvgLatency != 0 {
		t.Errorf("Expected 0 avg latency, got %v", summaries[0].AvgLatency)
	}
}

func TestConnectionTracker_GetConnectionSummary_MultipleConnections(t *testing.T) {
	tracker := NewConnectionTracker()
	now := time.Now()

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventConnect,
		Target:    "example.com:80",
		Error:     0,
		Timestamp: uint64(now.UnixNano()),
	})
	tracker.ProcessEvent(&events.Event{
		Type:      events.EventTCPSend,
		Target:    "example.com:80",
		LatencyNS: 1000000,
		Timestamp: uint64(now.Add(time.Millisecond).UnixNano()),
	})

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventConnect,
		Target:    "test.com:443",
		Error:     0,
		Timestamp: uint64(now.Add(2 * time.Millisecond).UnixNano()),
	})
	tracker.ProcessEvent(&events.Event{
		Type:      events.EventTCPSend,
		Target:    "test.com:443",
		LatencyNS: 2000000,
		Timestamp: uint64(now.Add(3 * time.Millisecond).UnixNano()),
	})
	tracker.ProcessEvent(&events.Event{
		Type:      events.EventTCPSend,
		Target:    "test.com:443",
		LatencyNS: 2000000,
		Timestamp: uint64(now.Add(4 * time.Millisecond).UnixNano()),
	})

	summaries := tracker.GetConnectionSummary()
	if len(summaries) != 2 {
		t.Fatalf("Expected 2 connections, got %d", len(summaries))
	}
	if summaries[0].TotalOps < summaries[1].TotalOps {
		t.Error("Summaries should be sorted by TotalOps descending")
	}
}

func TestGenerateConnectionCorrelation_ManyConnections(t *testing.T) {
	now := time.Now()
	var evs []*events.Event

	for i := 0; i < 20; i++ {
		target := fmt.Sprintf("example%d.com:80", i)
		evs = append(evs, &events.Event{
			Type:      events.EventConnect,
			Target:    target,
			Error:     0,
			Timestamp: uint64(now.Add(time.Duration(i) * time.Millisecond).UnixNano()),
		})
		evs = append(evs, &events.Event{
			Type:      events.EventTCPSend,
			Target:    target,
			LatencyNS: 1000000,
			Timestamp: uint64(now.Add(time.Duration(i+1) * time.Millisecond).UnixNano()),
		})
	}

	report := GenerateConnectionCorrelation(evs)
	if report == "" {
		t.Fatal("Expected non-empty correlation report")
	}
	if !strings.Contains(report, "Connection Correlation") {
		t.Error("Expected report to contain 'Connection Correlation'")
	}
}

func TestConnectionTracker_ProcessEvent_TCPRecvWithoutConnect(t *testing.T) {
	tracker := NewConnectionTracker()
	now := time.Now()

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventTCPRecv,
		Target:    "example.com:80",
		LatencyNS: 1000000,
		Timestamp: uint64(now.UnixNano()),
	})

	summaries := tracker.GetConnectionSummary()
	if len(summaries) != 1 {
		t.Errorf("Expected 1 connection, got %d", len(summaries))
	}
	if summaries[0].RecvCount != 1 {
		t.Errorf("Expected 1 recv, got %d", summaries[0].RecvCount)
	}
}

func TestConnectionTracker_ProcessEvent_TCPWithExistingConnection(t *testing.T) {
	tracker := NewConnectionTracker()
	now := time.Now()
	target := "example.com:80"

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventConnect,
		Target:    target,
		Error:     0,
		Timestamp: uint64(now.UnixNano()),
	})

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventTCPSend,
		Target:    target,
		LatencyNS: 1000000,
		Timestamp: uint64(now.Add(time.Millisecond).UnixNano()),
	})

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventTCPRecv,
		Target:    target,
		LatencyNS: 2000000,
		Timestamp: uint64(now.Add(2 * time.Millisecond).UnixNano()),
	})

	summaries := tracker.GetConnectionSummary()
	if len(summaries) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(summaries))
	}
	if summaries[0].SendCount != 1 {
		t.Errorf("Expected 1 send, got %d", summaries[0].SendCount)
	}
	if summaries[0].RecvCount != 1 {
		t.Errorf("Expected 1 recv, got %d", summaries[0].RecvCount)
	}
	if summaries[0].TotalOps != 2 {
		t.Errorf("Expected 2 total ops, got %d", summaries[0].TotalOps)
	}
}

func TestConnectionTracker_GetConnectionSummary_WithLatency(t *testing.T) {
	tracker := NewConnectionTracker()
	now := time.Now()
	target := "example.com:80"

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventTCPSend,
		Target:    target,
		LatencyNS: 10000000,
		Timestamp: uint64(now.UnixNano()),
	})

	tracker.ProcessEvent(&events.Event{
		Type:      events.EventTCPRecv,
		Target:    target,
		LatencyNS: 20000000,
		Timestamp: uint64(now.Add(time.Millisecond).UnixNano()),
	})

	summaries := tracker.GetConnectionSummary()
	if len(summaries) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(summaries))
	}
	if summaries[0].AvgLatency == 0 {
		t.Error("Expected non-zero average latency")
	}
	if summaries[0].AvgLatency.Nanoseconds() != 15000000 {
		t.Errorf("Expected 15ms avg latency, got %v", summaries[0].AvgLatency)
	}
}
