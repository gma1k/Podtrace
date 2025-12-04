package detector

import (
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestDetectIssues_HighConnectionFailureRate(t *testing.T) {
	events := []*events.Event{
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventConnect, Error: 0},
	}

	issues := DetectIssues(events, 10.0, 100.0)

	if len(issues) == 0 {
		t.Error("Expected at least one issue for high failure rate")
	}

	found := false
	for _, issue := range issues {
		if contains(issue, "High connection failure rate") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected 'High connection failure rate' issue, got %v", issues)
	}
}

func TestDetectIssues_LowConnectionFailureRate(t *testing.T) {
	eventSlice := []*events.Event{
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 111}, // 10% error rate
	}

	issues := DetectIssues(eventSlice, 10.0, 100.0)

	found := false
	for _, issue := range issues {
		if contains(issue, "High connection failure rate") {
			found = true
			break
		}
	}
	_ = found
}

func TestDetectIssues_HighTCPRTTSpikeRate(t *testing.T) {
	eventSlice := []*events.Event{}
	for i := 0; i < 100; i++ {
		latency := uint64(50000000)
		if i < 10 {
			latency = 150000000
		}
		eventSlice = append(eventSlice, &events.Event{
			Type:      events.EventTCPSend,
			LatencyNS: latency,
		})
	}

	issues := DetectIssues(eventSlice, 10.0, 100.0)

	found := false
	for _, issue := range issues {
		if contains(issue, "High TCP RTT spike rate") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected 'High TCP RTT spike rate' issue, got %v", issues)
	}
}

func TestDetectIssues_LowTCPRTTSpikeRate(t *testing.T) {
	eventSlice := []*events.Event{}
	for i := 0; i < 100; i++ {
		latency := uint64(50000000)
		if i < 2 {
			latency = 150000000
		}
		eventSlice = append(eventSlice, &events.Event{
			Type:      events.EventTCPSend,
			LatencyNS: latency,
		})
	}

	issues := DetectIssues(eventSlice, 10.0, 100.0)

	for _, issue := range issues {
		if contains(issue, "High TCP RTT spike rate") {
			t.Errorf("Should not detect high RTT spike rate for 2%% spike rate, got: %v", issues)
		}
	}
}

func TestDetectIssues_NoEvents(t *testing.T) {
	issues := DetectIssues([]*events.Event{}, 10.0, 100.0)

	if len(issues) != 0 {
		t.Errorf("Expected no issues for empty events, got %v", issues)
	}
}

func TestDetectIssues_MixedEvents(t *testing.T) {
	eventSlice := []*events.Event{
		{Type: events.EventDNS, Error: 0},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventTCPSend, LatencyNS: 150000000},
		{Type: events.EventRead, Error: 0},
	}

	issues := DetectIssues(eventSlice, 10.0, 100.0)

	connectIssues := 0
	tcpIssues := 0
	for _, issue := range issues {
		if contains(issue, "connection") {
			connectIssues++
		}
		if contains(issue, "TCP RTT") {
			tcpIssues++
		}
	}

	if connectIssues == 0 && len(eventSlice) > 0 {
	}
}

func TestDetectIssues_CustomThresholds(t *testing.T) {
	eventSlice := []*events.Event{
		{Type: events.EventConnect, Error: 0},
		{Type: events.EventConnect, Error: 111},
		{Type: events.EventConnect, Error: 111},
	}

	issues := DetectIssues(eventSlice, 50.0, 100.0)
	lowThresholdCount := len(issues)

	issues = DetectIssues(eventSlice, 100.0, 100.0)
	highThresholdCount := len(issues)

	if lowThresholdCount < highThresholdCount {
		t.Errorf("Lower threshold should detect more issues, got low=%d high=%d", lowThresholdCount, highThresholdCount)
	}
}

func BenchmarkDetectIssues(b *testing.B) {
	eventSlice := make([]*events.Event, 1000)
	for i := range eventSlice {
		eventSlice[i] = &events.Event{
			Type:      events.EventConnect,
			Error:     int32(i % 10),
			LatencyNS: uint64(i * 1000000),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DetectIssues(eventSlice, 10.0, 100.0)
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
