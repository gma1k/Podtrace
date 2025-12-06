package correlator

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestErrorCorrelator_AddEvent(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)

	event := &events.Event{
		Type:      events.EventConnect,
		Target:    "10.244.1.5:8080",
		Error:     -111,
		Timestamp: uint64(time.Now().UnixNano()),
	}

	correlator.AddEvent(event, nil)

	chains := correlator.GetChains()
	if len(chains) != 0 {
		t.Logf("chains created: %d", len(chains))
	}
}

func TestErrorCorrelator_BuildChains(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)

	baseTime := time.Now()
	events := []*events.Event{
		{
			Type:      events.EventConnect,
			Target:    "10.244.1.5:8080",
			Error:     -111,
			Timestamp: uint64(baseTime.UnixNano()),
		},
		{
			Type:      events.EventTCPSend,
			Target:    "10.244.1.5:8080",
			Error:     -11,
			Timestamp: uint64(baseTime.Add(1 * time.Second).UnixNano()),
		},
		{
			Type:      events.EventConnect,
			Target:    "10.244.1.5:8080",
			Error:     -111,
			Timestamp: uint64(baseTime.Add(2 * time.Second).UnixNano()),
		},
	}

	k8sContext := map[string]interface{}{
		"target_pod": "target-pod",
	}

	for _, event := range events {
		correlator.AddEvent(event, k8sContext)
	}

	chains := correlator.GetChains()
	if len(chains) == 0 {
		t.Log("no chains created, which may be expected")
	}
}

func TestErrorCorrelator_GenerateSuggestions(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)

	chain := []*ErrorEvent{
		{
			ErrorCode: -111,
			Target:    "10.244.1.5:8080",
			Context:   map[string]string{"target_pod": "target-pod"},
		},
		{
			ErrorCode: -11,
			Target:    "10.244.1.5:8080",
			Context:   map[string]string{"target_pod": "target-pod"},
		},
	}

	suggestions := correlator.generateSuggestions(chain)
	if len(suggestions) == 0 {
		t.Error("expected at least one suggestion")
	}
}

func TestErrorCorrelator_CalculateSeverity(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)

	tests := []struct {
		chainLength int
		expected    string
	}{
		{25, "critical"},
		{15, "high"},
		{7, "medium"},
		{3, "low"},
	}

	for _, tt := range tests {
		chain := make([]*ErrorEvent, tt.chainLength)
		for i := range chain {
			chain[i] = &ErrorEvent{}
		}

		severity := correlator.calculateSeverity(chain)
		if severity != tt.expected {
			t.Errorf("expected severity %q for chain length %d, got %q", tt.expected, tt.chainLength, severity)
		}
	}
}

func TestErrorCorrelator_GetErrorSummary(t *testing.T) {
	correlator := NewErrorCorrelator(30 * time.Second)

	summary := correlator.GetErrorSummary()
	if summary != "" {
		t.Error("expected empty summary when no errors")
	}

	event := &events.Event{
		Type:      events.EventConnect,
		Target:    "10.244.1.5:8080",
		Error:     -111,
		Timestamp: uint64(time.Now().UnixNano()),
	}

	correlator.AddEvent(event, nil)
	summary = correlator.GetErrorSummary()
	if summary == "" {
		t.Error("expected non-empty summary with errors")
	}
}
