package tracker

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestPodCommunicationTracker_ProcessEvent(t *testing.T) {
	tracker := NewPodCommunicationTracker("source-pod", "default")

	event := &events.Event{
		Type:      events.EventConnect,
		Target:    "10.244.1.5:8080",
		Timestamp: uint64(time.Now().UnixNano()),
		Error:     0,
	}

	k8sContext := map[string]interface{}{
		"target_pod":      "target-pod",
		"target_service":  "test-service",
		"target_namespace": "default",
	}

	tracker.ProcessEvent(event, k8sContext)

	summaries := tracker.GetSummary()
	if len(summaries) == 0 {
		t.Fatal("expected at least one communication summary")
	}

	if summaries[0].Target != "test-service" {
		t.Errorf("expected target 'test-service', got %q", summaries[0].Target)
	}

	if summaries[0].Namespace != "default" {
		t.Errorf("expected namespace 'default', got %q", summaries[0].Namespace)
	}
}

func TestPodCommunicationTracker_ProcessEvent_NoContext(t *testing.T) {
	tracker := NewPodCommunicationTracker("source-pod", "default")

	event := &events.Event{
		Type:      events.EventConnect,
		Target:    "10.244.1.5:8080",
		Timestamp: uint64(time.Now().UnixNano()),
	}

	tracker.ProcessEvent(event, nil)

	summaries := tracker.GetSummary()
	if len(summaries) != 0 {
		t.Errorf("expected no summaries without context, got %d", len(summaries))
	}
}

func TestPodCommunicationTracker_ProcessEvent_NonNetwork(t *testing.T) {
	tracker := NewPodCommunicationTracker("source-pod", "default")

	event := &events.Event{
		Type:      events.EventRead,
		Target:    "file.txt",
		Timestamp: uint64(time.Now().UnixNano()),
	}

	k8sContext := map[string]interface{}{
		"target_pod": "target-pod",
	}

	tracker.ProcessEvent(event, k8sContext)

	summaries := tracker.GetSummary()
	if len(summaries) != 0 {
		t.Errorf("expected no summaries for non-network events, got %d", len(summaries))
	}
}

func TestGeneratePodCommunicationReport(t *testing.T) {
	summaries := []PodCommunicationSummary{
		{
			Target:          "service-1",
			Namespace:       "default",
			ConnectionCount: 10,
			TotalBytes:      1024,
			AvgLatency:      time.Millisecond * 10,
			ErrorCount:      0,
			LastSeen:        time.Now(),
		},
	}

	report := GeneratePodCommunicationReport(summaries)
	if report == "" {
		t.Fatal("expected non-empty report")
	}

	if !contains(report, "service-1") {
		t.Error("report should contain service name")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

