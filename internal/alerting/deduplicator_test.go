package alerting

import (
	"testing"
	"time"
)

func TestAlertDeduplicator_ShouldSend(t *testing.T) {
	dedup := NewAlertDeduplicator(5 * time.Minute)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test Alert",
		Message:   "Test message",
		Timestamp: time.Now(),
		Source:    "test",
	}
	if !dedup.ShouldSend(alert) {
		t.Error("First alert should be sent")
	}
	if dedup.ShouldSend(alert) {
		t.Error("Duplicate alert should not be sent")
	}
}

func TestAlertDeduplicator_ShouldSend_Nil(t *testing.T) {
	dedup := NewAlertDeduplicator(5 * time.Minute)
	if dedup.ShouldSend(nil) {
		t.Error("Nil alert should not be sent")
	}
}

func TestAlertDeduplicator_Cleanup(t *testing.T) {
	dedup := NewAlertDeduplicator(1 * time.Second)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test Alert",
		Message:   "Test message",
		Timestamp: time.Now(),
		Source:    "test",
	}
	dedup.ShouldSend(alert)
	time.Sleep(2 * time.Second)
	dedup.Cleanup(1 * time.Second)
	if !dedup.ShouldSend(alert) {
		t.Error("Alert should be sendable after cleanup")
	}
}

func TestAlertDeduplicator_Reset(t *testing.T) {
	dedup := NewAlertDeduplicator(5 * time.Minute)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test Alert",
		Message:   "Test message",
		Timestamp: time.Now(),
		Source:    "test",
	}
	dedup.ShouldSend(alert)
	dedup.Reset()
	if !dedup.ShouldSend(alert) {
		t.Error("Alert should be sendable after reset")
	}
}

