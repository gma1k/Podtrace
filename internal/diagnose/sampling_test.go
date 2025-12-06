package diagnose

import (
	"testing"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

func TestGetEventPriority_Critical(t *testing.T) {
	event := &events.Event{Type: events.EventDNS, Error: 1}
	priority := getEventPriority(event)
	if priority != config.PriorityCritical {
		t.Errorf("Expected PriorityCritical for error event, got %d", priority)
	}

	event = &events.Event{Type: events.EventOOMKill}
	priority = getEventPriority(event)
	if priority != config.PriorityCritical {
		t.Errorf("Expected PriorityCritical for OOMKill, got %d", priority)
	}

	event = &events.Event{Type: events.EventPageFault}
	priority = getEventPriority(event)
	if priority != config.PriorityCritical {
		t.Errorf("Expected PriorityCritical for PageFault, got %d", priority)
	}
}

func TestGetEventPriority_High(t *testing.T) {
	event := &events.Event{Type: events.EventTCPRetrans}
	priority := getEventPriority(event)
	if priority != config.PriorityHigh {
		t.Errorf("Expected PriorityHigh for TCPRetrans, got %d", priority)
	}

	event = &events.Event{Type: events.EventLockContention}
	priority = getEventPriority(event)
	if priority != config.PriorityHigh {
		t.Errorf("Expected PriorityHigh for LockContention, got %d", priority)
	}
}

func TestGetEventPriority_Normal(t *testing.T) {
	event := &events.Event{Type: events.EventDNS}
	priority := getEventPriority(event)
	if priority != config.PriorityNormal {
		t.Errorf("Expected PriorityNormal for DNS, got %d", priority)
	}

	event = &events.Event{Type: events.EventConnect}
	priority = getEventPriority(event)
	if priority != config.PriorityNormal {
		t.Errorf("Expected PriorityNormal for Connect, got %d", priority)
	}
}

func TestGetEventPriority_Low(t *testing.T) {
	event := &events.Event{Type: events.EventRead}
	priority := getEventPriority(event)
	if priority != config.PriorityLow {
		t.Errorf("Expected PriorityLow for Read, got %d", priority)
	}

	event = &events.Event{Type: events.EventWrite}
	priority = getEventPriority(event)
	if priority != config.PriorityLow {
		t.Errorf("Expected PriorityLow for Write, got %d", priority)
	}
}

func TestGetEventPriority_NilEvent(t *testing.T) {
	priority := getEventPriority(nil)
	if priority != config.PriorityLow {
		t.Errorf("Expected PriorityLow for nil event, got %d", priority)
	}
}

func TestShouldSampleEvent_CriticalAlwaysKept(t *testing.T) {
	event := &events.Event{Type: events.EventDNS, Error: 1}
	if !shouldSampleEvent(event, 1) {
		t.Error("Expected critical event to always be sampled")
	}

	if !shouldSampleEvent(event, 100) {
		t.Error("Expected critical event to always be sampled regardless of count")
	}
}

func TestShouldSampleEvent_TypeSpecificRates(t *testing.T) {
	event := &events.Event{Type: events.EventDNS}
	if !shouldSampleEvent(event, 10) {
		t.Error("Expected DNS event to be sampled at count 10 (1 in 10)")
	}
	if shouldSampleEvent(event, 11) {
		t.Error("Expected DNS event not to be sampled at count 11")
	}

	event = &events.Event{Type: events.EventTCPSend}
	if !shouldSampleEvent(event, 50) {
		t.Error("Expected TCPSend event to be sampled at count 50 (1 in 50)")
	}
	if shouldSampleEvent(event, 51) {
		t.Error("Expected TCPSend event not to be sampled at count 51")
	}

	event = &events.Event{Type: events.EventRead}
	if !shouldSampleEvent(event, 100) {
		t.Error("Expected Read event to be sampled at count 100 (1 in 100)")
	}
	if shouldSampleEvent(event, 101) {
		t.Error("Expected Read event not to be sampled at count 101")
	}
}

func TestShouldSampleEvent_DefaultRate(t *testing.T) {
	event := &events.Event{Type: events.EventType(9999)}
	if !shouldSampleEvent(event, config.EventSamplingRate) {
		t.Errorf("Expected unknown event type to use default sampling rate %d", config.EventSamplingRate)
	}
}

func TestShouldSampleEvent_NilEvent(t *testing.T) {
	if shouldSampleEvent(nil, 1) {
		t.Error("Expected nil event not to be sampled")
	}
}

