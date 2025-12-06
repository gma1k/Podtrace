package diagnose

import (
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

var eventTypeSamplingRates = map[events.EventType]int{
	events.EventOOMKill:      1,
	events.EventPageFault:     1,
	events.EventNetDevError:   1,
	events.EventTCPRetrans:    5,
	events.EventDNS:           10,
	events.EventConnect:       20,
	events.EventHTTPReq:       30,
	events.EventHTTPResp:      30,
	events.EventTCPSend:       50,
	events.EventTCPRecv:       50,
	events.EventUDPSend:       50,
	events.EventUDPRecv:       50,
	events.EventWrite:         100,
	events.EventRead:          100,
	events.EventFsync:         100,
	events.EventSchedSwitch:  200,
	events.EventLockContention: 50,
	events.EventDBQuery:       20,
	events.EventExec:           10,
	events.EventFork:           10,
	events.EventOpen:           100,
	events.EventClose:          200,
	events.EventTCPState:      100,
}

func getEventPriority(event *events.Event) int {
	if event == nil {
		return config.PriorityLow
	}

	if event.Error != 0 {
		return config.PriorityCritical
	}

	switch event.Type {
	case events.EventOOMKill, events.EventPageFault, events.EventNetDevError:
		return config.PriorityCritical
	case events.EventTCPRetrans, events.EventLockContention:
		return config.PriorityHigh
	case events.EventDNS, events.EventConnect, events.EventHTTPReq, events.EventHTTPResp:
		return config.PriorityNormal
	default:
		return config.PriorityLow
	}
}

func shouldSampleEvent(event *events.Event, eventCount int) bool {
	if event == nil {
		return false
	}

	priority := getEventPriority(event)
	if priority == config.PriorityCritical {
		return true
	}

	samplingRate, ok := eventTypeSamplingRates[event.Type]
	if !ok {
		samplingRate = config.EventSamplingRate
	}

	return eventCount%samplingRate == 0
}

