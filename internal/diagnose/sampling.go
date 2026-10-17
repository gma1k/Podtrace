package diagnose

import (
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

var eventTypeSamplingRates = map[events.EventType]int{
	events.EventOOMKill:        1,
	events.EventPageFault:      1,
	events.EventNetDevError:    1,
	events.EventTCPRetrans:     5,
	events.EventDNS:            10,
	events.EventConnect:        20,
	events.EventConnectResult:  20,
	events.EventHTTPReq:        30,
	events.EventHTTPResp:       30,
	events.EventTCPSend:        50,
	events.EventTCPRecv:        50,
	events.EventUDPSend:        50,
	events.EventUDPRecv:        50,
	events.EventWrite:          100,
	events.EventRead:           100,
	events.EventFsync:          100,
	events.EventSchedSwitch:    200,
	events.EventLockContention: 50,
	events.EventDBQuery:        20,
	events.EventExec:           10,
	events.EventFork:           10,
	events.EventOpen:           100,
	events.EventClose:          100,
	events.EventTCPState:       100,
}

// alwaysKept reports whether a full buffer keeps every event of type t. These
// are rare, and no section divides them by a count of other events.
func alwaysKept(t events.EventType) bool {
	switch t {
	case events.EventOOMKill, events.EventPageFault, events.EventNetDevError, events.EventRequestDone:
		return true
	default:
		return false
	}
}

// shouldSampleEvent decides whether a full buffer admits event. Every other
// type is admitted with probability 1/rate, failures and successes alike:
// keeping every failure while sampling the successes inflates an error rate
// up to rate times (1% becomes about 17% at 1-in-20), and the report and the
// issue rules both divide one by the other. The draw is random rather than every rate-th event, so a
// stream that alternates (send, receive, send, ...) cannot alias with the
// rate and lose one kind entirely. intn is rand.IntN.
func shouldSampleEvent(event *events.Event, intn func(int) int) bool {
	if event == nil {
		return false
	}
	if alwaysKept(event.Type) {
		return true
	}
	rate, ok := eventTypeSamplingRates[event.Type]
	if !ok {
		rate = config.EventSamplingRate
	}
	return rate <= 1 || intn(rate) == 0
}
