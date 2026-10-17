package criticalpath

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func httpEvent(id uint64, typ events.EventType) *events.Event {
	return &events.Event{Type: typ, CorrelationID: id, Target: "/orders", HTTPMethod: "GET"}
}

func TestFinishedRequestsDoNotAccumulateEndpointIDs(t *testing.T) {
	c := New()
	const requests = 5 * maxEndpoints
	for id := uint64(1); id <= requests; id++ {
		c.Feed(httpEvent(id, events.EventHTTPReq))
		c.Feed(finished(id, 0, 1, 0))
	}

	if len(c.endpoints) != 0 {
		t.Errorf("%d endpoints held after every request finished", len(c.endpoints))
	}
	if len(c.endpointOrder) > 2*maxEndpoints {
		t.Errorf("endpointOrder holds %d ids for 0 live requests; it must be compacted", len(c.endpointOrder))
	}
	if got := c.Summary().Requests; got != requests {
		t.Errorf("requests = %d, want %d", got, requests)
	}
}

func TestALateResponseDoesNotReopenAFinishedRequest(t *testing.T) {
	c := New()
	c.Feed(httpEvent(1, events.EventHTTPReq))
	c.Feed(finished(1, 0, 1, 0))
	c.Feed(httpEvent(1, events.EventHTTPResp))

	if len(c.endpoints) != 0 {
		t.Errorf("a response after request-done re-added its endpoint: %v", c.endpoints)
	}
}

func TestTheEndpointCapHoldsWithStaleIDsAtTheHead(t *testing.T) {
	c := New()
	for id := uint64(1); id <= 100; id++ {
		c.Feed(httpEvent(id, events.EventHTTPReq))
		c.Feed(finished(id, 0, 1, 0))
	}
	for id := uint64(1000); id < 1000+2*maxEndpoints; id++ {
		c.Feed(httpEvent(id, events.EventHTTPReq))
	}

	if len(c.endpoints) > maxEndpoints {
		t.Errorf("endpoints = %d, cap is %d", len(c.endpoints), maxEndpoints)
	}
}
