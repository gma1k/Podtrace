package agent

import (
	"strings"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/alerting"
)

const maxDeliveryErrorBytes = 300

// deliveryState is one PodTrace exporter's current delivery failure.
type deliveryState struct {
	Exporter      string
	FailingSince  time.Time
	FailedBatches int64
	LastError     string
}

// deliveryHealth records which PodTraces' exporters are failing to deliver
// on this node, so the status writer can put it on nodeStatus instead of
// leaving it in the agent log.
type deliveryHealth struct {
	mu   sync.Mutex
	byCR map[CRKey]*deliveryEntry
}

type deliveryEntry struct {
	owner any
	state *deliveryState
}

func newDeliveryHealth() *deliveryHealth {
	return &deliveryHealth{byCR: map[CRKey]*deliveryEntry{}}
}

// register makes owner the PodTrace's current exporter, starting healthy.
func (h *deliveryHealth) register(cr CRKey, owner any) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.byCR[cr] = &deliveryEntry{owner: owner}
}

// fail records a failed batch of the current exporter.
func (h *deliveryHealth) fail(cr CRKey, owner any, exporter string, err error, now time.Time) {
	if h == nil || err == nil {
		return
	}
	text := alerting.RedactURLsInText(err.Error())
	if len(text) > maxDeliveryErrorBytes {
		text = strings.ToValidUTF8(text[:maxDeliveryErrorBytes], "") + "..."
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.byCR[cr]
	if !ok || e.owner != owner {
		return
	}
	if e.state == nil {
		e.state = &deliveryState{Exporter: exporter, FailingSince: now}
	}
	e.state.FailedBatches++
	e.state.LastError = text
}

// delivered clears the failure once the current exporter delivers again.
func (h *deliveryHealth) delivered(cr CRKey, owner any) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.byCR[cr]; ok && e.owner == owner {
		e.state = nil
	}
}

// unregister drops the PodTrace's record when owner is still its current
// exporter, as when the PodTrace is removed from this node.
func (h *deliveryHealth) unregister(cr CRKey, owner any) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.byCR[cr]; ok && e.owner == owner {
		delete(h.byCR, cr)
	}
}

// failing reports the PodTrace's current delivery failure, if any.
func (h *deliveryHealth) failing(cr CRKey) (deliveryState, bool) {
	if h == nil {
		return deliveryState{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.byCR[cr]
	if !ok || e.state == nil {
		return deliveryState{}, false
	}
	return *e.state, true
}
