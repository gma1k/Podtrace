package workloadmetrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
)

const exemplarTraceIDLabel = "trace_id"

const exemplarSpanIDLabel = "span_id"

const exemplarLabelBudget = 128

// exemplarFor builds the exemplar labels for an event, reporting false when
// the event carries no trace identity worth linking to.
func exemplarFor(e *events.Event) (prometheus.Labels, bool) {
	if e == nil || !isHexID(e.TraceID) {
		return nil, false
	}

	labels := prometheus.Labels{exemplarTraceIDLabel: e.TraceID}
	if isHexID(e.SpanID) {
		labels[exemplarSpanIDLabel] = e.SpanID
	}

	if exemplarLabelLen(labels) > exemplarLabelBudget {
		delete(labels, exemplarSpanIDLabel)
		if exemplarLabelLen(labels) > exemplarLabelBudget {
			return nil, false
		}
	}
	return labels, true
}

// isHexID reports whether id is a non-empty run of hexadecimal digits, the
// shape of every trace and span id podtrace links to.
func isHexID(id string) bool {
	if id == "" {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// exemplarLabelLen measures an exemplar against Prometheus's budget.
func exemplarLabelLen(labels prometheus.Labels) int {
	total := 0
	for name, value := range labels {
		total += len(name) + len(value)
	}
	return total
}

// observeExemplar records one observation, attaching the exemplar when the
// observer supports it.
func observeExemplar(o prometheus.Observer, seconds float64, labels prometheus.Labels) {
	if labels != nil {
		if eo, ok := o.(prometheus.ExemplarObserver); ok {
			eo.ObserveWithExemplar(seconds, labels)
			return
		}
	}
	o.Observe(seconds)
}

// addExemplar increments a counter, attaching the exemplar when supported.
func addExemplar(c prometheus.Counter, delta float64, labels prometheus.Labels) {
	if labels != nil {
		if ea, ok := c.(prometheus.ExemplarAdder); ok {
			ea.AddWithExemplar(delta, labels)
			return
		}
	}
	c.Add(delta)
}
