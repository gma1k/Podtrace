package parser

import (
	"reflect"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestPutEventClearsEnrichedIdentity(t *testing.T) {
	event := &events.Event{
		Type:         events.EventHTTPReq,
		TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:       "00f067aa0ba902b7",
		ParentSpanID: "00f067aa0ba902b8",
		TraceFlags:   1,
		TraceState:   "vendor=secret",
		K8s:          &events.K8sMetadata{},
	}
	PutEvent(event)
	if !reflect.DeepEqual(*event, events.Event{}) {
		t.Fatalf("pooled event kept state: %+v", *event)
	}
}
