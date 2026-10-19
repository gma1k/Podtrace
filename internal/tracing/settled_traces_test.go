package tracing

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/tracing/exporter"
)

func TestSettledTracesByExportOutcome(t *testing.T) {
	first, second := &tracker.Trace{TraceID: "first"}, &tracker.Trace{TraceID: "second"}
	batch := []*tracker.Trace{first, second}
	partial := &exporter.PartialExportError{FailedTraces: map[string]struct{}{"second": {}}, Err: errors.New("503")}

	cases := []struct {
		name string
		err  error
		want []*tracker.Trace
	}{
		{name: "delivered", err: nil, want: batch},
		{name: "whole batch failed", err: errors.New("collector unreachable"), want: nil},
		{name: "partial failure", err: fmt.Errorf("export: %w", partial), want: []*tracker.Trace{first}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := settledTraces(batch, tc.err)
			if len(got) != len(tc.want) {
				t.Fatalf("settled %d traces, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("settled[%d] = %s, want %s", i, got[i].TraceID, tc.want[i].TraceID)
				}
			}
		})
	}
}
