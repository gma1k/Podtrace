package workloadmetrics

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/tracing"
)

func TestAnInvalidUTF8B3TraceIDNeitherPanicsNorBecomesAnExemplar(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{Lookup: kernelTestLookup, TraceContext: tracing.NewContextEnricher().Enrich})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	batch := []*events.Event{{
		Type:      events.EventRedisCmd,
		CgroupID:  kernelTestCgroup,
		LatencyNS: 1_000_000,
		Details:   "x-b3-traceid:\xff\xfe\r\nx-b3-spanid:ab",
	}}
	if err := sink.Export(t.Context(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if got := exemplarsOn(t, reg, "podtrace_workload_l7_requests_total"); len(got) != 0 {
		t.Errorf("exemplars = %q, want none for a malformed trace id", got)
	}
	if len(gather(t, reg, "podtrace_workload_l7_requests_total")) != 1 {
		t.Error("the request itself must still be counted")
	}
}

func TestExemplarForRefusesNonHexIdentifiers(t *testing.T) {
	if _, ok := exemplarFor(&events.Event{TraceID: "\xff\xfe"}); ok {
		t.Error("non-UTF-8 trace id produced an exemplar")
	}
	if _, ok := exemplarFor(&events.Event{TraceID: "not-a-trace"}); ok {
		t.Error("non-hex trace id produced an exemplar")
	}
	labels, ok := exemplarFor(&events.Event{TraceID: testTraceID, SpanID: "\xff"})
	if !ok {
		t.Fatal("valid trace id with a bad span id must still link the trace")
	}
	if _, present := labels[exemplarSpanIDLabel]; present {
		t.Error("non-hex span id was attached to the exemplar")
	}
}

func TestSemconvRPCMethodWithInvalidUTF8IsSanitised(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{SemanticConventions: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sink.Export(t.Context(), []*events.Event{{
		Type:      events.EventGRPCMethod,
		LatencyNS: 1_000_000,
		Target:    "/pkg.Svc/Get\xff",
		K8s:       enriched(),
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	assertAllLabelValuesValid(t, reg)
	if len(gather(t, reg, semconvRPCDuration)) != 1 {
		t.Error("the RPC must still be recorded under a sanitised method")
	}
}

func TestProcessLabelWithInvalidUTF8IsSanitised(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{IncludeProcessLabel: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sink.Export(t.Context(), []*events.Event{{
		Type:        events.EventTCPSend,
		LatencyNS:   1_000_000,
		Bytes:       10,
		ProcessName: "w\xc3",
		K8s:         enriched(),
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	assertAllLabelValuesValid(t, reg)
	metrics := gather(t, reg, "podtrace_workload_network_bytes_total")
	if len(metrics) != 1 {
		t.Fatalf("want 1 series, got %d", len(metrics))
	}
	if got := labelsOf(metrics[0])["process"]; got != "w�" {
		t.Errorf("process = %q, want %q", got, "w�")
	}
}

func TestLabelValueCapsLengthOnARuneBoundary(t *testing.T) {
	long := strings.Repeat("a", maxLabelValueBytes-1) + "é"
	got := labelValue(long)
	if len(got) > maxLabelValueBytes || !utf8.ValidString(got) {
		t.Fatalf("labelValue returned %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
	if got != strings.Repeat("a", maxLabelValueBytes-1) {
		t.Errorf("cut inside a rune or dropped too much: %q", got[len(got)-4:])
	}
	if name := strings.Repeat("n", 253); labelValue(name) != name {
		t.Error("a maximum-length Kubernetes name must never be cut")
	}
}

func TestARefusedPeakHeldGaugeLeavesNoPeakBehind(t *testing.T) {
	sink, _ := newTestSink(t, 1)
	sink.now = func() time.Time { return time.Unix(1000, 0) }

	if err := sink.Export(t.Context(), []*events.Event{{Type: events.EventTCPRetrans, K8s: enriched()}}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	for i := 0; i < 20; i++ {
		meta := enriched()
		meta.WorkloadName = "pool-" + strings.Repeat("x", i+1)
		if err := sink.Export(t.Context(), []*events.Event{{Type: events.EventDBPoolStats, Bytes: 4, TCPState: 8, Error: 50, K8s: meta}}); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}

	if n := len(sink.peaks); n != 0 {
		t.Errorf("peaks holds %d entries for series the budget refused", n)
	}
}

func assertAllLabelValuesValid(t *testing.T, reg *prometheus.Registry) {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if !utf8.ValidString(lp.GetValue()) {
					t.Errorf("%s{%s=%q} is not valid UTF-8", f.GetName(), lp.GetName(), lp.GetValue())
				}
			}
		}
	}
}
