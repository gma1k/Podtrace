package workloadmetrics

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func kernelCountedTracedResponse() *events.Event {
	return &events.Event{
		Type:             events.EventHTTPResp,
		CgroupID:         kernelTestCgroup,
		LatencyNS:        4_000_000,
		Details:          "200",
		TraceID:          testTraceID,
		SpanID:           testSpanID,
		KernelAggregated: true,
	}
}

func kernelOK() kernelagg.Row {
	return kernelRow(events.EventHTTPResp, 2<<3, kernelagg.BucketIndex(4_000_000), 3, 12_000_000, 0)
}

func histogramExemplarTraceIDs(t *testing.T, reg *prometheus.Registry, name string) []string {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var out []string
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, ex := range m.GetHistogram().GetExemplars() {
				for _, l := range ex.GetLabel() {
					if l.GetName() == exemplarTraceIDLabel {
						out = append(out, l.GetValue())
					}
				}
			}
		}
	}
	return out
}

func TestAKernelCountedRequestStillLinksToItsTrace(t *testing.T) {
	sink, reg := kernelSink(t)

	sink.IngestKernel([]kernelagg.Row{kernelOK()})
	if err := sink.Export(t.Context(), []*events.Event{kernelCountedTracedResponse()}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if got := exemplarsOn(t, reg, "podtrace_workload_l7_requests_total"); len(got) != 1 || got[0] != testTraceID {
		t.Errorf("l7_requests_total exemplars = %v, want [%s]", got, testTraceID)
	}
	if got := histogramExemplarTraceIDs(t, reg, "podtrace_workload_l7_request_duration_seconds"); len(got) != 1 || got[0] != testTraceID {
		t.Errorf("l7_request_duration_seconds exemplars = %v, want [%s]", got, testTraceID)
	}

	var total float64
	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() == "podtrace_workload_l7_requests_total" {
			if len(f.GetMetric()) != 1 {
				t.Errorf("l7_requests_total has %d series, want only the kernel's", len(f.GetMetric()))
			}
			for _, m := range f.GetMetric() {
				total += m.GetCounter().GetValue()
			}
		}
		if f.GetName() == "podtrace_workload_l7_request_duration_seconds" {
			for _, m := range f.GetMetric() {
				if m.GetHistogram().GetSampleCount() != 3 {
					t.Errorf("duration count = %d, want the kernel's 3: linking must not count again", m.GetHistogram().GetSampleCount())
				}
			}
		}
	}
	if total != 3 {
		t.Errorf("l7_requests_total = %v, want the kernel's 3: linking must not count again", total)
	}

	var text bytes.Buffer
	enc := expfmt.NewEncoder(&text, expfmt.NewFormat(expfmt.TypeOpenMetrics))
	for _, f := range families {
		if err := enc.Encode(f); err != nil {
			t.Fatalf("Encode: %v", err)
		}
	}
	if !strings.Contains(text.String(), `trace_id="`+testTraceID+`"`) {
		t.Error("the OpenMetrics exposition carries no trace_id exemplar")
	}
}

func TestAKernelCountedRequestWithoutATraceAddsNoExemplar(t *testing.T) {
	sink, reg := kernelSink(t)
	e := kernelCountedTracedResponse()
	e.TraceID, e.SpanID = "", ""
	if err := sink.Export(t.Context(), []*events.Event{e}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := exemplarsOn(t, reg, "podtrace_workload_l7_requests_total"); len(got) != 0 {
		t.Errorf("exemplars = %v, want none", got)
	}
	if got := histogramExemplarTraceIDs(t, reg, "podtrace_workload_l7_request_duration_seconds"); len(got) != 0 {
		t.Errorf("histogram exemplars = %v, want none", got)
	}
}

func TestAClientCallCountedByTheKernelLinksOnlyItsEdge(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:  true,
		KernelAggregation: true,
		Lookup:            kernelTestLookup,
		ResolvePeer: func(string, uint16) (PeerIdentity, bool) {
			return PeerIdentity{Namespace: "shop", Service: "payments"}, true
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e := kernelCountedTracedResponse()
	e.TCPState = events.HTTPRoleBits(false)
	if err := sink.Export(t.Context(), []*events.Event{e}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := exemplarsOn(t, reg, "podtrace_workload_l7_requests_total"); len(got) != 0 {
		t.Errorf("a call the workload made linked its served-request counter: %v", got)
	}
	if got := exemplarsOn(t, reg, "podtrace_workload_edge_requests_total"); len(got) != 1 {
		t.Errorf("edge exemplars = %v, want the call's trace", got)
	}
}

func TestALinkedExemplarLandsOnTheKernelsOwnSeriesWithTheProcessLabelOn(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:    true,
		KernelAggregation:   true,
		IncludeProcessLabel: true,
		Lookup:              kernelTestLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sink.IngestKernel([]kernelagg.Row{kernelOK()})
	e := kernelCountedTracedResponse()
	e.ProcessName = "nginx"
	if err := sink.Export(t.Context(), []*events.Event{e}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	for _, name := range []string{"podtrace_workload_l7_requests_total", "podtrace_workload_l7_request_duration_seconds"} {
		metrics := gather(t, reg, name)
		if len(metrics) != 1 {
			t.Fatalf("%s has %d series, want only the kernel's: a link must not mint a series", name, len(metrics))
		}
		if got := labelsOf(metrics[0])["process"]; got != "unknown" {
			t.Errorf("%s process = %q, want the kernel's unknown", name, got)
		}
	}
	if got := exemplarsOn(t, reg, "podtrace_workload_l7_requests_total"); len(got) != 1 {
		t.Errorf("exemplars = %v, want the trace on the kernel's series", got)
	}
}

func TestKernelCountedNetworkAndDNSEventsLinkTheirHistograms(t *testing.T) {
	sink, reg := kernelSink(t)
	traced := func(e *events.Event) *events.Event {
		e.CgroupID = kernelTestCgroup
		e.TraceID = testTraceID
		e.SpanID = testSpanID
		e.KernelAggregated = true
		return e
	}
	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventTCPSend, 0, kernelagg.BucketIndex(250_000), 1, 250_000, 100),
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceUDP, 0, false), kernelagg.BucketIndex(150_000_000), 1, 150_000_000, 0),
	})
	batch := []*events.Event{
		traced(&events.Event{Type: events.EventTCPSend, LatencyNS: 250_000, Bytes: 100}),
		traced(&events.Event{Type: events.EventDNS, LatencyNS: 150_000_000}),
	}
	if err := sink.Export(t.Context(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}
	for _, name := range []string{"podtrace_workload_network_latency_seconds", "podtrace_workload_dns_latency_seconds"} {
		if got := histogramExemplarTraceIDs(t, reg, name); len(got) != 1 || got[0] != testTraceID {
			t.Errorf("%s exemplars = %v, want [%s]", name, got, testTraceID)
		}
	}
}

func TestHoldingAnExemplarForAFamilyTheKernelDoesNotFeedIsANoOp(t *testing.T) {
	k := newKernelHistograms([]string{"namespace"}, false)
	k.holdExemplar("not_a_kernel_family", []string{"shop"}, 1, prometheus.Labels{exemplarTraceIDLabel: testTraceID}, time.Unix(1, 0))
	if _, ok := k.series["not_a_kernel_family"]; ok {
		t.Error("an unknown family gained a series")
	}
}

func TestAnExemplarCannotAddASeriesTheBudgetRefuses(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		SeriesBudget:      1,
		NativeHistograms:  true,
		KernelAggregation: true,
		Lookup:            kernelTestLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sink.IngestKernel([]kernelagg.Row{kernelRow(events.EventTCPRetrans, 0, kernelagg.BucketNone, 1, 0, 0)})

	e := &events.Event{Type: events.EventTCPSend, CgroupID: kernelTestCgroup, LatencyNS: 250_000, TraceID: testTraceID, SpanID: testSpanID, KernelAggregated: true}
	if err := sink.Export(t.Context(), []*events.Event{e}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if n := len(sink.kernelHist.series["network_latency_seconds"]); n != 0 {
		t.Errorf("network_latency_seconds holds %d series past a spent budget", n)
	}
	if got := histogramExemplarTraceIDs(t, reg, "podtrace_workload_network_latency_seconds"); len(got) != 0 {
		t.Errorf("exemplars = %v, want none for a refused series", got)
	}
}
