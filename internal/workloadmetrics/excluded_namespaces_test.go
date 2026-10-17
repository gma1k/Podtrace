package workloadmetrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func TestAnExcludedNamespaceFeedsNoSeriesEvenWhenItsPodIsTraced(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{ExcludeNamespaces: []string{" kube-system ", "shop"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	excluded := enriched()
	kept := enriched()
	kept.Namespace = "payments"
	batch := []*events.Event{
		{Type: events.EventTCPSend, LatencyNS: 1000, Bytes: 10, K8s: excluded},
		{Type: events.EventHTTPResp, LatencyNS: 1000, Details: "200", K8s: excluded},
		{Type: events.EventTCPSend, LatencyNS: 1000, Bytes: 10, K8s: kept},
	}
	if err := sink.Export(t.Context(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	for _, id := range seriesIdentities(t, reg) {
		if strings.Contains(id, "namespace=shop") {
			t.Errorf("excluded namespace produced series %s", id)
		}
	}
	if got := testutil.ToFloat64(sink.c.eventsTotal.WithLabelValues("excluded")); got != 2 {
		t.Errorf("events_total{outcome=excluded} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(sink.c.eventsTotal.WithLabelValues("unattributed")); got != 0 {
		t.Errorf("excluded events counted as unattributed: %v", got)
	}
	if len(gather(t, reg, "podtrace_workload_network_bytes_total")) != 1 {
		t.Error("the non-excluded namespace must still be recorded")
	}
}

func TestKernelRowsFromAnExcludedNamespaceAreHandledButNotRecorded(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:  true,
		KernelAggregation: true,
		Lookup:            kernelTestLookup,
		ExcludeNamespaces: []string{"shop"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rows := []kernelagg.Row{kernelRow(events.EventTCPSend, 0, 3, 4, 4000, 512)}
	if applied := sink.IngestKernel(rows); applied != 1 {
		t.Errorf("IngestKernel applied = %d, want 1 so the row is not reported unattributed", applied)
	}
	for _, id := range seriesIdentities(t, reg) {
		if strings.Contains(id, "namespace=shop") {
			t.Errorf("excluded namespace produced series %s", id)
		}
	}
}

func TestBaseLabelsRefuseAnExcludedNamespace(t *testing.T) {
	sink, err := New(prometheus.NewRegistry(), Options{ExcludeNamespaces: []string{"shop"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := sink.baseLabelValues(&events.Event{K8s: enriched()}); ok {
		t.Error("baseLabelValues attributed an event from an excluded namespace")
	}
}

func TestAnUnattributedEventIsNotCountedAsExcluded(t *testing.T) {
	sink, err := New(prometheus.NewRegistry(), Options{ExcludeNamespaces: []string{"shop"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sink.Export(t.Context(), []*events.Event{{Type: events.EventTCPSend, CgroupID: 99}}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := testutil.ToFloat64(sink.c.eventsTotal.WithLabelValues("excluded")); got != 0 {
		t.Errorf("excluded = %v, want 0 for an event with no pod metadata", got)
	}
	if got := testutil.ToFloat64(sink.c.eventsTotal.WithLabelValues("unattributed")); got != 1 {
		t.Errorf("unattributed = %v, want 1", got)
	}
}
