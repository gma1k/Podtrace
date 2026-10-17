package agent

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRetiredCRReinstatedByExporterInit(t *testing.T) {
	m := NewMetrics()
	key := CRKey{"ns", "back"}
	m.dropPolicyMetrics(key)

	m.ObserveSpanBatched(key, 1)
	if strings.Contains(scrape(t, m), `cr_name="back"`) {
		t.Fatal("retired CR accepted a span observation")
	}

	m.ObserveExporterInit(key, nil)
	m.ObserveSpanBatched(key, 1)
	if got := scrapeMetric(t, m, `spans_batched_total{cr_namespace="ns",cr_name="back"}`); got != 1 {
		t.Fatalf("spans_batched_total after exporter rebuilt = %d, want 1", got)
	}
}

func TestRetiredCRLapsesAfterTTL(t *testing.T) {
	m := NewMetrics()
	now := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return now }
	key := CRKey{"ns", "old"}
	other := CRKey{"ns", "older"}
	m.dropPolicyMetrics(key)
	m.dropPolicyMetrics(other)

	if !m.isRetired(key) {
		t.Fatal("freshly removed CR is not retired")
	}
	now = now.Add(retiredCRTTL)
	if m.isRetired(key) {
		t.Fatal("retirement outlived its TTL")
	}
	m.RefreshFromRouter(NewRouter(nil))
	m.retiredMu.Lock()
	remaining := len(m.retired)
	m.retiredMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expired retirements kept: %d", remaining)
	}
	m.ObserveExportDelivery(key, 1, errors.New("connection refused"))
	if scrapeMetric(t, m, `export_delivery_dropped_total{cr_namespace="ns",cr_name="old"}`) != 1 {
		t.Fatal("a lapsed retirement still suppresses observations")
	}
}
