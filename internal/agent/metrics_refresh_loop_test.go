package agent

import (
	"context"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestRefreshMetricsAdvancesCountersWithoutReconcile(t *testing.T) {
	m := NewMetrics()
	router := NewRouter(nil)
	router.Publish([]CRRule{
		mkRule("ns", "steady", []uint64{1}, []events.EventType{events.EventDNS}, &recExp{name: "x"}),
	})
	enricher := NewPodEnricher()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- refreshMetrics(ctx, 5*time.Millisecond, m, router, enricher) }()

	key := CRKey{"ns", "steady"}
	router.Stats().incr(key, 9)
	router.Stats().incrDropped(key, 3)
	enricher.Lookup(42)

	deadline := time.Now().Add(5 * time.Second)
	for {
		exported := scrapeMetric(t, m, `events_exported_total{cr_namespace="ns",cr_name="steady"}`)
		dropped := scrapeMetric(t, m, `events_dropped_total{cr_namespace="ns",cr_name="steady"}`)
		misses := scrapeMetric(t, m, `enrichment_lookups_total{result="miss"}`)
		if exported == 9 && dropped == 3 && misses == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("counters never refreshed: exported=%d dropped=%d misses=%d", exported, dropped, misses)
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refreshMetrics returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refreshMetrics did not stop on cancel")
	}
}

func TestRefreshMetricsWithoutRouterReturnsImmediately(t *testing.T) {
	if err := refreshMetrics(context.Background(), time.Millisecond, NewMetrics(), nil, nil); err != nil {
		t.Fatalf("refreshMetrics = %v", err)
	}
}
