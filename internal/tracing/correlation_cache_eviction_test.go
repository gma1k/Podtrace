package tracing

import (
	"fmt"
	"testing"
	"time"
)

func TestABurstOfUnansweredRequestsKeepsTheNewestCorrelations(t *testing.T) {
	c := newCorrelationCache(100)
	for i := 0; i < 150; i++ {
		c.store(fmt.Sprintf("burst-%d", i), correlationEntry{traceID: "t"})
	}

	if got := len(c.m); got != 100 {
		t.Fatalf("cache size = %d, want 100", got)
	}
	for i := 50; i < 150; i++ {
		if _, ok := c.loadDelete(fmt.Sprintf("burst-%d", i)); !ok {
			t.Fatalf("in-flight correlation burst-%d was evicted by the overflow", i)
		}
	}
}

func TestRestoringAKeyRefreshesItsPlaceInTheEvictionOrder(t *testing.T) {
	c := newCorrelationCache(2)
	c.store("k1", correlationEntry{traceID: "old"})
	c.store("k2", correlationEntry{traceID: "t2"})
	c.store("k1", correlationEntry{traceID: "new"})
	c.store("k3", correlationEntry{traceID: "t3"})

	if _, ok := c.loadDelete("k2"); ok {
		t.Error("k2 was the oldest entry and should have been evicted")
	}
	if e, ok := c.loadDelete("k1"); !ok || e.traceID != "new" {
		t.Errorf("k1 = %+v ok=%v, want the refreshed entry", e, ok)
	}
}

func TestSweepDropsStaleEntriesAndKeepsFreshOnes(t *testing.T) {
	c := newCorrelationCache(16)
	c.store("stale", correlationEntry{traceID: "t"})
	c.m["stale"].Value.(*correlationItem).entry.storedNS = time.Now().Add(-time.Hour).UnixNano()
	c.store("fresh", correlationEntry{traceID: "t"})

	c.sweep(time.Minute)

	if _, ok := c.loadDelete("stale"); ok {
		t.Error("stale entry survived the sweep")
	}
	if _, ok := c.loadDelete("fresh"); !ok {
		t.Error("fresh entry was swept")
	}
	if c.order.Len() != 0 {
		t.Errorf("order list holds %d entries after draining, want 0", c.order.Len())
	}
}
