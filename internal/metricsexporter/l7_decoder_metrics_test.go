package metricsexporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordL7DecoderDrops(t *testing.T) {
	counter := l7DecoderDropsCounter.WithLabelValues("h2", "unit_test")
	before := testutil.ToFloat64(counter)
	RecordL7DecoderDrops("h2", "unit_test", 0)
	RecordL7DecoderDrops("h2", "unit_test", 3)
	if got := testutil.ToFloat64(counter) - before; got != 3 {
		t.Fatalf("drops delta = %v, want 3", got)
	}
}

func TestRecordL7DecoderRetainedBytes(t *testing.T) {
	RecordL7DecoderRetainedBytes("unit_test", 4096)
	if got := testutil.ToFloat64(l7DecoderRetainedBytesGauge.WithLabelValues("unit_test")); got != 4096 {
		t.Fatalf("retained bytes = %v, want 4096", got)
	}
}

func TestL7DecoderCollectorsCanJoinAnotherRegistry(t *testing.T) {
	collectors := L7DecoderCollectors()
	if len(collectors) != 2 {
		t.Fatalf("collectors = %d, want 2", len(collectors))
	}
	if err := prometheus.NewRegistry().Register(collectors[0]); err != nil {
		t.Fatalf("register on a second registry: %v", err)
	}
}
