package workloadmetrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func TestARecreatedKernelSeriesStartsItsCumulativeWindowAgain(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:  true,
		KernelAggregation: true,
		Lookup:            kernelTestLookup,
		Now:               func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	row := kernelRow(events.EventTCPSend, 0, 3, 4, 4000, 512)

	sink.IngestKernel(rowsOf(row))
	if got := kernelLatencyStart(t, sink); !got.Equal(clock) {
		t.Fatalf("first StartTime = %v, want %v", got, clock)
	}

	clock = clock.Add(time.Hour)
	if sink.Reap(time.Minute) == 0 {
		t.Fatal("idle series was not reaped")
	}
	clock = clock.Add(time.Minute)
	recreated := clock
	sink.IngestKernel(rowsOf(row))

	if got := kernelLatencyStart(t, sink); !got.Equal(recreated) {
		t.Errorf("StartTime after re-creation = %v, want %v; the cumulative value restarted, so its window must too", got, recreated)
	}
}

func rowsOf(rows ...kernelagg.Row) []kernelagg.Row { return rows }

func kernelLatencyStart(t *testing.T, sink *Sink) time.Time {
	t.Helper()
	scopes, err := NewProducer(sink).Produce(t.Context())
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	for _, sm := range scopes {
		for _, m := range sm.Metrics {
			if m.Name != "podtrace_workload_network_latency_seconds" {
				continue
			}
			h, ok := m.Data.(metricdata.ExponentialHistogram[float64])
			if !ok || len(h.DataPoints) != 1 {
				t.Fatalf("network latency = %T with unexpected points", m.Data)
			}
			return h.DataPoints[0].StartTime
		}
	}
	t.Fatal("network latency histogram not produced")
	return time.Time{}
}
