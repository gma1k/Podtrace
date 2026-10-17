package agent

import (
	"testing"
	"time"
)

func TestAZeroValueMetricsCanRetireACR(t *testing.T) {
	m := &Metrics{}
	key := CRKey{Namespace: "ns", Name: "gone"}
	m.retire(key)
	if !m.isRetired(key) {
		t.Fatal("a zero-value Metrics forgot the retired CR")
	}
}

func TestMetricsClockFallsBackToWallTime(t *testing.T) {
	before := time.Now()
	got := (&Metrics{}).clock()
	if got.Before(before) || got.After(time.Now()) {
		t.Errorf("clock() = %v, want the wall clock", got)
	}
	fixed := time.Unix(1_800_000_000, 0)
	if got := (&Metrics{now: func() time.Time { return fixed }}).clock(); !got.Equal(fixed) {
		t.Errorf("clock() = %v, want the injected %v", got, fixed)
	}
}

func TestEngineObserverLogsAnExporterPanicWithoutPanicking(t *testing.T) {
	o := &metricsEngineObserver{}
	o.OnExporterPanic("otlp", "label value is not valid UTF-8", []byte("goroutine 1 [running]:"))
}
