package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/workloadmetrics"
	"github.com/gma1k/podtrace/pkg/tracer"
)

// The drain loop runs on its own goroutine while the test observes it, so the
// fake has to be safe for concurrent use or -race reports the test, not a bug.
type fakeAggregator struct {
	*NoopBackend
	mu       sync.Mutex
	modes    []kernelagg.Mode
	rows     []kernelagg.Row
	drainErr error
	modeErr  error
	drains   int
}

func (f *fakeAggregator) SetKernelAggregationMode(mode kernelagg.Mode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.modeErr != nil {
		return f.modeErr
	}
	f.modes = append(f.modes, mode)
	return nil
}

func (f *fakeAggregator) DrainKernelMetrics() ([]kernelagg.Row, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.drains++
	if f.drainErr != nil {
		return nil, f.drainErr
	}
	return f.rows, nil
}

func (f *fakeAggregator) drainCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.drains
}

func (f *fakeAggregator) modeLog() []kernelagg.Mode {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]kernelagg.Mode(nil), f.modes...)
}

func kernelTestSink(t *testing.T) *workloadmetrics.Sink {
	t.Helper()
	sink, err := workloadmetrics.New(NewMetrics().Registerer(), workloadmetrics.Options{
		KernelAggregation: true,
		NativeHistograms:  true,
		Lookup: func(uint64) (events.K8sMetadata, bool) {
			return events.K8sMetadata{
				Namespace: "ns", WorkloadName: "wl", WorkloadKind: "Deployment", ContainerName: "c",
			}, true
		},
	})
	if err != nil {
		t.Fatalf("workloadmetrics.New: %v", err)
	}
	return sink
}

func withKernelAggregation(t *testing.T, on bool) {
	t.Helper()
	prev := config.WorkloadMetricsKernelAggregation
	config.WorkloadMetricsKernelAggregation = on
	t.Cleanup(func() { config.WorkloadMetricsKernelAggregation = prev })
}

func TestDrainLoopIsANoopWhenThereIsNothingToDrain(t *testing.T) {
	withKernelAggregation(t, true)
	logger := logr.Discard()

	if err := drainKernelMetrics(context.Background(), &fakeAggregator{}, nil, nil, NewMetrics(), logger); err != nil {
		t.Errorf("a nil sink returned %v, want nil", err)
	}

	withKernelAggregation(t, false)
	if err := drainKernelMetrics(context.Background(), &fakeAggregator{}, kernelTestSink(t), nil, NewMetrics(), logger); err != nil {
		t.Errorf("aggregation disabled returned %v, want nil", err)
	}
}

func TestABackendWithoutAggregationFallsBackToTheEventPath(t *testing.T) {
	withKernelAggregation(t, true)

	// NoopBackend implements TracerBackend but not KernelAggregator.
	var backend tracer.TracerBackend = &NoopBackend{}
	if err := drainKernelMetrics(context.Background(), backend, kernelTestSink(t), nil, NewMetrics(), logr.Discard()); err != nil {
		t.Errorf("returned %v; an unsupported backend must fall back, not fail the agent", err)
	}

	failing := &fakeAggregator{modeErr: errors.New("no aggregation maps")}
	if err := drainKernelMetrics(context.Background(), failing, kernelTestSink(t), nil, NewMetrics(), logr.Discard()); err != nil {
		t.Errorf("returned %v; a backend that refuses the mode must fall back, not fail", err)
	}
}

func TestTheDrainLoopFoldsRowsAndRestoresTheModeOnShutdown(t *testing.T) {
	withKernelAggregation(t, true)
	prev := config.WorkloadMetricsDrainInterval
	config.WorkloadMetricsDrainInterval = 10 * time.Millisecond
	t.Cleanup(func() { config.WorkloadMetricsDrainInterval = prev })

	agg := &fakeAggregator{rows: []kernelagg.Row{{
		Key:   kernelagg.Key{CgroupID: 1, EventType: uint8(events.EventTCPSend), Bucket: 80},
		Value: kernelagg.Value{Count: 2, SumNS: 4000, Bytes: 700},
	}}}
	metrics := NewMetrics()
	router := NewRouter(nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- drainKernelMetrics(ctx, agg, kernelTestSink(t), router, metrics, logr.Discard()) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && agg.drainCount() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("drain loop returned %v", err)
	}

	if agg.drainCount() == 0 {
		t.Error("the loop never drained; rows would sit in the map until it evicted them")
	}
	modes := agg.modeLog()
	if len(modes) == 0 || modes[len(modes)-1] != kernelagg.ModeOff {
		t.Errorf("modes = %v; the loop must switch the probes off on shutdown so a restarting "+
			"agent does not leave them folding into a map nobody drains", modes)
	}
}

func TestTheBypassFollowsWhetherACRIsRouting(t *testing.T) {
	withKernelAggregation(t, true)
	prev := config.WorkloadMetricsDrainInterval
	config.WorkloadMetricsDrainInterval = time.Hour
	t.Cleanup(func() { config.WorkloadMetricsDrainInterval = prev })

	agg := &fakeAggregator{}
	router := NewRouter(nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- drainKernelMetrics(ctx, agg, kernelTestSink(t), router, NewMetrics(), logr.Discard()) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(agg.modeLog()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	router.Publish([]CRRule{{Key: CRKey{Name: "cr"}}}).Wait()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range agg.modeLog() {
			if m == kernelagg.ModeOn {
				goto found
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
found:
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("drainKernelMetrics returned %v on shutdown", err)
	}

	sawBypass, sawOn := false, false
	for _, m := range agg.modeLog() {
		switch m {
		case kernelagg.ModeBypass:
			sawBypass = true
		case kernelagg.ModeOn:
			sawOn = true
		}
	}
	if !sawBypass {
		t.Error("the loop never armed the bypass with no CR routing, so a metrics-only node " +
			"keeps paying for a ringbuf crossing per event")
	}
	if !sawOn {
		t.Error("publishing a CR never lifted the bypass; the session would see no events")
	}
}

func TestDrainFailuresAreCountedRatherThanSilent(t *testing.T) {
	metrics := NewMetrics()

	metrics.RecordKernelDrain(5, 3)
	metrics.RecordKernelDrainFailure()

	var nilMetrics *Metrics
	nilMetrics.RecordKernelDrain(1, 1)
	nilMetrics.RecordKernelDrainFailure()

	bare := &Metrics{}
	bare.RecordKernelDrain(1, 1)
	bare.RecordKernelDrainFailure()
}

// modeFlakyAggregator accepts the initial support probe, then fails, which is
// what a map that goes away under the agent looks like.
type modeFlakyAggregator struct {
	*fakeAggregator
	calls int
}

func (m *modeFlakyAggregator) SetKernelAggregationMode(mode kernelagg.Mode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.calls == 1 {
		return nil
	}
	return errors.New("map disappeared")
}

func TestALaterModeFailureIsLoggedRatherThanFatal(t *testing.T) {
	withKernelAggregation(t, true)
	prev := config.WorkloadMetricsDrainInterval
	config.WorkloadMetricsDrainInterval = 10 * time.Millisecond
	t.Cleanup(func() { config.WorkloadMetricsDrainInterval = prev })

	agg := &modeFlakyAggregator{fakeAggregator: &fakeAggregator{}}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := drainKernelMetrics(ctx, agg, kernelTestSink(t), NewRouter(nil), NewMetrics(), logr.Discard()); err != nil {
		t.Errorf("returned %v; a mode write that starts failing mid-run must not take the agent "+
			"down — the event path still produces every family", err)
	}
}

func TestTheLoopRunsWithoutARouter(t *testing.T) {
	withKernelAggregation(t, true)
	prev := config.WorkloadMetricsDrainInterval
	config.WorkloadMetricsDrainInterval = 10 * time.Millisecond
	t.Cleanup(func() { config.WorkloadMetricsDrainInterval = prev })

	agg := &fakeAggregator{}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := drainKernelMetrics(ctx, agg, kernelTestSink(t), nil, NewMetrics(), logr.Discard()); err != nil {
		t.Fatalf("returned %v", err)
	}
	for _, m := range agg.modeLog() {
		if m == kernelagg.ModeOn {
			return
		}
	}
	if len(agg.modeLog()) == 0 {
		t.Error("no mode was ever set without a router")
	}
}

func TestADrainFailureIsCountedAndTheLoopContinues(t *testing.T) {
	withKernelAggregation(t, true)
	prev := config.WorkloadMetricsDrainInterval
	config.WorkloadMetricsDrainInterval = 10 * time.Millisecond
	t.Cleanup(func() { config.WorkloadMetricsDrainInterval = prev })

	agg := &fakeAggregator{drainErr: errors.New("map read failed")}
	metrics := NewMetrics()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := drainKernelMetrics(ctx, agg, kernelTestSink(t), NewRouter(nil), metrics, logr.Discard()); err != nil {
		t.Fatalf("a failing drain returned %v; one bad interval must not stop the loop", err)
	}
	if agg.drainCount() < 2 {
		t.Errorf("drained %d times; the loop must keep trying after a failure", agg.drains)
	}
}
