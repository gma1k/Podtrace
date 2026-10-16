package tracer_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/pkg/tracer"
)

// statsCallingObserver re-enters the engine from inside the observer
// callback — this deadlocked when callbacks ran under the engine mutex.
type statsCallingObserver struct {
	eng   tracer.Engine
	mu    sync.Mutex
	calls int
}

func (o *statsCallingObserver) OnCgroupsAttached(int) {
	_ = o.eng.Stats()
	o.mu.Lock()
	o.calls++
	o.mu.Unlock()
}
func (o *statsCallingObserver) OnCgroupsDetached(int) { _ = o.eng.Stats() }

func TestEngine_ObserverMayCallStats(t *testing.T) {
	backend := &mockBackend{}
	obs := &statsCallingObserver{}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{&recordingExporter{name: "x"}},
		tracer.Config{Observer: obs})
	if err != nil {
		t.Fatal(err)
	}
	obs.eng = eng

	ctx, cancel := context.WithCancel(context.Background())
	targets := make(chan tracer.TargetSet, 1)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	targets <- tracer.TargetSet{{CgroupPath: "/sys/fs/cgroup/x"}}

	deadline := time.After(5 * time.Second)
	for {
		obs.mu.Lock()
		calls := obs.calls
		obs.mu.Unlock()
		if calls > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("observer callback never completed — Stats() re-entry deadlocked the engine")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("engine Run returned %v on shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not shut down")
	}
}

// ctxHonoringExporter fails any Export whose context is already done —
// like every real OTLP/HTTP exporter.
type ctxHonoringExporter struct {
	recordingExporter
}

func (e *ctxHonoringExporter) Export(ctx context.Context, batch []*events.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return e.recordingExporter.Export(ctx, batch)
}

// TestEngine_ShutdownFlushesTailBatch: the final flush used to run with
// the already-cancelled run context, so ctx-honoring exporters dropped
// the tail batch of every run.
func TestEngine_ShutdownFlushesTailBatch(t *testing.T) {
	backend := &mockBackend{}
	exporter := &ctxHonoringExporter{recordingExporter{name: "ctx"}}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exporter},
		tracer.Config{EventBufferSize: 16, ExportBatchSize: 100})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{{CgroupPath: "/c"}}
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()
	waitUntil(t, 2*time.Second, func() bool { return len(backend.attachedPaths()) == 1 })

	for i := 0; i < 3; i++ {
		backend.emit(t, &events.Event{Type: events.EventDNS})
	}
	waitForReceived(t, eng, 3)

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("engine Run returned %v on shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not shut down")
	}

	if got := exporter.totalEvents(); got != 3 {
		t.Errorf("tail batch: exporter received %d events, want 3", got)
	}
	if got := eng.Stats().EventsExported; got != 3 {
		t.Errorf("EventsExported = %d, want 3", got)
	}
}

// TestEngine_DropsAreCounted: EventsDropped stayed permanently 0 even
// when every exporter rejected every batch.
func TestEngine_DropsAreCounted(t *testing.T) {
	backend := &mockBackend{}
	exporter := &recordingExporter{name: "down", exportErr: errors.New("collector down")}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exporter},
		tracer.Config{EventBufferSize: 16, ExportBatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{{CgroupPath: "/c"}}
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()
	waitUntil(t, 2*time.Second, func() bool { return len(backend.attachedPaths()) == 1 })

	for i := 0; i < 4; i++ {
		backend.emit(t, &events.Event{Type: events.EventDNS})
	}
	waitForReceived(t, eng, 4)

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("engine Run returned %v on shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not shut down")
	}

	stats := eng.Stats()
	if stats.EventsDropped != 4 {
		t.Errorf("EventsDropped = %d, want 4 (every export failed)", stats.EventsDropped)
	}
	if stats.EventsExported != 0 {
		t.Errorf("EventsExported = %d, want 0", stats.EventsExported)
	}
}

func waitForReceived(t *testing.T, eng tracer.Engine, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if eng.Stats().EventsReceived >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("EventsReceived = %d, want %d", eng.Stats().EventsReceived, want)
}
