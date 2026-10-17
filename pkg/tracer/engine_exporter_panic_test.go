package tracer_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/pkg/tracer"
)

type panickingExporter struct {
	mu    sync.Mutex
	calls int
}

func (p *panickingExporter) Name() string { return "panicking" }

func (p *panickingExporter) Export(context.Context, []*events.Event) error {
	p.mu.Lock()
	p.calls++
	first := p.calls == 1
	p.mu.Unlock()
	if first {
		panic("label value is not valid UTF-8")
	}
	return nil
}

func (p *panickingExporter) Close(context.Context) error { return nil }

type recordingPanicObserver struct {
	mu       sync.Mutex
	exporter string
	panics   int
}

func (o *recordingPanicObserver) OnCgroupsAttached(int) {}
func (o *recordingPanicObserver) OnCgroupsDetached(int) {}
func (o *recordingPanicObserver) OnExporterPanic(exporter string, _ any, stack []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.exporter = exporter
	if len(stack) > 0 {
		o.panics++
	}
}

func (o *recordingPanicObserver) count() (string, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.exporter, o.panics
}

func TestEngineSurvivesAnExporterPanicAndKeepsDelivering(t *testing.T) {
	backend := &mockBackend{}
	bad := &panickingExporter{}
	good := &recordingExporter{name: "good"}
	obs := &recordingPanicObserver{}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{bad, good}, tracer.Config{
		EventBufferSize: 16,
		ExportBatchSize: 1,
		Observer:        obs,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{{CgroupPath: "/c"}}
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return len(backend.activePaths()) == 1 })
	backend.emit(t, &events.Event{Type: events.EventRedisCmd})
	backend.emit(t, &events.Event{Type: events.EventRedisCmd})

	waitUntil(t, 2*time.Second, func() bool { return good.totalEvents() == 2 })
	if name, n := obs.count(); name != "panicking" || n != 1 {
		t.Errorf("observer saw exporter=%q panics=%d, want panicking/1", name, n)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if s := eng.Stats(); s.ExporterFailure != 1 {
		t.Errorf("ExporterFailure = %d, want 1", s.ExporterFailure)
	}
}
