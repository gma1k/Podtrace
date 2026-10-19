package profiling

import (
	"context"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func fillTriggerQueue(h *Handler) {
	for i := 0; i < cap(h.triggerChan); i++ {
		h.triggerChan <- triggerReq{ptype: ProfileCPU}
	}
}

func returnsWithin(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("call blocked on a full profiling queue")
	}
}

func TestTriggerNowDropsRequestWhenQueueIsFull(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{6060})
	fillTriggerQueue(h)

	returnsWithin(t, func() { h.TriggerNow(ProfileGoroutine, 0) })

	if len(h.triggerChan) != cap(h.triggerChan) {
		t.Errorf("queue length %d, want %d", len(h.triggerChan), cap(h.triggerChan))
	}
	h.queuedMu.Lock()
	defer h.queuedMu.Unlock()
	if h.queued[ProfileGoroutine] {
		t.Error("a dropped request must not be marked as queued")
	}
}

func TestCheckSpikeDoesNotBlockWhenQueueIsFull(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{6060})
	fillTriggerQueue(h)
	slow := &events.Event{
		Type:      events.EventTCPSend,
		LatencyNS: uint64(config.ProfilingAutoTriggerMS*float64(config.NSPerMS)) + 1,
	}

	returnsWithin(t, func() { h.checkSpike(context.Background(), slow) })

	if !h.triggered.Load() {
		t.Error("a slow event must still mark the session as triggered")
	}
	if len(h.triggerChan) != cap(h.triggerChan) {
		t.Errorf("queue length %d, want %d", len(h.triggerChan), cap(h.triggerChan))
	}
	h.queuedMu.Lock()
	defer h.queuedMu.Unlock()
	if h.queued[ProfileHeap] || h.queued[ProfileGoroutine] {
		t.Errorf("rejected auto-trigger profiles must not be marked as queued: %v", h.queued)
	}
}

func TestWorkerStopsWhileWaitingForAFetchSlot(t *testing.T) {
	h := newHandler("10.0.0.1", []int{6060}, make(chan struct{}, 1), 1)
	h.sem <- struct{}{}
	if h.enqueue(ProfileHeap, 0) != triggerQueued {
		t.Fatal("expected the request to be queued")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		h.work(ctx)
		close(done)
	}()
	waitFor(t, func() bool {
		h.queuedMu.Lock()
		defer h.queuedMu.Unlock()
		return !h.queued[ProfileHeap]
	})
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop on cancellation while the fetch slot was taken")
	}
	if len(h.sem) != 1 {
		t.Errorf("sem length %d, want 1: the cancelled worker must not take or release a slot", len(h.sem))
	}
	if h.GetResult() != nil {
		t.Error("no profile may be fetched once the worker is cancelled")
	}
}

func TestNewHandlerFloorsConcurrencyAtOne(t *testing.T) {
	orig := config.ProfilingMaxConcurrent
	config.ProfilingMaxConcurrent = 0
	t.Cleanup(func() { config.ProfilingMaxConcurrent = orig })

	h := NewHandler("10.0.0.1", []int{6060})
	if cap(h.sem) != 1 || h.workers != 1 {
		t.Errorf("sem capacity %d workers %d, want 1 and 1", cap(h.sem), h.workers)
	}
}
