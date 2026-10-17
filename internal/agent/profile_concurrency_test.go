package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestProfileGateRejectsConcurrentRequestWithRetryAfter(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	var calls atomic.Int32
	h := newProfileGate(20 * time.Millisecond).limit(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		w.WriteHeader(http.StatusOK)
	})

	first := httptest.NewRecorder()
	firstDone := make(chan struct{})
	go func() {
		h(first, httptest.NewRequest(http.MethodGet, "/profile", nil))
		close(firstDone)
	}()
	<-started

	second := httptest.NewRecorder()
	h(second, httptest.NewRequest(http.MethodGet, "/profile", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("concurrent request status = %d, want 429", second.Code)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Error("429 carries no Retry-After")
	}

	close(release)
	<-firstDone
	if first.Code != http.StatusOK {
		t.Fatalf("first request status = %d", first.Code)
	}

	third := httptest.NewRecorder()
	h(third, httptest.NewRequest(http.MethodGet, "/profile", nil))
	if third.Code != http.StatusOK {
		t.Fatalf("request after release status = %d, want 200", third.Code)
	}
}

func TestProfileGateQueuedRequestRunsWhenSlotFrees(t *testing.T) {
	gate := newProfileGate(5 * time.Second)
	gate.slot <- struct{}{}
	h := gate.limit(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h(rec, httptest.NewRequest(http.MethodGet, "/profile", nil))
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	<-gate.slot

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("queued request never ran")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("queued request status = %d, want 200", rec.Code)
	}
}

func TestProfileGateAbandonsWaitWhenClientLeaves(t *testing.T) {
	gate := newProfileGate(5 * time.Second)
	gate.slot <- struct{}{}
	var ran atomic.Bool
	h := gate.limit(func(w http.ResponseWriter, r *http.Request) { ran.Store(true) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/profile", nil).WithContext(ctx))
	if ran.Load() {
		t.Fatal("handler ran for a departed client")
	}
	if time.Since(start) > time.Second {
		t.Fatal("wait ignored the request context")
	}
}
