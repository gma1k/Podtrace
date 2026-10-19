package profiling

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

type blockingPprof struct {
	srv      *httptest.Server
	release  chan struct{}
	inFlight *atomic.Int64
	maxSeen  *atomic.Int64
	hits     atomic.Int64
}

func newBlockingPprof(t *testing.T, inFlight, maxSeen *atomic.Int64, release chan struct{}) *blockingPprof {
	t.Helper()
	b := &blockingPprof{release: release, inFlight: inFlight, maxSeen: maxSeen}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/pprof/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		b.hits.Add(1)
		n := inFlight.Add(1)
		for {
			m := maxSeen.Load()
			if n <= m || maxSeen.CompareAndSwap(m, n) {
				break
			}
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestHandlerRepeatedTriggersDoNotPileUpGoroutines(t *testing.T) {
	var inFlight, maxSeen atomic.Int64
	release := make(chan struct{})
	b := newBlockingPprof(t, &inFlight, &maxSeen, release)
	host, port := mustParseAddr(t, b.srv.Listener.Addr().String())
	h := NewHandler(host, []int{port})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx, make(chan *events.Event))
	waitFor(t, func() bool { return h.profiler.foundPort.Load() != 0 })

	h.TriggerNow(ProfileHeap, 0)
	waitFor(t, func() bool { return inFlight.Load() == 1 })

	before := runtime.NumGoroutine()
	for i := 0; i < 500; i++ {
		h.TriggerNow(ProfileHeap, 0)
		h.TriggerNow(ProfileGoroutine, 0)
		h.TriggerNow(ProfileCPU, time.Second)
		time.Sleep(50 * time.Microsecond)
	}
	if grown := runtime.NumGoroutine() - before; grown > 10 {
		t.Errorf("goroutines grew by %d while one fetch was blocked", grown)
	}
	if n := len(h.triggerChan); n > profileTypeCount {
		t.Errorf("queue holds %d requests, want at most one per profile type", n)
	}
	if got := maxSeen.Load(); got > int64(profilingConcurrency()) {
		t.Errorf("%d fetches in flight, want at most %d", got, profilingConcurrency())
	}
	close(release)
	waitFor(t, func() bool { return len(h.triggerChan) == 0 && inFlight.Load() == 0 })
	if hits := b.hits.Load(); hits > 4 {
		t.Errorf("expected repeated triggers to coalesce into at most 4 fetches, got %d", hits)
	}
}

func TestMultiHandlerSharesOneConcurrencyBoundAcrossPods(t *testing.T) {
	var inFlight, maxSeen atomic.Int64
	release := make(chan struct{})
	const pods = 4
	servers := make([]*blockingPprof, 0, pods)
	for i := 0; i < pods; i++ {
		b := newBlockingPprof(t, &inFlight, &maxSeen, release)
		servers = append(servers, b)
	}
	m := &MultiHandler{}
	sem := make(chan struct{}, profilingConcurrency())
	for _, b := range servers {
		host, p := mustParseAddr(t, b.srv.Listener.Addr().String())
		h := newHandler(host, []int{p}, sem, profilingConcurrency())
		h.profiler.foundPort.Store(int64(p))
		m.handlers = append(m.handlers, h)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx, make(chan *events.Event))

	rr := httptest.NewRecorder()
	m.HTTPStart(rr, httptest.NewRequest(http.MethodPost, "/profile/start?type=heap", nil))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rr.Code)
	}
	waitFor(t, func() bool { return inFlight.Load() >= 1 })
	time.Sleep(100 * time.Millisecond)
	if got, want := maxSeen.Load(), int64(profilingConcurrency()); got > want {
		t.Errorf("%d fetches in flight across %d pods, want at most %d", got, pods, want)
	}
	close(release)
	var wg sync.WaitGroup
	for _, h := range m.handlers {
		wg.Add(1)
		go func(h *Handler) {
			defer wg.Done()
			waitFor(t, func() bool { r := h.GetResult(); return r != nil && r.HeapProfile != nil })
		}(h)
	}
	wg.Wait()
}

func TestNewMultiHandlerSharesSemaphore(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1", "10.0.0.2"}, []int{6060})
	if m.handlers[0].sem != m.handlers[1].sem {
		t.Error("pods must share one concurrency semaphore")
	}
	if cap(m.handlers[0].sem) != profilingConcurrency() {
		t.Errorf("sem capacity %d, want %d", cap(m.handlers[0].sem), config.ProfilingMaxConcurrent)
	}
}

func TestHTTPStartReportsCoalescedRequest(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{6060})
	first := httptest.NewRecorder()
	h.HTTPStart(first, httptest.NewRequest(http.MethodPost, "/profile/start?type=cpu", nil))
	second := httptest.NewRecorder()
	h.HTTPStart(second, httptest.NewRequest(http.MethodPost, "/profile/start?type=cpu", nil))

	if first.Code != http.StatusAccepted || second.Code != http.StatusAccepted {
		t.Fatalf("codes %d, %d; want 202, 202", first.Code, second.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(second.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "already_queued" {
		t.Errorf("status=%v want already_queued", body["status"])
	}
	if len(h.triggerChan) != 1 {
		t.Errorf("queue length %d, want 1", len(h.triggerChan))
	}
}

func TestHTTPStartReturns429WhenEveryQueueIsFull(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{6060})
	for i := 0; i < cap(h.triggerChan); i++ {
		h.triggerChan <- triggerReq{ptype: ProfileHeap}
	}
	rr := httptest.NewRecorder()
	h.HTTPStart(rr, httptest.NewRequest(http.MethodPost, "/profile/start?type=goroutine", nil))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header")
	}
}

func TestMultiHandlerHTTPStartClampsDuration(t *testing.T) {
	m := NewMultiHandler([]string{"10.0.0.1"}, []int{6060})
	rr := httptest.NewRecorder()
	m.HTTPStart(rr, httptest.NewRequest(http.MethodPost, "/profile/start?type=cpu&duration=100h", nil))
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if want := clampProfileDuration(100 * time.Hour).String(); body["duration"] != want {
		t.Errorf("duration=%v want %s", body["duration"], want)
	}
}
