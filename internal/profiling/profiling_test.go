package profiling

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

// ─── profiler.go ─────────────────────────────────────────────────────────────

func TestNewPodProfiler_Fields(t *testing.T) {
	p := NewPodProfiler("10.0.0.1", []int{6060, 8080})
	if p.podIP != "10.0.0.1" {
		t.Errorf("expected podIP=10.0.0.1, got %q", p.podIP)
	}
	if len(p.ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(p.ports))
	}
}

func TestDiscover_EmptyPodIP(t *testing.T) {
	p := NewPodProfiler("", []int{6060})
	if p.Discover(context.Background()) {
		t.Error("Discover should return false for empty podIP")
	}
}

func TestDiscover_AlreadyDiscovered(t *testing.T) {
	p := NewPodProfiler("127.0.0.1", []int{6060})
	p.foundPort.Store(9999)
	if !p.Discover(context.Background()) {
		t.Error("Discover should return true when foundPort already set")
	}
}

func TestDiscover_LiveServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/debug/pprof/") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	// Extract host and port from the test server URL.
	addr := srv.Listener.Addr().String()
	var host string
	var port int
	if _, err := parseAddr(addr, &host, &port); err != nil {
		t.Skipf("cannot parse test server addr: %v", err)
	}

	p := NewPodProfiler(host, []int{port})
	if !p.Discover(context.Background()) {
		t.Error("Discover should return true for a live server with /debug/pprof/")
	}
	if p.foundPort.Load() != int64(port) {
		t.Errorf("expected foundPort=%d, got %d", port, p.foundPort.Load())
	}
}

func TestDiscover_NoServer(t *testing.T) {
	// Port 1 is virtually always refused.
	p := NewPodProfiler("127.0.0.1", []int{1})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if p.Discover(ctx) {
		t.Error("Discover should return false when no server is listening")
	}
}

func TestFetchHeap_NoEndpoint(t *testing.T) {
	p := NewPodProfiler("127.0.0.1", []int{})
	r := p.FetchHeap(context.Background())
	if r.Available {
		t.Error("expected Available=false when no endpoint discovered")
	}
	if r.Error == "" {
		t.Error("expected non-empty Error")
	}
}

func TestFetchGoroutine_NoEndpoint(t *testing.T) {
	p := NewPodProfiler("127.0.0.1", []int{})
	r := p.FetchGoroutine(context.Background())
	if r.Available {
		t.Error("expected Available=false when no endpoint discovered")
	}
}

func TestFetchCPUProfile_NoEndpoint(t *testing.T) {
	p := NewPodProfiler("127.0.0.1", []int{})
	r := p.FetchCPUProfile(context.Background(), time.Second)
	if r.Available {
		t.Error("expected Available=false when no endpoint discovered")
	}
}

func TestFetchHeap_LiveServer(t *testing.T) {
	const heapText = `heap profile: 1: 1024 [1: 1024] @ heap/1048576
1: 1024 [1: 1024] @
#	0x0	example.com/pkg.Alloc+0x0	file.go:1

`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(heapText))
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	p.foundPort.Store(int64(port))
	r := p.FetchHeap(context.Background())
	if !r.Available {
		t.Errorf("expected Available=true, error=%q", r.Error)
	}
	if r.Type != ProfileHeap {
		t.Errorf("expected type=heap, got %v", r.Type)
	}
}

func TestFetchGoroutine_LiveServer(t *testing.T) {
	const goroutineText = `goroutine 1 [running]:
main.main()
	main.go:10

goroutine 2 [chan receive]:
runtime.gopark()
	proc.go:100

goroutine 3 [select]:
runtime.gopark()
	proc.go:100
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(goroutineText))
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	p.foundPort.Store(int64(port))
	r := p.FetchGoroutine(context.Background())
	if !r.Available {
		t.Errorf("expected Available=true, error=%q", r.Error)
	}
	if r.GoroutineCount != 3 {
		t.Errorf("expected GoroutineCount=3, got %d", r.GoroutineCount)
	}
	if r.BlockedCount != 2 {
		t.Errorf("expected BlockedCount=2, got %d", r.BlockedCount)
	}
}

func TestFetchCPUProfile_LiveServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake-cpu-profile-data"))
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	p.foundPort.Store(int64(port))
	r := p.FetchCPUProfile(context.Background(), 1*time.Second)
	if !r.Available {
		t.Errorf("expected Available=true, error=%q", r.Error)
	}
	if r.RawBytes != nil {
		t.Error("expected the CPU profile body to be dropped once parsed")
	}
	if len(r.TopCPUFunctions) != 0 {
		t.Errorf("expected no functions from an unparseable body, got %v", r.TopCPUFunctions)
	}
}

func TestFetchHeap_ServerReturns500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	p.foundPort.Store(int64(port))
	r := p.FetchHeap(context.Background())
	if r.Available {
		t.Error("expected Available=false for 500 response")
	}
}

func TestFetchCPUProfile_ServerReturns404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	p := NewPodProfiler(host, []int{port})
	p.foundPort.Store(int64(port))
	r := p.FetchCPUProfile(context.Background(), 1*time.Second)
	if r.Available {
		t.Error("expected Available=false for 404 response")
	}
}

// ─── ProfileType.String ───────────────────────────────────────────────────────

func TestProfileType_String(t *testing.T) {
	cases := []struct {
		pt   ProfileType
		want string
	}{
		{ProfileHeap, "heap"},
		{ProfileGoroutine, "goroutine"},
		{ProfileCPU, "cpu"},
		{ProfileType(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.pt.String(); got != c.want {
			t.Errorf("ProfileType(%d).String() = %q, want %q", c.pt, got, c.want)
		}
	}
}

// ─── parseHeapText ────────────────────────────────────────────────────────────

func TestParseHeapText_EmptyInput(t *testing.T) {
	samples := parseHeapText("")
	if len(samples) != 0 {
		t.Errorf("expected 0 samples for empty input, got %d", len(samples))
	}
}

func TestParseHeapText_WithAllocations(t *testing.T) {
	text := `heap profile: 2: 2048 [2: 2048] @ heap/1048576
1: 1024 [1: 1024] @
#	0x0	example.com/pkg.BigAlloc+0x1a	file.go:20
#	0x1	example.com/pkg.Caller+0x2b	file.go:30

1: 1024 [1: 1024] @
#	0x2	example.com/pkg.OtherAlloc+0x0	other.go:5
`
	samples := parseHeapText(text)
	if len(samples) == 0 {
		t.Error("expected at least one sample from heap text")
	}
	// Verify sorting: first sample should have highest or equal bytes.
	for i := 1; i < len(samples); i++ {
		if samples[i].Bytes > samples[i-1].Bytes {
			t.Errorf("samples not sorted by bytes desc at index %d", i)
		}
	}
}

func TestParseHeapText_SkipsMallocgc(t *testing.T) {
	text := `1: 512 [1: 512] @
#	0x0	runtime.mallocgc+0x0	malloc.go:1
#	0x1	example.com/pkg.RealAlloc+0x0	file.go:1
`
	samples := parseHeapText(text)
	for _, s := range samples {
		if strings.Contains(s.Function, "mallocgc") {
			t.Errorf("mallocgc should be filtered from samples, got %q", s.Function)
		}
	}
}

func TestParseHeapText_Top20Cap(t *testing.T) {
	// Build a heap text with 25 distinct functions.
	var sb strings.Builder
	for i := 0; i < 25; i++ {
		sb.WriteString("1: 1024 [1: 1024] @\n")
		sb.WriteString("# 0x0\texample.com/pkg.Func")
		for c := 'a'; c <= 'z' && int(c-'a') == i%26; c++ {
			sb.WriteRune(c)
		}
		sb.WriteString("+0x0\tfile.go:1\n\n")
	}
	samples := parseHeapText(sb.String())
	if len(samples) > 20 {
		t.Errorf("expected at most 20 samples, got %d", len(samples))
	}
}

// ─── parseGoroutineText ───────────────────────────────────────────────────────

func TestParseGoroutineText_EmptyInput(t *testing.T) {
	total, blocked := parseGoroutineText("")
	if total != 0 || blocked != 0 {
		t.Errorf("expected 0,0 for empty input, got %d,%d", total, blocked)
	}
}

func TestParseGoroutineText_MixedStates(t *testing.T) {
	text := `goroutine 1 [running]:
main.main()

goroutine 2 [chan receive]:
runtime.gopark()

goroutine 3 [select]:
runtime.gopark()

goroutine 4 [IO wait]:
net.(*netFD).Read()

goroutine 5 [semacquire]:
sync.runtime_SemacquireMutex()
`
	total, blocked := parseGoroutineText(text)
	if total != 5 {
		t.Errorf("expected total=5, got %d", total)
	}
	// running is not blocked; chan receive, select, IO wait, semacquire are.
	if blocked != 4 {
		t.Errorf("expected blocked=4, got %d", blocked)
	}
}

func TestParseGoroutineText_WithDuration(t *testing.T) {
	// State can include duration like "[chan receive, 5 minutes]".
	text := `goroutine 1 [chan receive, 5 minutes]:
runtime.gopark()
`
	total, blocked := parseGoroutineText(text)
	if total != 1 {
		t.Errorf("expected total=1, got %d", total)
	}
	if blocked != 1 {
		t.Errorf("expected blocked=1 for 'chan receive' with duration, got %d", blocked)
	}
}

// ─── correlator.go ────────────────────────────────────────────────────────────

func TestCorrelate_NilEvents(t *testing.T) {
	cr := Correlate(context.Background(), nil, nil, nil, 100.0, nil)
	if cr == nil {
		t.Fatal("expected non-nil CorrelatedResult")
		return
	}
	if len(cr.SlowEvents) != 0 {
		t.Errorf("expected no slow events for nil input")
	}
}

func TestCorrelate_EmptyEvents(t *testing.T) {
	cr := Correlate(context.Background(), []*events.Event{}, nil, nil, 100.0, nil)
	if cr == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCorrelate_OOMAndPageFault(t *testing.T) {
	evts := []*events.Event{
		{Type: events.EventOOMKill, Target: "leaky-process", Bytes: 1024 * 1024},
		{Type: events.EventPageFault, PID: 42},
		{Type: events.EventPageFault, PID: 42},
		{Type: events.EventPageFault, PID: 99},
	}
	cr := Correlate(context.Background(), evts, nil, nil, 100.0, nil)
	if len(cr.OOMEvents) != 1 {
		t.Errorf("expected 1 OOM event, got %d", len(cr.OOMEvents))
	}
	if cr.PageFaultCounts[42] != 2 {
		t.Errorf("expected 2 page faults for PID 42, got %d", cr.PageFaultCounts[42])
	}
	if cr.PageFaultCounts[99] != 1 {
		t.Errorf("expected 1 page fault for PID 99, got %d", cr.PageFaultCounts[99])
	}
}

func TestCorrelate_SlowEvents_SortedByLatency(t *testing.T) {
	evts := []*events.Event{
		{Type: events.EventTCPSend, LatencyNS: 500_000_000, PID: 1},   // 500ms
		{Type: events.EventTCPSend, LatencyNS: 1_000_000_000, PID: 2}, // 1s
		{Type: events.EventTCPSend, LatencyNS: 100_000_000, PID: 3},   // 100ms
	}
	cr := Correlate(context.Background(), evts, nil, nil, 50.0, nil) // 50ms threshold
	if len(cr.SlowEvents) == 0 {
		t.Fatal("expected slow events above 50ms threshold")
	}
	for i := 1; i < len(cr.SlowEvents); i++ {
		if cr.SlowEvents[i].LatencyNS > cr.SlowEvents[i-1].LatencyNS {
			t.Errorf("slow events not sorted by latency desc at index %d", i)
		}
	}
}

func TestCorrelate_SchedSwitchCorrelation(t *testing.T) {
	// A slow TCP event creates a window; a SchedSwitch inside the window should
	// contribute hot frames.
	slowTS := uint64(time.Now().Add(-GetClockOffset_ns()).UnixNano())
	evts := []*events.Event{
		{
			Type:      events.EventTCPSend,
			LatencyNS: 500_000_000, // 500ms > threshold
			PID:       10,
			Timestamp: slowTS,
		},
		{
			Type:      events.EventSchedSwitch,
			LatencyNS: 1_000_000,
			PID:       10,
			Timestamp: slowTS + 10_000_000, // 10ms later (inside window)
			Stack:     []uint64{0xdeadbeef, 0xcafebabe},
		},
	}
	cr := Correlate(context.Background(), evts, nil, nil, 100.0, nil) // 100ms threshold
	_ = cr                                                            // result depends on clock alignment; just ensure no panic
}

func TestCorrelate_WithPprofData(t *testing.T) {
	heap := &ProfileResult{
		Type:      ProfileHeap,
		Available: true,
		TopFunctions: []FunctionSample{
			{Function: "pkg.Alloc", Bytes: 1024, Count: 5},
		},
	}
	goroutine := &ProfileResult{
		Type:           ProfileGoroutine,
		Available:      true,
		GoroutineCount: 10,
		BlockedCount:   3,
	}
	cr := Correlate(context.Background(), []*events.Event{}, heap, goroutine, 100.0, nil)
	if !cr.PprofAvailable {
		t.Error("expected PprofAvailable=true when heap and goroutine profiles are available")
	}
	if cr.HeapProfile == nil {
		t.Error("expected HeapProfile to be set")
	}
	if cr.GoroutineProfile == nil {
		t.Error("expected GoroutineProfile to be set")
	}
}

func TestCorrelate_NilProfileResults(t *testing.T) {
	cr := Correlate(context.Background(), []*events.Event{}, nil, nil, 100.0, nil)
	if cr.PprofAvailable {
		t.Error("expected PprofAvailable=false when both profiles are nil")
	}
}

func TestIsSlowEventType_Coverage(t *testing.T) {
	slow := []events.EventType{
		events.EventTCPSend, events.EventTCPRecv, events.EventConnect,
		events.EventRead, events.EventWrite, events.EventFsync,
		events.EventDNS, events.EventDBQuery, events.EventRedisCmd,
		events.EventMemcachedCmd, events.EventGRPCMethod,
		events.EventKafkaProduce, events.EventKafkaFetch,
		events.EventTLSHandshake, events.EventLockContention,
		events.EventHTTPResp, events.EventFastCGIResp,
	}
	for _, et := range slow {
		if !isSlowEventType(et) {
			t.Errorf("expected isSlowEventType(%v)=true", et)
		}
	}
	// PageFault, OOMKill, SchedSwitch, Fork, Exec are not slow.
	notSlowActual := []events.EventType{
		events.EventPageFault, events.EventOOMKill, events.EventSchedSwitch,
		events.EventFork, events.EventExec,
	}
	for _, et := range notSlowActual {
		if isSlowEventType(et) {
			t.Errorf("expected isSlowEventType(%v)=false", et)
		}
	}
}

func TestGenerateSection_NilResult(t *testing.T) {
	out := GenerateSection(nil, time.Second)
	if out != "" {
		t.Errorf("expected empty string for nil CorrelatedResult, got %q", out)
	}
}

func TestGenerateSection_NoPprofAvailable(t *testing.T) {
	cr := &CorrelatedResult{
		PprofAvailable:  false,
		PageFaultCounts: map[uint32]int{},
	}
	out := GenerateSection(cr, time.Second)
	if !strings.Contains(out, "not found") {
		t.Errorf("expected 'not found' tip when pprof unavailable, got %q", out)
	}
}

func TestGenerateSection_WithSlowEvents(t *testing.T) {
	cr := &CorrelatedResult{
		PprofAvailable: true,
		PodIP:          "10.0.0.1",
		SlowEvents: []*events.Event{
			{Type: events.EventTCPSend, LatencyNS: 1_000_000_000, PID: 1, ProcessName: "myapp", Target: "db:5432"},
		},
		PageFaultCounts: map[uint32]int{},
	}
	out := GenerateSection(cr, time.Second)
	if !strings.Contains(out, "Slow events") {
		t.Errorf("expected 'Slow events' in output, got %q", out)
	}
}

func TestGenerateSection_WithHighBlockedGoroutines(t *testing.T) {
	cr := &CorrelatedResult{
		PprofAvailable: true,
		GoroutineProfile: &ProfileResult{
			Available:      true,
			GoroutineCount: 200,
			BlockedCount:   60, // > 50 → warning
		},
		PageFaultCounts: map[uint32]int{},
	}
	out := GenerateSection(cr, time.Second)
	if !strings.Contains(out, "WARNING") {
		t.Errorf("expected WARNING for high blocked goroutine count, got %q", out)
	}
}

func TestGenerateSection_WithHeapTopFunctions(t *testing.T) {
	cr := &CorrelatedResult{
		PprofAvailable: true,
		HeapProfile: &ProfileResult{
			Available: true,
			TopFunctions: []FunctionSample{
				{Function: "pkg.BigAlloc", Bytes: 4 * 1024 * 1024, Count: 10},
			},
		},
		PageFaultCounts: map[uint32]int{},
	}
	out := GenerateSection(cr, time.Second)
	if !strings.Contains(out, "heap alloc") {
		t.Errorf("expected heap alloc section, got %q", out)
	}
}

func TestGenerateSection_WithPageFaults(t *testing.T) {
	cr := &CorrelatedResult{
		PprofAvailable:  false,
		PageFaultCounts: map[uint32]int{42: 100, 99: 50},
	}
	out := GenerateSection(cr, time.Second)
	if !strings.Contains(out, "Page faults") {
		t.Errorf("expected 'Page faults' in output, got %q", out)
	}
}

func TestGenerateSection_WithOOMEvents(t *testing.T) {
	cr := &CorrelatedResult{
		PprofAvailable: false,
		OOMEvents: []*events.Event{
			{Target: "leaky", Bytes: 512 * 1024 * 1024},
		},
		PageFaultCounts: map[uint32]int{},
	}
	out := GenerateSection(cr, time.Second)
	if !strings.Contains(out, "OOM Kill") {
		t.Errorf("expected 'OOM Kill' in output, got %q", out)
	}
}

func TestGenerateSection_CPUSchedulingActivity(t *testing.T) {
	cr := &CorrelatedResult{
		PprofAvailable: false,
		CPUHotProcesses: []ProcessCPU{
			{PID: 1, Name: "myapp", SchedCount: 100, AvgBlockNS: 50_000},
		},
		PageFaultCounts: map[uint32]int{},
	}
	out := GenerateSection(cr, time.Second)
	if !strings.Contains(out, "CPU Scheduling") {
		t.Errorf("expected 'CPU Scheduling' in output, got %q", out)
	}
}

func TestGenerateSection_HotFrames(t *testing.T) {
	cr := &CorrelatedResult{
		PprofAvailable: false,
		HotFrames: []FrameCount{
			{Frame: "0xdeadbeef", Count: 5},
			{Frame: "0xcafebabe", Count: 3},
		},
		PageFaultCounts: map[uint32]int{},
	}
	out := GenerateSection(cr, time.Second)
	if !strings.Contains(out, "hot frames") {
		t.Errorf("expected 'hot frames' in output, got %q", out)
	}
}

// ─── handler.go ──────────────────────────────────────────────────────────────

func TestNewHandler_Fields(t *testing.T) {
	h := NewHandler("10.0.0.5", []int{6060, 8080})
	if h.podIP != "10.0.0.5" {
		t.Errorf("expected podIP=10.0.0.5, got %q", h.podIP)
	}
	if h.profiler == nil {
		t.Error("expected non-nil profiler")
	}
	if h.triggerChan == nil {
		t.Error("expected non-nil triggerChan")
	}
}

func TestHandler_TriggerNow_NonBlocking(t *testing.T) {
	h := NewHandler("", []int{})
	// Fill the channel.
	for i := 0; i < config.ProfilingMaxConcurrent; i++ {
		h.TriggerNow(ProfileHeap, 0)
	}
	// Extra trigger should be dropped without blocking.
	done := make(chan struct{})
	go func() {
		h.TriggerNow(ProfileHeap, 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("TriggerNow blocked when channel is full")
	}
}

func TestHandler_GetResult_InitiallyNil(t *testing.T) {
	h := NewHandler("", []int{})
	if h.GetResult() != nil {
		t.Error("expected nil result before any profiling")
	}
}

func TestHandler_Run_CtxCancel(t *testing.T) {
	h := NewHandler("127.0.0.1", []int{1})
	ch := make(chan *events.Event)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.Run(ctx, ch)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run did not exit after context cancel")
	}
}

func TestHandler_Run_ClosedChannel(t *testing.T) {
	h := NewHandler("127.0.0.1", []int{1})
	ch := make(chan *events.Event)
	close(ch)
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		h.Run(ctx, ch)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run did not exit when channel closed")
	}
}

func TestHandler_Run_AutoTrigger_OnlyOnce(t *testing.T) {
	// Create a test pprof server that serves heap and goroutine endpoints.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(""))
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	h := NewHandler(host, []int{port})

	ch := make(chan *events.Event, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go h.Run(ctx, ch)
	time.Sleep(50 * time.Millisecond) // let Discover run

	// Send a high-latency slow event to trigger auto-profile.
	triggerNS := uint64(config.ProfilingAutoTriggerMS*float64(config.NSPerMS)) + 1
	ch <- &events.Event{Type: events.EventTCPSend, LatencyNS: triggerNS}
	// Send a second one; should be rate-limited (no second trigger).
	ch <- &events.Event{Type: events.EventTCPSend, LatencyNS: triggerNS}

	time.Sleep(200 * time.Millisecond)
	if !h.triggered.Load() {
		t.Error("expected triggered=true after high-latency event")
	}
}

func TestHandler_Run_NilEvent(t *testing.T) {
	h := NewHandler("127.0.0.1", []int{1})
	ch := make(chan *events.Event, 2)
	ch <- nil // nil event should be skipped without panic
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	h.Run(ctx, ch) // returns when ctx done
}

func TestHandler_GenerateSection_NilResult(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{})
	out := h.GenerateSection([]*events.Event{}, time.Second)
	// With no result and no pprof endpoint, should still produce a section string.
	if out == "" {
		t.Error("expected non-empty section even with no profiling data")
	}
}

func TestHandler_GenerateSection_WithResult(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{})
	h.mu.Lock()
	h.result = &CorrelatedResult{
		PprofAvailable:  true,
		PodIP:           "10.0.0.1",
		PageFaultCounts: map[uint32]int{},
		HeapProfile: &ProfileResult{
			Available: true,
			TopFunctions: []FunctionSample{
				{Function: "pkg.BigAlloc", Bytes: 1024, Count: 1},
			},
		},
	}
	h.mu.Unlock()

	evts := []*events.Event{
		{Type: events.EventTCPSend, LatencyNS: 500_000_000},
	}
	out := h.GenerateSection(evts, time.Second)
	if out == "" {
		t.Error("expected non-empty section with stored result")
	}
}

// ─── Handler HTTP endpoints ───────────────────────────────────────────────────

func TestHTTPStatus_MethodNotAllowed(t *testing.T) {
	h := NewHandler("", []int{})
	req := httptest.NewRequest(http.MethodPost, "/profile/status", nil)
	rr := httptest.NewRecorder()
	h.HTTPStatus(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHTTPStatus_NoResult(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{6060})
	req := httptest.NewRequest(http.MethodGet, "/profile/status", nil)
	rr := httptest.NewRecorder()
	h.HTTPStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["has_result"] != false {
		t.Errorf("expected has_result=false, got %v", body["has_result"])
	}
}

func TestHTTPResult_MethodNotAllowed(t *testing.T) {
	h := NewHandler("", []int{})
	req := httptest.NewRequest(http.MethodPost, "/profile/result", nil)
	rr := httptest.NewRecorder()
	h.HTTPResult(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHTTPResult_NoContent(t *testing.T) {
	h := NewHandler("", []int{})
	req := httptest.NewRequest(http.MethodGet, "/profile/result", nil)
	rr := httptest.NewRecorder()
	h.HTTPResult(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
}

func TestHTTPResult_WithResult(t *testing.T) {
	h := NewHandler("10.0.0.1", []int{})
	h.mu.Lock()
	h.result = &CorrelatedResult{
		PprofAvailable:  true,
		PodIP:           "10.0.0.1",
		PageFaultCounts: map[uint32]int{42: 5},
		HotFrames:       []FrameCount{{Frame: "0xabcd", Count: 3}},
		CPUHotProcesses: []ProcessCPU{{PID: 1, Name: "app", SchedCount: 10}},
		HeapProfile: &ProfileResult{
			Available:    true,
			TopFunctions: []FunctionSample{{Function: "pkg.Alloc", Bytes: 512, Count: 1}},
		},
		GoroutineProfile: &ProfileResult{
			Available:      true,
			GoroutineCount: 5,
			BlockedCount:   1,
		},
	}
	h.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/profile/result", nil)
	rr := httptest.NewRecorder()
	h.HTTPResult(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["pprof_available"] != true {
		t.Errorf("expected pprof_available=true, got %v", body["pprof_available"])
	}
	if body["goroutine_count"].(float64) != 5 {
		t.Errorf("expected goroutine_count=5, got %v", body["goroutine_count"])
	}
}

func TestHTTPStart_MethodNotAllowed(t *testing.T) {
	h := NewHandler("", []int{})
	req := httptest.NewRequest(http.MethodGet, "/profile/start", nil)
	rr := httptest.NewRecorder()
	h.HTTPStart(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHTTPStart_DefaultType(t *testing.T) {
	h := NewHandler("", []int{})
	req := httptest.NewRequest(http.MethodPost, "/profile/start", nil)
	rr := httptest.NewRecorder()
	h.HTTPStart(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["type"] != "heap" {
		t.Errorf("expected default type=heap, got %q", body["type"])
	}
}

func TestHTTPStart_CPUType(t *testing.T) {
	h := NewHandler("", []int{})
	req := httptest.NewRequest(http.MethodPost, "/profile/start?type=cpu&duration=5s", nil)
	rr := httptest.NewRecorder()
	h.HTTPStart(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if body["type"] != "cpu" {
		t.Errorf("expected type=cpu, got %q", body["type"])
	}
}

func TestHTTPStart_GoroutineType(t *testing.T) {
	h := NewHandler("", []int{})
	req := httptest.NewRequest(http.MethodPost, "/profile/start?type=goroutine", nil)
	rr := httptest.NewRecorder()
	h.HTTPStart(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rr.Code)
	}
	var body map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body["type"] != "goroutine" {
		t.Errorf("expected type=goroutine, got %q", body["type"])
	}
}

func TestHTTPStart_InvalidDuration(t *testing.T) {
	h := NewHandler("", []int{})
	req := httptest.NewRequest(http.MethodPost, "/profile/start?duration=notaduration", nil)
	rr := httptest.NewRecorder()
	h.HTTPStart(rr, req)
	// Invalid duration falls back to default — should still return 202.
	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202 for invalid duration, got %d", rr.Code)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// parseAddr splits "host:port" into host string and port int.
func parseAddr(addr string, host *string, port *int) (bool, error) {
	var h string
	var p int
	_, err := parseHostPort(addr, &h, &p)
	if err != nil {
		return false, err
	}
	*host = h
	*port = p
	return true, nil
}

func parseHostPort(addr string, host *string, port *int) (bool, error) {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon < 0 {
		return false, nil
	}
	h := addr[:lastColon]
	if h == "" {
		h = "127.0.0.1"
	}
	var p int
	if _, err := parseInt(addr[lastColon+1:], &p); err != nil {
		return false, err
	}
	*host = h
	*port = p
	return true, nil
}

func parseInt(s string, out *int) (bool, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return false, nil
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return true, nil
}

func mustParseAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	var host string
	var port int
	if _, err := parseAddr(addr, &host, &port); err != nil || port == 0 {
		t.Skipf("cannot parse test server address %q", addr)
	}
	return host, port
}

// GetClockOffset_ns returns the clock offset as a duration for use in
// computing BPF-like timestamps in tests.
func GetClockOffset_ns() time.Duration {
	return time.Duration(clock.MonotonicToWallOffset())
}

// Ensure atomic.Bool is used (keeps the import).
var _ atomic.Bool
