package profiling

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/stacktrace"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/metricsexporter"
)

// Handler is the event-channel consumer for performance profiling. It:
//   - Watches the event stream for latency spikes and auto-triggers profiling
//   - Accepts on-demand trigger requests via TriggerNow or the HTTP API
//   - Stores the latest CorrelatedResult for report generation
//
// It implements the tracer.ProfilingController interface (HTTPStart, HTTPStatus,
// HTTPResult) so it can be wired into the management port HTTP server.
type Handler struct {
	profiler    *PodProfiler
	mu          sync.RWMutex
	result      *CorrelatedResult
	triggered   atomic.Bool
	triggerChan chan triggerReq
	sem         chan struct{}
	workers     int
	queuedMu    sync.Mutex
	queued      map[ProfileType]bool
	podIP       string
}

type triggerReq struct {
	ptype    ProfileType
	duration time.Duration
}

// triggerOutcome reports what happened to a trigger request.
type triggerOutcome int

const (
	triggerQueued triggerOutcome = iota
	triggerCoalesced
	triggerRejected
)

const profileTypeCount = 3

// NewHandler creates a Handler for the pod at podIP. ports is the list of
// candidate pprof HTTP ports to probe.
func NewHandler(podIP string, ports []int) *Handler {
	concurrency := profilingConcurrency()
	return newHandler(podIP, ports, make(chan struct{}, concurrency), concurrency)
}

func newHandler(podIP string, ports []int, sem chan struct{}, workers int) *Handler {
	return &Handler{
		profiler:    NewPodProfiler(podIP, ports),
		triggerChan: make(chan triggerReq, profileTypeCount),
		sem:         sem,
		workers:     workers,
		queued:      make(map[ProfileType]bool, profileTypeCount),
		podIP:       podIP,
	}
}

func profilingConcurrency() int {
	if config.ProfilingMaxConcurrent < 1 {
		return 1
	}
	return config.ProfilingMaxConcurrent
}

// clampProfileDuration bounds a requested profile duration to a sane maximum so
// an on-demand request cannot pin a profile fetch (and its worker slot) open
// for an arbitrarily long time.
func clampProfileDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return config.ProfilingDefaultDuration
	}
	if max := config.ProfilingMaxDuration; max > 0 && d > max {
		return max
	}
	return d
}

// Run consumes eventChan, watching for latency spikes that auto-trigger a
// heap + goroutine profile fetch. It also services on-demand trigger requests.
func (h *Handler) Run(ctx context.Context, eventChan <-chan *events.Event) {
	discoverCtx, discoverCancel := context.WithTimeout(ctx, 3*time.Second)
	h.profiler.Discover(discoverCtx)
	discoverCancel()
	h.startWorkers(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-eventChan:
			if !ok {
				return
			}
			h.checkSpike(ctx, e)
		}
	}
}

// startWorkers starts the fixed pool that services triggerChan.
func (h *Handler) startWorkers(ctx context.Context) {
	for i := 0; i < h.workers; i++ {
		go h.work(ctx)
	}
}

func (h *Handler) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-h.triggerChan:
			h.queuedMu.Lock()
			delete(h.queued, req.ptype)
			h.queuedMu.Unlock()
			select {
			case h.sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			h.doProfile(ctx, req.ptype, req.duration)
			<-h.sem
		}
	}
}

// enqueue queues a profile request unless one of the same type is already
// waiting, in which case the waiting request is kept and this one coalesces
// into it. It never blocks.
func (h *Handler) enqueue(ptype ProfileType, duration time.Duration) triggerOutcome {
	h.queuedMu.Lock()
	defer h.queuedMu.Unlock()
	if h.queued[ptype] {
		return triggerCoalesced
	}
	select {
	case h.triggerChan <- triggerReq{ptype: ptype, duration: duration}:
		h.queued[ptype] = true
		return triggerQueued
	default:
		return triggerRejected
	}
}

// checkSpike auto-triggers a heap+goroutine profile when a slow event is seen,
// rate-limited to one trigger per session.
func (h *Handler) checkSpike(ctx context.Context, e *events.Event) {
	if e == nil {
		return
	}
	if !isSlowEventType(e.Type) {
		return
	}
	triggerNS := uint64(config.ProfilingAutoTriggerMS * float64(config.NSPerMS))
	if e.LatencyNS < triggerNS {
		return
	}
	// Only trigger once.
	if !h.triggered.CompareAndSwap(false, true) {
		return
	}
	metricsexporter.RecordProfilingAutoTrigger(h.podIP)
	logger.Info("Profiling auto-triggered by latency spike",
		zap.String("event_type", e.TypeString()),
		zap.Uint64("latency_ns", e.LatencyNS),
		zap.Uint32("pid", e.PID))

	for _, ptype := range []ProfileType{ProfileHeap, ProfileGoroutine} {
		if h.enqueue(ptype, 0) == triggerRejected {
			logger.Warn("Profiling queue full; auto-triggered profile not queued",
				zap.String("type", ptype.String()), zap.String("pod_ip", h.podIP))
		}
	}
}

// doProfile fetches the requested profile type and stores/updates the result.
func (h *Handler) doProfile(ctx context.Context, ptype ProfileType, duration time.Duration) {
	duration = clampProfileDuration(duration)

	var heap, goroutine *ProfileResult

	switch ptype {
	case ProfileHeap:
		heap = h.profiler.FetchHeap(ctx)
		if heap.Error != "" {
			logger.Warn("Heap profile fetch failed", zap.String("error", heap.Error))
			metricsexporter.RecordProfilingFetchError(h.podIP, ProfileHeap.String())
		}
	case ProfileGoroutine:
		goroutine = h.profiler.FetchGoroutine(ctx)
		if goroutine.Error != "" {
			logger.Warn("Goroutine profile fetch failed", zap.String("error", goroutine.Error))
			metricsexporter.RecordProfilingFetchError(h.podIP, ProfileGoroutine.String())
		} else if goroutine.Available {
			metricsexporter.RecordProfilingGoroutines(h.podIP, goroutine.GoroutineCount, goroutine.BlockedCount)
		}
	case ProfileCPU:
		// CPU profile is long; run synchronously (caller already in goroutine).
		cpu := h.profiler.FetchCPUProfile(ctx, duration)
		if cpu.Error != "" {
			logger.Warn("CPU profile fetch failed", zap.String("error", cpu.Error))
			metricsexporter.RecordProfilingFetchError(h.podIP, ProfileCPU.String())
		}
		h.mu.Lock()
		next := h.resultCopyLocked()
		if cpu.Available {
			next.CPUProfile = cpu
			next.PprofAvailable = true
		}
		next.PodIP = h.podIP
		h.result = next
		h.mu.Unlock()
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	next := h.resultCopyLocked()
	if heap != nil {
		next.HeapProfile = heap
		if heap.Available {
			next.PprofAvailable = true
		}
	}
	if goroutine != nil {
		next.GoroutineProfile = goroutine
		if goroutine.Available {
			next.PprofAvailable = true
		}
	}
	next.PodIP = h.podIP
	h.result = next
}

// resultCopyLocked returns a shallow copy of the current result (or a fresh
// one) so the caller can mutate and republish it without touching the struct
// readers may still be dereferencing. Caller holds h.mu.
func (h *Handler) resultCopyLocked() *CorrelatedResult {
	if h.result == nil {
		return &CorrelatedResult{PageFaultCounts: map[uint32]int{}, PodIP: h.podIP}
	}
	cp := *h.result
	return &cp
}

// TriggerNow enqueues an on-demand profile request without blocking. A request
// for a type that is already queued coalesces into the queued one.
func (h *Handler) TriggerNow(ptype ProfileType, duration time.Duration) {
	if h.enqueue(ptype, duration) == triggerRejected {
		logger.Warn("Profiling queue full; dropping request",
			zap.String("type", ptype.String()), zap.String("pod_ip", h.podIP))
	}
}

// GetResult returns the latest stored CorrelatedResult, or nil if no profiling
// has occurred yet.
func (h *Handler) GetResult() *CorrelatedResult {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.result
}

// GenerateSection correlates allEvents with the stored profiling data and
// returns a formatted report section string.
func (h *Handler) GenerateSection(allEvents []*events.Event, duration time.Duration) string {
	h.mu.RLock()
	storedHeap := h.result
	h.mu.RUnlock()

	var heap, goroutine, cpu *ProfileResult
	if storedHeap != nil {
		heap = storedHeap.HeapProfile
		goroutine = storedHeap.GoroutineProfile
		cpu = storedHeap.CPUProfile
	}

	ctx, cancel := context.WithTimeout(context.Background(), symbolizeBudget)
	defer cancel()

	cr := Correlate(ctx, allEvents, heap, goroutine,
		config.ProfilingAutoTriggerMS, stacktrace.NewResolver())
	cr.PodIP = h.podIP
	if cpu != nil && cpu.Available {
		cr.CPUProfile = cpu
		cr.PprofAvailable = true
	}

	// Merge pprof availability from profiler discovery.
	if h.profiler.foundPort.Load() != 0 {
		cr.PprofAvailable = true
	}

	return GenerateSection(cr, duration)
}

// --- HTTP handlers (implements tracer.ProfilingController) ---

// HTTPStart handles POST /profile/start?type=cpu|heap|goroutine&duration=30s
func (h *Handler) HTTPStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ptype, dur := parseStartRequest(r)
	writeStartResponse(w, ptype, dur, []triggerOutcome{h.enqueue(ptype, dur)}, nil)
}

// parseStartRequest reads the profile type and clamped duration of a
// /profile/start request.
func parseStartRequest(r *http.Request) (ProfileType, time.Duration) {
	q := r.URL.Query()
	dur := config.ProfilingDefaultDuration
	if durationStr := q.Get("duration"); durationStr != "" {
		if d, err := time.ParseDuration(durationStr); err == nil && d > 0 {
			dur = clampProfileDuration(d)
		}
	}
	switch strings.ToLower(q.Get("type")) {
	case "cpu":
		return ProfileCPU, dur
	case "goroutine":
		return ProfileGoroutine, dur
	default:
		return ProfileHeap, dur
	}
}

// writeStartResponse answers a /profile/start request. It is 202 when at
// least one pod queued or coalesced the request, and 429 when every pod's
// queue was full, so a caller learns its request was not taken.
func writeStartResponse(w http.ResponseWriter, ptype ProfileType, dur time.Duration, outcomes []triggerOutcome, extra map[string]interface{}) {
	var queued, coalesced, rejected int
	for _, o := range outcomes {
		switch o {
		case triggerQueued:
			queued++
		case triggerCoalesced:
			coalesced++
		default:
			rejected++
		}
	}
	status := "triggered"
	code := http.StatusAccepted
	switch {
	case len(outcomes) > 0 && rejected == len(outcomes):
		status = "busy"
		code = http.StatusTooManyRequests
		w.Header().Set("Retry-After", strconv.Itoa(int(clampProfileDuration(dur).Seconds())+1))
		logger.Warn("Profiling request rejected: queue full",
			zap.String("type", ptype.String()), zap.Int("pods", len(outcomes)))
	case queued == 0 && coalesced > 0:
		status = "already_queued"
	}
	body := map[string]interface{}{
		"status":   status,
		"type":     ptype.String(),
		"duration": dur.String(),
	}
	if coalesced > 0 {
		body["coalesced"] = coalesced
	}
	if rejected > 0 {
		body["rejected"] = rejected
	}
	for k, v := range extra {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// statusMap builds the profiling status payload for this pod.
func (h *Handler) statusMap() map[string]interface{} {
	h.mu.RLock()
	hasResult := h.result != nil
	h.mu.RUnlock()
	return map[string]interface{}{
		"pprof_available":      h.profiler.foundPort.Load() != 0,
		"pprof_port":           h.profiler.foundPort.Load(),
		"has_result":           hasResult,
		"auto_triggered":       h.triggered.Load(),
		"trigger_threshold_ms": config.ProfilingAutoTriggerMS,
		"pod_ip":               h.podIP,
	}
}

// HTTPStatus handles GET /profile/status
func (h *Handler) HTTPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.statusMap())
}

// resultMap builds the JSON-friendly result payload for this pod, or nil when
// no profiling has occurred.
func (h *Handler) resultMap() map[string]interface{} {
	h.mu.RLock()
	result := h.result
	h.mu.RUnlock()
	if result == nil {
		return nil
	}

	type frame struct {
		Frame string `json:"frame"`
		Count int    `json:"count"`
	}
	type proc struct {
		PID        uint32  `json:"pid"`
		Name       string  `json:"name"`
		SchedCount int     `json:"sched_count"`
		AvgBlockNS float64 `json:"avg_block_ns"`
	}
	type allocFn struct {
		Function string `json:"function"`
		Bytes    int64  `json:"bytes"`
		Count    int64  `json:"count"`
	}
	type cpuFn struct {
		Function string `json:"function"`
		CPUNS    int64  `json:"cpu_ns"`
		Samples  int64  `json:"samples"`
	}

	hotFrames := make([]frame, len(result.HotFrames))
	for i, f := range result.HotFrames {
		hotFrames[i] = frame(f)
	}
	procs := make([]proc, len(result.CPUHotProcesses))
	for i, p := range result.CPUHotProcesses {
		procs[i] = proc(p)
	}
	var topAllocs []allocFn
	if result.HeapProfile != nil {
		for _, f := range result.HeapProfile.TopFunctions {
			topAllocs = append(topAllocs, allocFn(f))
		}
	}
	var topCPU []cpuFn
	if result.CPUProfile != nil {
		for _, f := range result.CPUProfile.TopCPUFunctions {
			topCPU = append(topCPU, cpuFn{Function: f.Function, CPUNS: int64(f.CPUTime), Samples: f.Samples})
		}
	}
	goroutineCount := 0
	blockedCount := 0
	if result.GoroutineProfile != nil {
		goroutineCount = result.GoroutineProfile.GoroutineCount
		blockedCount = result.GoroutineProfile.BlockedCount
	}
	pageFaults := map[string]int{}
	for pid, cnt := range result.PageFaultCounts {
		pageFaults[strconv.Itoa(int(pid))] = cnt
	}
	return map[string]interface{}{
		"pprof_available":   result.PprofAvailable,
		"pod_ip":            result.PodIP,
		"slow_event_count":  len(result.SlowEvents),
		"hot_frames":        hotFrames,
		"cpu_hot_processes": procs,
		"top_heap_allocs":   topAllocs,
		"top_cpu_functions": topCPU,
		"goroutine_count":   goroutineCount,
		"blocked_count":     blockedCount,
		"page_fault_pids":   pageFaults,
		"oom_event_count":   len(result.OOMEvents),
		"start_time":        result.StartTime,
		"end_time":          result.EndTime,
	}
}

// HTTPResult handles GET /profile/result
func (h *Handler) HTTPResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := h.resultMap()
	if body == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "no_result"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
