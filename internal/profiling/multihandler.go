package profiling

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

// Reporter is the report-generation subset shared by the single-pod Handler and
// the multi-pod MultiHandler, so the CLI report path can hold either without
// caring how many pods are being profiled.
type Reporter interface {
	GenerateSection(allEvents []*events.Event, duration time.Duration) string
}

// MultiHandler fans profiling across every target pod on the node: one Handler
// (one pprof scrape target) per pod IP.
type MultiHandler struct {
	handlers []*Handler
}

// NewMultiHandler builds one Handler per distinct, non-empty pod IP.
func NewMultiHandler(podIPs []string, ports []int) *MultiHandler {
	concurrency := profilingConcurrency()
	sem := make(chan struct{}, concurrency)
	hs := make([]*Handler, 0, len(podIPs))
	seen := make(map[string]struct{}, len(podIPs))
	for _, ip := range podIPs {
		if ip == "" {
			continue
		}
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		hs = append(hs, newHandler(ip, ports, sem, concurrency))
	}
	return &MultiHandler{handlers: hs}
}

// Len reports how many pod profilers are active.
func (m *MultiHandler) Len() int { return len(m.handlers) }

// Run consumes eventChan, dispatching latency-spike checks to every sub-handler
// (each self-rate-limits to one auto-trigger) and servicing on-demand trigger
// requests against all pods. Every pod's workers draw from one shared
// semaphore, so fetches in flight across the node stay within
// config.ProfilingMaxConcurrent.
func (m *MultiHandler) Run(ctx context.Context, eventChan <-chan *events.Event) {
	for _, h := range m.handlers {
		discoverCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		h.profiler.Discover(discoverCtx)
		cancel()
	}
	for _, h := range m.handlers {
		h.startWorkers(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-eventChan:
			if !ok {
				return
			}
			for _, h := range m.handlers {
				h.checkSpike(ctx, e)
			}
		}
	}
}

// GenerateSection concatenates each pod's profiling section.
func (m *MultiHandler) GenerateSection(allEvents []*events.Event, duration time.Duration) string {
	var sb strings.Builder
	for _, h := range m.handlers {
		sb.WriteString(h.GenerateSection(allEvents, duration))
	}
	return sb.String()
}

// --- ProfilingController (management HTTP API), aggregated across pods ---

// HTTPStart triggers the requested profile type on every pod.
func (m *MultiHandler) HTTPStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ptype, dur := parseStartRequest(r)
	outcomes := make([]triggerOutcome, 0, len(m.handlers))
	for _, h := range m.handlers {
		outcomes = append(outcomes, h.enqueue(ptype, dur))
	}
	writeStartResponse(w, ptype, dur, outcomes, map[string]interface{}{"pods": len(m.handlers)})
}

// HTTPStatus returns a per-pod status array.
func (m *MultiHandler) HTTPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	statuses := make([]map[string]interface{}, 0, len(m.handlers))
	for _, h := range m.handlers {
		statuses = append(statuses, h.statusMap())
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"pods":     len(m.handlers),
		"statuses": statuses,
	})
}

// HTTPResult returns a per-pod result array (pods without a result are omitted).
func (m *MultiHandler) HTTPResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	results := make([]map[string]interface{}, 0, len(m.handlers))
	for _, h := range m.handlers {
		if body := h.resultMap(); body != nil {
			results = append(results, body)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if len(results) == 0 {
		w.WriteHeader(http.StatusNoContent)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "no_result"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"pods":    len(m.handlers),
		"results": results,
	})
}
