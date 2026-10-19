package tracker

import (
	"container/list"
	"strconv"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

type TraceTracker struct {
	mu      sync.RWMutex
	traces  map[string]*Trace
	recency *list.List
	evicted uint64
}

type Trace struct {
	TraceID   string
	Spans     []*Span
	StartTime time.Time
	EndTime   time.Time
	Services  map[string]*ServiceInfo
	mu        sync.RWMutex

	exportedSpans map[string]int
	lastUpdate    time.Time
	recency       *list.Element
}

type Span struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Service      string
	Operation    string
	StartTime    time.Time
	Duration     time.Duration
	Events       []*events.Event
	Attributes   map[string]string
	Error        bool

	firstSeen        time.Time
	awaitingResponse bool
	droppedEvents    int
}

const maxEventsPerSpan = 128

const maxOpenSpanHold = time.Minute

type ServiceInfo struct {
	Name      string
	Namespace string
	Pod       string
	Labels    map[string]string
}

func NewTraceTracker() *TraceTracker {
	return &TraceTracker{
		traces:  make(map[string]*Trace),
		recency: list.New(),
	}
}

func (tt *TraceTracker) ProcessEvent(event *events.Event, k8sContext interface{}) {
	if event == nil {
		return
	}

	if event.TraceID == "" {
		return
	}

	tt.mu.Lock()
	trace, exists := tt.traces[event.TraceID]
	if exists {
		tt.touchLocked(trace)
	} else {
		if config.MaxTrackedTraces <= 0 {
			tt.mu.Unlock()
			return
		}
		for len(tt.traces) >= config.MaxTrackedTraces {
			tt.evictOldestLocked()
		}
		trace = &Trace{
			TraceID:       event.TraceID,
			Spans:         make([]*Span, 0),
			StartTime:     event.TimestampTime(),
			EndTime:       event.TimestampTime(),
			Services:      make(map[string]*ServiceInfo),
			exportedSpans: make(map[string]int),
		}
		tt.traces[event.TraceID] = trace
		tt.touchLocked(trace)
	}
	tt.mu.Unlock()

	trace.mu.Lock()
	defer trace.mu.Unlock()

	trace.lastUpdate = time.Now()
	if event.TimestampTime().Before(trace.StartTime) {
		trace.StartTime = event.TimestampTime()
	}
	if event.TimestampTime().After(trace.EndTime) {
		trace.EndTime = event.TimestampTime()
	}

	span := tt.findOrCreateSpan(trace, event)
	if span == nil {
		return
	}

	span.addEvent(event)

	if k8sContext != nil {
		tt.updateServiceInfo(trace, span, k8sContext)
	}
}

// touchLocked marks trace as the most recently updated. Caller holds tt.mu.
func (tt *TraceTracker) touchLocked(trace *Trace) {
	if trace.recency != nil {
		tt.recency.MoveToFront(trace.recency)
		return
	}
	trace.recency = tt.recency.PushFront(trace)
}

// evictOldestLocked drops the trace idle longest. Caller holds tt.mu and
// guarantees the tracker is not empty.
func (tt *TraceTracker) evictOldestLocked() {
	trace := tt.recency.Back().Value.(*Trace)
	tt.removeLocked(trace.TraceID, trace)
	tt.evicted++
}

// removeLocked forgets the trace stored under traceID. Caller holds tt.mu.
func (tt *TraceTracker) removeLocked(traceID string, trace *Trace) {
	delete(tt.traces, traceID)
	if trace.recency != nil && tt.recency != nil {
		tt.recency.Remove(trace.recency)
		trace.recency = nil
	}
}

// EvictedTraceCount reports how many traces were evicted to make room for
// newer ones since the tracker was created.
func (tt *TraceTracker) EvictedTraceCount() uint64 {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	return tt.evicted
}

func (tt *TraceTracker) findOrCreateSpan(trace *Trace, event *events.Event) *Span {
	for _, span := range trace.Spans {
		if span.SpanID == event.SpanID {
			return span
		}
	}

	if len(trace.Spans) >= config.MaxSpansPerTrace {
		return nil
	}

	span := &Span{
		TraceID:      event.TraceID,
		SpanID:       event.SpanID,
		ParentSpanID: event.ParentSpanID,
		StartTime:    event.TimestampTime(),
		Events:       make([]*events.Event, 0),
		Attributes:   make(map[string]string),
		Operation:    event.TypeString(),
		firstSeen:    time.Now(),
	}

	if event.ProcessName != "" {
		span.Service = event.ProcessName
		span.Attributes["process.name"] = event.ProcessName
	}
	if event.PID > 0 {
		span.Attributes["process.pid"] = strconv.FormatUint(uint64(event.PID), 10)
	}
	if event.Target != "" {
		span.Attributes["target"] = event.Target
	}
	if event.Details != "" {
		span.Attributes["details"] = event.Details
	}
	if event.CorrelationID != 0 {
		span.Attributes["podtrace.correlation_id"] = strconv.FormatUint(event.CorrelationID, 10)
	}

	trace.Spans = append(trace.Spans, span)
	return span
}

func (tt *TraceTracker) updateServiceInfo(trace *Trace, span *Span, k8sContext interface{}) {
	ctx, ok := k8sContext.(map[string]interface{})
	if !ok {
		return
	}

	var serviceName, namespace, podName string
	var labels map[string]string

	if svc, ok := ctx["target_service"].(string); ok && svc != "" {
		serviceName = svc
	}
	if ns, ok := ctx["target_namespace"].(string); ok && ns != "" {
		namespace = ns
	}
	if pod, ok := ctx["target_pod"].(string); ok && pod != "" {
		podName = pod
	}
	if lbls, ok := ctx["target_labels"].(map[string]string); ok {
		labels = lbls
	}

	if serviceName == "" && podName == "" {
		return
	}

	key := serviceName
	if key == "" {
		key = podName
	}
	if namespace != "" {
		key = namespace + "/" + key
	}

	if _, exists := trace.Services[key]; !exists {
		trace.Services[key] = &ServiceInfo{
			Name:      serviceName,
			Namespace: namespace,
			Pod:       podName,
			Labels:    labels,
		}
	}

	if serviceName != "" {
		span.Service = serviceName
		span.Attributes["service.name"] = serviceName
	}
	if namespace != "" {
		span.Attributes["service.namespace"] = namespace
	}
	if podName != "" {
		span.Attributes["pod.name"] = podName
	}
}

func (tt *TraceTracker) GetTrace(traceID string) *Trace {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	return tt.traces[traceID]
}

func (tt *TraceTracker) GetAllTraces() []*Trace {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	traces := make([]*Trace, 0, len(tt.traces))
	for _, trace := range tt.traces {
		traces = append(traces, trace)
	}
	return traces
}

// SnapshotForExport returns deep copies of traces carrying only the spans that
// have not been handed to an exporter yet.
func (tt *TraceTracker) SnapshotForExport(settle time.Duration, force bool, exporter string) []*Trace {
	tt.mu.RLock()
	live := make([]*Trace, 0, len(tt.traces))
	for _, trace := range tt.traces {
		live = append(live, trace)
	}
	tt.mu.RUnlock()

	now := time.Now()
	out := make([]*Trace, 0, len(live))
	for _, trace := range live {
		trace.mu.Lock()
		if !force && now.Sub(trace.lastUpdate) < settle {
			trace.mu.Unlock()
			continue
		}
		sent := trace.exportedSpans[exporter]
		ready := len(trace.Spans)
		if !force {
			ready = settledPrefix(trace.Spans, sent, now)
		}
		if sent >= ready {
			trace.mu.Unlock()
			continue
		}
		snapshot := cloneTraceLocked(trace, sent, ready)
		trace.mu.Unlock()
		out = append(out, snapshot)
	}
	return out
}

// CommitExport advances the named exporter's watermark on each trace by the
// number of spans it accepted in the matching snapshot.
func (tt *TraceTracker) CommitExport(exported []*Trace, exporter string) {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	for _, snap := range exported {
		live := tt.traces[snap.TraceID]
		if live == nil {
			continue
		}
		live.mu.Lock()
		if live.exportedSpans == nil {
			live.exportedSpans = make(map[string]int)
		}
		live.exportedSpans[exporter] += len(snap.Spans)
		if live.exportedSpans[exporter] > len(live.Spans) {
			live.exportedSpans[exporter] = len(live.Spans)
		}
		live.mu.Unlock()
	}
}

// SnapshotAll returns deep copies of every trace (all spans) without touching
// export watermarks, for read-only consumers like the request-flow graph.
func (tt *TraceTracker) SnapshotAll() []*Trace {
	tt.mu.RLock()
	live := make([]*Trace, 0, len(tt.traces))
	for _, trace := range tt.traces {
		live = append(live, trace)
	}
	tt.mu.RUnlock()

	out := make([]*Trace, 0, len(live))
	for _, trace := range live {
		trace.mu.RLock()
		out = append(out, cloneTraceLocked(trace, 0, len(trace.Spans)))
		trace.mu.RUnlock()
	}
	return out
}

// settledPrefix returns the end of the run of spans from index from on that
// can be exported now: it stops at the first span still waiting for its
// response, unless that span has waited maxOpenSpanHold.
func settledPrefix(spans []*Span, from int, now time.Time) int {
	for i := from; i < len(spans); i++ {
		s := spans[i]
		if s.awaitingResponse && now.Sub(s.firstSeen) < maxOpenSpanHold {
			return i
		}
	}
	return len(spans)
}

// cloneTraceLocked deep-copies a trace, including only spans in
// [fromSpan, toSpan).
func cloneTraceLocked(trace *Trace, fromSpan, toSpan int) *Trace {
	out := &Trace{
		TraceID:   trace.TraceID,
		StartTime: trace.StartTime,
		EndTime:   trace.EndTime,
		Services:  make(map[string]*ServiceInfo, len(trace.Services)),
		Spans:     make([]*Span, 0, toSpan-fromSpan),
	}
	for k, v := range trace.Services {
		info := *v
		if v.Labels != nil {
			info.Labels = make(map[string]string, len(v.Labels))
			for lk, lv := range v.Labels {
				info.Labels[lk] = lv
			}
		}
		out.Services[k] = &info
	}
	for _, span := range trace.Spans[fromSpan:toSpan] {
		s := &Span{
			TraceID:      span.TraceID,
			SpanID:       span.SpanID,
			ParentSpanID: span.ParentSpanID,
			Service:      span.Service,
			Operation:    span.Operation,
			StartTime:    span.StartTime,
			Duration:     span.Duration,
			Error:        span.Error,
			Events:       make([]*events.Event, len(span.Events)),
			Attributes:   make(map[string]string, len(span.Attributes)),
		}
		copy(s.Events, span.Events)
		for ak, av := range span.Attributes {
			s.Attributes[ak] = av
		}
		out.Spans = append(out.Spans, s)
	}
	return out
}

func (tt *TraceTracker) CleanupOldTraces(maxAge time.Duration) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	now := time.Now()
	for traceID, trace := range tt.traces {
		trace.mu.RLock()
		age := now.Sub(trace.lastUpdate)
		trace.mu.RUnlock()
		if age > maxAge {
			tt.removeLocked(traceID, trace)
		}
	}
}

func (tt *TraceTracker) GetTraceCount() int {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	return len(tt.traces)
}

// addEvent records e on the span: it widens the span to cover e, in constant
// time, and keeps e itself while the span holds fewer than maxEventsPerSpan.
func (s *Span) addEvent(e *events.Event) {
	hi := e.TimestampTime()
	lo := hi.Add(-e.Latency())
	if len(s.Events) == 0 && s.droppedEvents == 0 {
		s.StartTime, s.Duration = lo, hi.Sub(lo)
	} else {
		start, end := s.StartTime, s.StartTime.Add(s.Duration)
		if lo.Before(start) {
			start = lo
		}
		if hi.After(end) {
			end = hi
		}
		s.StartTime, s.Duration = start, end.Sub(start)
	}
	if e.IsError() {
		s.Error = true
	}
	switch {
	case e.Type == events.EventHTTPReq && e.CorrelationID != 0:
		s.awaitingResponse = true
	case e.Type == events.EventHTTPResp:
		s.awaitingResponse = false
	}

	if len(s.Events) < maxEventsPerSpan {
		s.Events = append(s.Events, e)
		return
	}
	s.droppedEvents++
	if s.Attributes == nil {
		s.Attributes = make(map[string]string)
	}
	s.Attributes["podtrace.dropped_events"] = strconv.Itoa(s.droppedEvents)
}

// UpdateDuration recomputes the span's start and duration from its events.
func (s *Span) UpdateDuration() {
	if len(s.Events) == 0 {
		return
	}

	first := s.Events[0]
	start := first.TimestampTime().Add(-first.Latency())
	end := first.TimestampTime()

	for _, event := range s.Events {
		hi := event.TimestampTime()
		lo := hi.Add(-event.Latency())
		if lo.Before(start) {
			start = lo
		}
		if hi.After(end) {
			end = hi
		}
	}

	s.StartTime = start
	s.Duration = end.Sub(start)
}
