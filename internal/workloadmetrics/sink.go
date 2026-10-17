package workloadmetrics

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

// Options configures a Sink.
type Options struct {
	SeriesBudget int

	NativeHistograms bool

	IncludePodLabel bool

	IncludeProcessLabel bool

	Lookup func(cgroupID uint64) (events.K8sMetadata, bool)

	TraceContext func(*events.Event) bool

	ResolvePeer func(peerIP string, peerPort uint16) (PeerIdentity, bool)

	OnBudgetExhausted func(budget int)

	Now func() time.Time

	SemanticConventions bool

	AttributeCardinality int

	KernelAggregation bool

	DNSPacketCapture bool

	ExcludeNamespaces []string
}

// schedPreempted is the value bpf/cpu.c puts in TCPState when the task left
// the CPU while still runnable.
const schedPreempted = 1

// seriesEntry records enough about an admitted series to delete it later.
type seriesEntry struct {
	family    string
	namespace string
	labels    []string
	lastSeen  time.Time
}

// Sink aggregates events into the continuous surface.
type Sink struct {
	c          *collectors
	sc         *semconvCollectors
	edges      *edgeCollectors
	kernelHist *kernelHistograms
	lookup     func(uint64) (events.K8sMetadata, bool)

	resolvePeer func(string, uint16) (PeerIdentity, bool)

	own *prometheus.Registry

	includePod     bool
	includeProcess bool

	dnsPacketCapture bool

	excludedNamespaces map[string]struct{}

	traceContext func(*events.Event) bool

	mu        sync.Mutex
	seen      map[string]*seriesEntry
	perNS     map[string]int
	peaks     map[string]utilizationPeak
	budget    int
	exhausted bool

	now func() time.Time

	onExhausted func(budget int)
}

// New builds a Sink and registers its collectors with reg.
func New(reg prometheus.Registerer, opts Options) (*Sink, error) {
	c := newCollectors(opts)
	if err := c.register(reg); err != nil {
		return nil, err
	}

	var sc *semconvCollectors
	if opts.SemanticConventions {
		limit := opts.AttributeCardinality
		if limit == 0 {
			limit = defaultAttributeCardinality
		}
		sc = newSemconvCollectors(opts.NativeHistograms, limit)
		if err := sc.register(reg); err != nil {
			return nil, fmt.Errorf("register semantic-convention metrics: %w", err)
		}
	}
	var edges *edgeCollectors
	if opts.ResolvePeer != nil {
		limit := opts.AttributeCardinality
		if limit == 0 {
			limit = defaultAttributeCardinality
		}
		edges = newEdgeCollectors(opts.NativeHistograms, limit, opts.KernelAggregation)
		if err := edges.register(reg); err != nil {
			return nil, fmt.Errorf("register service-map metrics: %w", err)
		}
	}

	var kernelHist *kernelHistograms
	if opts.KernelAggregation {
		kernelHist = newKernelHistograms(baseLabelNames(opts), opts.ResolvePeer != nil)
		if err := reg.Register(kernelHist); err != nil {
			return nil, fmt.Errorf("register kernel-aggregated metrics: %w", err)
		}
	}

	own := prometheus.NewRegistry()
	own.MustRegister(c.all()...)
	if kernelHist != nil {
		own.MustRegister(kernelHist)
	}
	if sc != nil {
		own.MustRegister(sc.all()...)
	}
	if edges != nil {
		own.MustRegister(edges.all()...)
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}
	if kernelHist != nil {
		kernelHist.now = clock
	}
	var excluded map[string]struct{}
	for _, ns := range opts.ExcludeNamespaces {
		if ns = strings.TrimSpace(ns); ns != "" {
			if excluded == nil {
				excluded = make(map[string]struct{}, len(opts.ExcludeNamespaces))
			}
			excluded[ns] = struct{}{}
		}
	}
	return &Sink{
		c:              c,
		sc:             sc,
		edges:          edges,
		kernelHist:     kernelHist,
		resolvePeer:    opts.ResolvePeer,
		own:            own,
		lookup:         opts.Lookup,
		traceContext:   opts.TraceContext,
		includePod:     opts.IncludePodLabel,
		includeProcess: opts.IncludeProcessLabel,

		dnsPacketCapture: opts.DNSPacketCapture,

		excludedNamespaces: excluded,

		seen:        make(map[string]*seriesEntry),
		perNS:       make(map[string]int),
		budget:      opts.SeriesBudget,
		onExhausted: opts.OnBudgetExhausted,
		now:         clock,
	}, nil
}

func (s *Sink) Name() string { return "workload-metrics" }

// Gather returns the workload surface in Prometheus exposition form,
// making the Sink a prometheus.Gatherer over its own families only.
func (s *Sink) Gather() ([]*dto.MetricFamily, error) {
	if s == nil || s.own == nil {
		return nil, nil
	}
	return s.own.Gather()
}

// Close releases nothing; the collectors live as long as the registry.
func (s *Sink) Close(context.Context) error { return nil }

// admit reports whether a series may be observed, enforcing the budget.
func (s *Sink) admit(family string, labelValues []string) bool {
	for i, v := range labelValues {
		labelValues[i] = labelValue(v)
	}

	var key strings.Builder
	key.WriteString(family)
	for _, v := range labelValues {
		key.WriteByte(0)
		key.WriteString(v)
	}
	k := key.String()

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.seen[k]; ok {
		existing.lastSeen = s.now()
		return true
	}
	namespace := namespaceOf(family, labelValues)
	if s.budget > 0 && len(s.seen) >= s.budget && !s.fairOverflowLocked(namespace) {
		s.c.seriesDropped.WithLabelValues(family).Inc()
		notify := !s.exhausted
		s.exhausted = true
		if notify && s.onExhausted != nil {
			s.onExhausted(s.budget)
		}
		return false
	}
	s.seen[k] = &seriesEntry{
		family:    family,
		namespace: namespace,
		labels:    append([]string(nil), labelValues...),
		lastSeen:  s.now(),
	}
	s.perNS[namespace]++
	s.c.seriesActive.Set(float64(len(s.seen)))
	return true
}

// fairOverflowLocked reports whether a namespace may add a series once the
// budget is spent.
func (s *Sink) fairOverflowLocked(namespace string) bool {
	if len(s.seen) >= s.budget+s.budget/4 {
		return false
	}
	namespaces := len(s.perNS)
	if _, known := s.perNS[namespace]; !known {
		namespaces++
	}
	return s.perNS[namespace] < s.budget/namespaces
}

// namespaceOf is the namespace a series belongs to. The convention families
// lead with service_name.
func namespaceOf(family string, labelValues []string) string {
	idx := 0
	switch family {
	case semconvHTTPDuration, semconvRPCDuration, semconvDBDuration:
		idx = 1
	}
	if idx >= len(labelValues) {
		return ""
	}
	return labelValues[idx]
}

// Reap deletes series that have not been observed for longer than maxIdle,
// returning how many it removed.
func (s *Sink) Reap(maxIdle time.Duration) int {
	if maxIdle <= 0 {
		return 0
	}

	cutoff := s.now().Add(-maxIdle)

	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for key, entry := range s.seen {
		if entry.lastSeen.After(cutoff) {
			continue
		}
		if s.deleteSeries(entry) {
			removed++
		}
		delete(s.seen, key)
		delete(s.peaks, peakKey(entry.family, entry.labels))
		if s.perNS[entry.namespace] <= 1 {
			delete(s.perNS, entry.namespace)
		} else {
			s.perNS[entry.namespace]--
		}
	}
	if removed > 0 {
		s.c.seriesReaped.Add(float64(removed))
		s.c.seriesActive.Set(float64(len(s.seen)))
		if s.budget <= 0 || len(s.seen) < s.budget {
			s.exhausted = false
		}
	}
	return removed
}

// deleteSeries removes one series from whichever collector owns its family.
//
// Every family that passes through admit must resolve here. One that does not
// is still dropped from s.seen, so the budget counts it as gone while the
// collector goes on exporting it: kernel-aggregated histograms, the service
// map and the semantic-convention histograms all leaked that way, and a
// departed workload's series outlived it for the life of the agent.
func (s *Sink) deleteSeries(entry *seriesEntry) bool {
	if s.kernelHist.owns(entry.family) {
		return s.kernelHist.delete(entry.family, entry.labels)
	}
	if v, ok := s.vecFor(entry.family); ok {
		return v.DeleteLabelValues(entry.labels...)
	}
	return false
}

// labelledVec is what every event-path collector shares: the ability to drop
// one series by its label values.
type labelledVec interface {
	DeleteLabelValues(labelValues ...string) bool
}

// vecFor resolves an event-path family to its collector.
func (s *Sink) vecFor(family string) (labelledVec, bool) {
	if h, ok := s.c.histogramFor(family); ok {
		return h, true
	}
	if v, ok := s.c.counterFor(family); ok {
		return v, true
	}
	if g, ok := s.c.sat.gaugeFor(family); ok {
		return g, true
	}
	if s.edges != nil {
		switch family {
		case edgeRequestsTotal:
			return s.edges.requests, true
		case edgeRequestDuration:
			return s.edges.duration, true
		case edgeBytesTotal:
			return s.edges.bytes, true
		}
	}
	if s.sc != nil {
		switch family {
		case semconvHTTPDuration:
			return s.sc.httpDuration, true
		case semconvRPCDuration:
			return s.sc.rpcDuration, true
		case semconvDBDuration:
			return s.sc.dbDuration, true
		}
	}
	return nil, false
}

func (s *Sink) observe(e *events.Event, h *prometheus.HistogramVec, family string, labelValues []string, seconds float64) {
	s.observeExemplar(e, h, family, labelValues, seconds, nil)
}

// observeExemplar records an observation and, when the event carried a trace
// id, the exemplar that links this bucket back to that trace.
//
// Under kernel aggregation a family is exported by the kernel store alone, so
// an observation of it is folded into that store: not every probe aggregates
// in the kernel. An event the kernel already counted never gets here; record
// returns before any family is touched.
// Skipping by family instead, as this once did, silently dropped every
// sched_switch, lock, filesystem-metadata and most L7 observation whenever
// kernel aggregation was on: cpu.contention could never fire.
func (s *Sink) observeExemplar(e *events.Event, h *prometheus.HistogramVec, family string, labelValues []string, seconds float64, ex prometheus.Labels) {
	if s.kernelHist.owns(family) {
		if !s.admit(family, labelValues) {
			return
		}
		ns := uint64(0)
		if seconds > 0 {
			ns = uint64(seconds * 1e9)
		}
		s.kernelHist.observeBucket(family, labelValues, kernelagg.BucketIndex(ns), 1, seconds)
		return
	}
	if !s.admit(family, labelValues) {
		return
	}
	observeExemplar(h.WithLabelValues(labelValues...), seconds, ex)
}

func (s *Sink) add(c *prometheus.CounterVec, family string, labelValues []string, delta float64) {
	s.addExemplar(c, family, labelValues, delta, nil)
}

// addExemplar increments a counter and, when the event carried a trace id,
// the exemplar that links this increment back to that trace.
func (s *Sink) addExemplar(c *prometheus.CounterVec, family string, labelValues []string, delta float64, ex prometheus.Labels) {
	if !s.admit(family, labelValues) {
		return
	}
	addExemplar(c.WithLabelValues(labelValues...), delta, ex)
}

// Export aggregates a batch. It never returns an error: a metrics plane
// that fails a batch would stall the engine's fan-out for every other
// exporter, and a dropped observation is already visible through
// metrics_events_total and metrics_series_dropped_total.
func (s *Sink) Export(_ context.Context, batch []*events.Event) error {
	for _, e := range batch {
		if e == nil {
			continue
		}
		if s.excludes(e) {
			s.c.eventsTotal.WithLabelValues("excluded").Inc()
			continue
		}
		if s.traceContext != nil {
			s.traceContext(e)
		}
		base, ok := s.baseLabelValues(e)
		if !ok {
			s.c.eventsTotal.WithLabelValues("unattributed").Inc()
			continue
		}
		if s.record(e, base) {
			s.c.eventsTotal.WithLabelValues("aggregated").Inc()
		} else {
			s.c.eventsTotal.WithLabelValues("ignored").Inc()
		}
	}
	return nil
}

// baseLabelValues projects an event's pod metadata onto the base label
// set, resolving it through Lookup when the event arrives unenriched.
func (s *Sink) baseLabelValues(e *events.Event) ([]string, bool) {
	meta, ok := s.metadataFor(e)
	if !ok {
		return nil, false
	}
	if meta.Namespace == "" || meta.WorkloadName == "" {
		return nil, false
	}
	if _, excluded := s.excludedNamespaces[meta.Namespace]; excluded {
		return nil, false
	}

	values := make([]string, 0, len(defaultBaseLabels)+2)
	values = append(values,
		meta.Namespace,
		meta.WorkloadName,
		orUnknown(meta.WorkloadKind),
		orUnknown(meta.ContainerName),
	)
	if s.includePod {
		values = append(values, orUnknown(meta.PodName))
	}
	if s.includeProcess {
		values = append(values, orUnknown(e.ProcessName))
	}
	return values, true
}

// excludes reports whether an event belongs to a namespace the plane was
// told to skip.
func (s *Sink) excludes(e *events.Event) bool {
	if len(s.excludedNamespaces) == 0 {
		return false
	}
	meta, ok := s.metadataFor(e)
	if !ok {
		return false
	}
	_, excluded := s.excludedNamespaces[meta.Namespace]
	return excluded
}

func (s *Sink) metadataFor(e *events.Event) (events.K8sMetadata, bool) {
	if e.K8s != nil && !e.K8s.IsZero() {
		return *e.K8s, true
	}
	if s.lookup == nil {
		return events.K8sMetadata{}, false
	}
	return s.lookup(e.CgroupID)
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func appendLabels(base []string, extra ...string) []string {
	out := make([]string, 0, len(base)+len(extra))
	out = append(out, base...)
	out = append(out, extra...)
	return out
}

// record routes one event to its family. Returns false when no family
// maps to the event type, which is expected: this surface deliberately
// covers golden signals rather than every event podtrace can emit.
func (s *Sink) record(e *events.Event, base []string) bool {
	seconds := e.Latency().Seconds()

	if e.KernelAggregated && s.kernelHist != nil {
		if events.IsL7Response(e.Type) && !e.IsClientL7Response() {
			s.recordSemconv(e, seconds)
		}
		s.linkKernelExemplar(e, base, seconds)
		return true
	}

	if e.Type == events.EventDNS && !e.CountsAsDNSLookup(s.dnsPacketCapture) {
		return true
	}

	ex, _ := exemplarFor(e)

	clientCall := e.IsClientL7Response()
	if e.IsError() && !clientCall {
		s.add(s.c.errors, "errors_total", appendLabels(base, errorKind(e.Type)), 1)
	}

	switch e.Type {
	case events.EventHTTPReq, events.EventFastCGIReq:
		return true

	case events.EventHTTPResp, events.EventGRPCMethod,
		events.EventFastCGIResp, events.EventRedisCmd, events.EventMemcachedCmd,
		events.EventKafkaProduce, events.EventKafkaFetch, events.EventDBQuery:
		if clientCall {
			s.recordEdgeL7(e, outcome(e), seconds)
			return true
		}
		protocol := protocolLabel(e)
		s.addExemplar(s.c.l7Requests, "l7_requests_total",
			appendLabels(base, protocol, statusClass(e), outcome(e)), 1, ex)
		s.observeExemplar(e, s.c.l7Duration, "l7_request_duration_seconds",
			appendLabels(base, protocol), seconds, ex)
		s.recordSemconv(e, seconds)
		if !e.IsServerL7Response() {
			s.recordEdgeL7(e, outcome(e), seconds)
		}
		return true

	case events.EventTCPSend, events.EventTCPRecv, events.EventUDPSend, events.EventUDPRecv:
		direction, transport := networkDimensions(e.Type)
		s.observeExemplar(e, s.c.networkLatency, "network_latency_seconds",
			appendLabels(base, direction, transport), seconds, ex)
		if e.Bytes > 0 {
			s.add(s.c.networkBytes, "network_bytes_total",
				appendLabels(base, direction, transport), float64(e.Bytes))
		}
		s.recordEdgeNetwork(e, direction)
		return true

	case events.EventConnect:
		if events.CountsAsConnectionAttempt(e.Type, e.IsError()) {
			s.add(s.c.networkConnections, "network_connections_total",
				appendLabels(base, "tcp", connectOutcome(e)), 1)
		}
		return true

	case events.EventConnectResult:
		s.add(s.c.networkConnections, "network_connections_total",
			appendLabels(base, "tcp", outcome(e)), 1)
		return true

	case events.EventTCPRetrans:
		s.add(s.c.networkRetransmits, "network_retransmits_total", base, 1)
		return true

	case events.EventNetDevError:
		s.add(s.c.networkDeviceErrors, "network_device_errors_total", base, 1)
		return true

	case events.EventTCPRTT:
		s.observe(e, s.c.networkRTT, "network_rtt_seconds", base, seconds)
		return true

	case events.EventLockContention:
		s.observe(e, s.c.lockContention, "lock_contention_seconds", base, seconds)
		return true

	case events.EventDNS:
		answer := e.DNSAnswer()
		s.add(s.c.dnsLookups, "dns_lookups_total", appendLabels(base, answer), 1)
		if answer != events.DNSAnswerTimeout {
			s.observeExemplar(e, s.c.dnsLatency, "dns_latency_seconds", base, seconds, ex)
		}
		return true

	case events.EventDNSQuery:
		return true

	case events.EventRead, events.EventWrite, events.EventFsync,
		events.EventOpen, events.EventClose, events.EventUnlink, events.EventRename:
		operation := filesystemOperation(e.Type)
		s.observe(e, s.c.filesystemLatency, "filesystem_latency_seconds",
			appendLabels(base, operation), seconds)
		if e.Bytes > 0 && (e.Type == events.EventRead || e.Type == events.EventWrite) {
			s.add(s.c.filesystemBytes, "filesystem_bytes_total",
				appendLabels(base, operation), float64(e.Bytes))
		}
		return true

	case events.EventSchedSwitch:
		s.observe(e, s.c.cpuBlocked, "cpu_blocked_seconds", base, seconds)
		if e.TCPState == schedPreempted {
			s.observe(e, s.c.cpuRunqueue, "cpu_runqueue_latency_seconds", base, seconds)
		}
		return true

	case events.EventTLSHandshake:
		s.observe(e, s.c.tlsHandshakeDuration, "tls_handshake_duration_seconds", base, seconds)
		return true

	case events.EventDBAcquire:
		s.observe(e, s.c.sat.acquireWait, "db_connection_acquire_seconds", base, seconds)
		return true

	case events.EventResourceLimit, events.EventPoolAcquire,
		events.EventPoolRelease, events.EventPoolExhausted,
		events.EventDBPoolStats:
		return s.recordSaturation(e, base)

	default:
		return false
	}
}

// linkKernelExemplar attaches a traced event to the series the kernel already
// counted it in, without counting it again. While a PodTrace exists the
// kernel still aggregates, so every L7, network and DNS event arrives here
// already counted; returning before the exemplar, as this once did, meant
// the metric-to-trace link was missing exactly while someone was tracing.
func (s *Sink) linkKernelExemplar(e *events.Event, base []string, seconds float64) {
	ex, ok := exemplarFor(e)
	if !ok {
		return
	}
	base = s.kernelBase(base)
	switch e.Type {
	case events.EventHTTPResp, events.EventGRPCMethod,
		events.EventFastCGIResp, events.EventRedisCmd, events.EventMemcachedCmd,
		events.EventKafkaProduce, events.EventKafkaFetch, events.EventDBQuery:
		if !e.IsClientL7Response() {
			protocol := protocolLabel(e)
			s.addExemplar(s.c.l7Requests, "l7_requests_total",
				appendLabels(base, protocol, statusClass(e), outcome(e)), 0, ex)
			s.holdKernelExemplar("l7_request_duration_seconds", appendLabels(base, protocol), seconds, ex)
		}
		if !e.IsServerL7Response() {
			if identity, ok := s.edgeIdentity(e); ok {
				s.addExemplar(s.edges.requests, edgeRequestsTotal, appendLabels(identity, outcome(e)), 0, ex)
				s.holdKernelExemplar(edgeRequestDuration, identity, seconds, ex)
			}
		}

	case events.EventTCPSend, events.EventTCPRecv, events.EventUDPSend, events.EventUDPRecv:
		direction, transport := networkDimensions(e.Type)
		s.holdKernelExemplar("network_latency_seconds", appendLabels(base, direction, transport), seconds, ex)

	case events.EventDNS:
		if e.CountsAsDNSLookup(s.dnsPacketCapture) && e.DNSAnswer() != events.DNSAnswerTimeout {
			s.holdKernelExemplar("dns_latency_seconds", base, seconds, ex)
		}
	}
}

// kernelBase is the base label set the kernel counted an event under.
func (s *Sink) kernelBase(base []string) []string {
	if !s.includeProcess || len(base) == 0 {
		return base
	}
	out := append([]string(nil), base...)
	out[len(out)-1] = orUnknown("")
	return out
}

// holdKernelExemplar records the latest exemplar of a kernel-fed histogram.
func (s *Sink) holdKernelExemplar(family string, labelValues []string, seconds float64, ex prometheus.Labels) {
	if !s.kernelHist.owns(family) || !s.admit(family, labelValues) {
		return
	}
	s.kernelHist.holdExemplar(family, labelValues, seconds, ex, s.now())
}

func (s *Sink) recordSemconv(e *events.Event, seconds float64) {
	if s.sc == nil {
		return
	}
	meta, ok := s.metadataFor(e)
	if !ok {
		return
	}
	id := semconvIdentity(meta)

	switch e.Type {
	case events.EventHTTPResp:
		s.observe(e, s.sc.httpDuration, semconvHTTPDuration,
			appendLabels(id, httpRequestMethod(e), statusCodeLabel(e), networkProtocolName(e)), seconds)

	case events.EventGRPCMethod:
		method := s.sc.methodValues.bound(firstLine(e.Target))
		s.observe(e, s.sc.rpcDuration, semconvRPCDuration,
			appendLabels(id, rpcSystem(e.Type), method), seconds)

	case events.EventRedisCmd, events.EventMemcachedCmd, events.EventDBQuery:
		op := s.sc.operationValues.bound(firstLine(e.Details))
		s.observe(e, s.sc.dbDuration, semconvDBDuration,
			appendLabels(id, dbSystem(e.Type), op), seconds)
	}
}
