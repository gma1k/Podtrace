package workloadmetrics

import (
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
)

// Kernel-aggregated metrics.
//
// The probes fold observations into a BPF map instead of shipping one event
// per observation, and the agent drains that map on an interval. Rows arrive
// here and are folded into the same families the event path produces, so a
// dashboard cannot tell which path served it.

// syntheticEvent rebuilds just enough of an event for label derivation.
func syntheticEvent(row *kernelagg.Row) *events.Event {
	variant := kernelagg.DecodeVariant(row.Key.Variant)
	e := &events.Event{
		Type:        events.EventType(row.Key.EventType),
		CgroupID:    row.Key.CgroupID,
		Bytes:       row.Value.Bytes,
		TCPState:    uint32(variant.Transport) | uint32(row.Key.Role)&events.HTTPRoleMask,
		PeerDstIP:   events.PeerIP(peerFamilyV4, row.Key.PeerIP, [16]byte{}),
		PeerDstPort: row.Key.PeerPort,
	}
	if variant.IsError {
		e.Error = 1
	}
	return e
}

const peerFamilyV4 = uint8(2)

// ingestKernelEdge projects one drained row onto the service map.
func (s *Sink) ingestKernelEdge(e *events.Event, row *kernelagg.Row, direction string, l7 bool, seconds float64, count float64) {
	if s.edges == nil {
		return
	}
	identity, ok := s.edgeIdentity(e)
	if !ok {
		return
	}
	if l7 {
		s.add(s.edges.requests, edgeRequestsTotal, appendLabels(identity, outcome(e)), count)
		if row.Key.Bucket != kernelagg.BucketNone && s.admit(edgeRequestDuration, identity) {
			s.kernelHist.observeBucket(edgeRequestDuration, identity, row.Key.Bucket, row.Value.Count, seconds)
		}
		return
	}
	if row.Value.Bytes > 0 {
		s.add(s.edges.bytes, edgeBytesTotal, appendLabels(identity, direction), float64(row.Value.Bytes))
	}
}

// kernelHistogram is one cumulative series assembled from kernel deltas.
type kernelHistogram struct {
	labelValues []string
	count       uint64
	sum         float64
	buckets     map[uint16]int64
	created     time.Time
	exemplar    *prometheus.Exemplar
}

// kernelHistograms collects the histogram families fed from the kernel.
type kernelHistograms struct {
	mu     sync.Mutex
	descs  map[string]*prometheus.Desc
	series map[string]map[string]*kernelHistogram

	now func() time.Time
}

func newKernelHistograms(base []string, withEdges bool) *kernelHistograms {
	k := &kernelHistograms{
		descs:  map[string]*prometheus.Desc{},
		series: map[string]map[string]*kernelHistogram{},
		now:    time.Now,
	}
	add := func(family string, labels []string) {
		k.descs[family] = prometheus.NewDesc(metricPrefix+family, kernelHelp[family], labels, nil)
		k.series[family] = map[string]*kernelHistogram{}
	}
	for family, extra := range kernelHistogramLabels {
		add(family, append(append([]string(nil), base...), extra...))
	}
	if withEdges {
		add(edgeRequestDuration, append([]string(nil), edgeLabels...))
	}
	return k
}

// owns reports whether the kernel feeds this family. The event path checks it
// before observing, because a family fed by both would be counted twice.
func (k *kernelHistograms) owns(family string) bool {
	if k == nil {
		return false
	}
	_, ok := k.series[family]
	return ok
}

// kernelHistogramLabels lists the extra label keys each histogram family
// carries beyond the base set, matching the event path exactly.
var kernelHistogramLabels = map[string][]string{
	"network_latency_seconds":        {"direction", "transport"},
	"dns_latency_seconds":            {},
	"l7_request_duration_seconds":    {"protocol"},
	"filesystem_latency_seconds":     {"operation"},
	"cpu_blocked_seconds":            {},
	"cpu_runqueue_latency_seconds":   {},
	"lock_contention_seconds":        {},
	"network_rtt_seconds":            {},
	"tls_handshake_duration_seconds": {},
	"db_connection_acquire_seconds":  {},
}

var kernelHelp = map[string]string{
	edgeRequestDuration:              "Duration of L7 requests between a workload and the service it called.",
	"network_latency_seconds":        "Latency of network operations.",
	"dns_latency_seconds":            "Latency of DNS resolutions.",
	"l7_request_duration_seconds":    "Duration of decoded application-protocol requests.",
	"filesystem_latency_seconds":     "Latency of filesystem operations.",
	"cpu_blocked_seconds":            "Time a workload spent blocked off-CPU.",
	"cpu_runqueue_latency_seconds":   "Time a workload spent runnable but not running.",
	"lock_contention_seconds":        "Time a workload spent waiting on a futex or pthread mutex.",
	"network_rtt_seconds":            "Smoothed round-trip time as the kernel measures it.",
	"tls_handshake_duration_seconds": "Duration of TLS handshakes.",
	"db_connection_acquire_seconds":  "Time callers spent obtaining a pooled database connection, queueing or reconnecting.",
}

func kernelSeriesKey(family string, labelValues []string) string {
	return family + "\x00" + strings.Join(labelValues, "\x00")
}

// observeBucket folds one drained row into its cumulative series.
func (k *kernelHistograms) observeBucket(family string, labelValues []string, bucket uint16, count uint64, sumSeconds float64) {
	k.mu.Lock()
	defer k.mu.Unlock()

	byLabels, ok := k.series[family]
	if !ok {
		return
	}
	id := kernelSeriesKey(family, labelValues)
	entry := byLabels[id]
	if entry == nil {
		entry = &kernelHistogram{
			labelValues: append([]string(nil), labelValues...),
			buckets:     map[uint16]int64{},
			created:     k.now(),
		}
		byLabels[id] = entry
	}
	entry.count += count
	entry.sum += sumSeconds
	entry.buckets[bucket] += safeconv.Uint64ToInt64(count)
}

// holdExemplar keeps the latest traced observation of one series, so the
// histogram the kernel fills can still link to a trace.
func (k *kernelHistograms) holdExemplar(family string, labelValues []string, seconds float64, labels prometheus.Labels, at time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()

	byLabels, ok := k.series[family]
	if !ok {
		return
	}
	id := kernelSeriesKey(family, labelValues)
	entry := byLabels[id]
	if entry == nil {
		entry = &kernelHistogram{
			labelValues: append([]string(nil), labelValues...),
			buckets:     map[uint16]int64{},
			created:     k.now(),
		}
		byLabels[id] = entry
	}
	entry.exemplar = &prometheus.Exemplar{Value: seconds, Labels: labels, Timestamp: at}
}

// Describe implements prometheus.Collector.
func (k *kernelHistograms) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range k.descs {
		ch <- d
	}
}

// Collect implements prometheus.Collector, emitting one native histogram per
// series.
func (k *kernelHistograms) Collect(ch chan<- prometheus.Metric) {
	k.mu.Lock()
	defer k.mu.Unlock()

	for family := range k.series {
		k.collectFamilyLocked(family, ch)
	}
}

// collectFamilyLocked emits one family's series. Callers hold k.mu.
func (k *kernelHistograms) collectFamilyLocked(family string, ch chan<- prometheus.Metric) {
	desc := k.descs[family]
	if desc == nil {
		return
	}
	for _, entry := range k.series[family] {
		if entry.count == 0 {
			continue
		}
		buckets := make(map[int]int64, len(entry.buckets))
		for idx, n := range entry.buckets {
			buckets[kernelagg.NativeIndex(idx)] += n
		}
		metric, err := prometheus.NewConstNativeHistogram(
			desc, entry.count, entry.sum, buckets, nil, 0,
			kernelagg.Schema, kernelZeroThreshold, entry.created,
			entry.labelValues...,
		)
		if err != nil {
			continue
		}
		if entry.exemplar != nil {
			if withExemplar, err := prometheus.NewMetricWithExemplars(metric, *entry.exemplar); err == nil {
				metric = withExemplar
			}
		}
		ch <- metric
	}
}

// kernelFamilyCollector exposes a single kernel-fed family as a Collector.
type kernelFamilyCollector struct {
	k      *kernelHistograms
	family string
}

func (c kernelFamilyCollector) Describe(ch chan<- *prometheus.Desc) {
	if d := c.k.descs[c.family]; d != nil {
		ch <- d
	}
}

func (c kernelFamilyCollector) Collect(ch chan<- prometheus.Metric) {
	c.k.mu.Lock()
	defer c.k.mu.Unlock()
	c.k.collectFamilyLocked(c.family, ch)
}

const kernelZeroThreshold = 1e-12

// delete drops one series. Idleness is tracked once, by the Sink's admit
// bookkeeping, which is what decides when to call this.
func (k *kernelHistograms) delete(family string, labelValues []string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	byLabels, ok := k.series[family]
	if !ok {
		return false
	}
	id := kernelSeriesKey(family, labelValues)
	if _, ok := byLabels[id]; !ok {
		return false
	}
	delete(byLabels, id)
	return true
}

// IngestKernel folds drained rows into the metric families, returning how
// many were attributed to a resident workload.
func (s *Sink) IngestKernel(rows []kernelagg.Row) int {
	if s == nil || s.kernelHist == nil {
		return 0
	}
	applied := 0
	for i := range rows {
		if s.ingestKernelRow(&rows[i]) {
			applied++
		}
	}
	return applied
}

func (s *Sink) ingestKernelRow(row *kernelagg.Row) bool {
	e := syntheticEvent(row)
	if s.excludes(e) {
		return true
	}
	base, ok := s.baseLabelValues(e)
	if !ok {
		return false
	}

	seconds := float64(row.Value.SumNS) / 1e9
	count := float64(row.Value.Count)

	switch e.Type {
	case events.EventTCPSend, events.EventTCPRecv, events.EventUDPSend, events.EventUDPRecv:
		direction, transport := networkDimensions(e.Type)
		if row.Value.Bytes > 0 {
			s.add(s.c.networkBytes, "network_bytes_total",
				appendLabels(base, direction, transport), float64(row.Value.Bytes))
		}
		s.kernelObserve("network_latency_seconds", appendLabels(base, direction, transport), row, seconds)
		s.ingestKernelEdge(e, row, direction, false, seconds, count)

	case events.EventDNS:
		variant := kernelagg.DecodeVariant(row.Key.Variant)
		source := variant.Transport
		if source == events.DNSSourceEncrypted || (s.dnsPacketCapture && source == events.DNSSourceLibc) {
			return true
		}
		s.add(s.c.dnsLookups, "dns_lookups_total",
			appendLabels(base, events.DNSAnswerOfClass(variant.StatusClass)), count)
		s.kernelObserve("dns_latency_seconds", base, row, seconds)

	case events.EventDNSQuery:

	case events.EventRead, events.EventWrite, events.EventFsync,
		events.EventOpen, events.EventClose, events.EventUnlink, events.EventRename:
		operation := filesystemOperation(e.Type)
		if row.Value.Bytes > 0 && (e.Type == events.EventRead || e.Type == events.EventWrite) {
			s.add(s.c.filesystemBytes, "filesystem_bytes_total",
				appendLabels(base, operation), float64(row.Value.Bytes))
		}
		s.kernelObserve("filesystem_latency_seconds", appendLabels(base, operation), row, seconds)

	case events.EventConnect, events.EventConnectResult:
		variant := kernelagg.DecodeVariant(row.Key.Variant)
		if events.CountsAsConnectionAttempt(e.Type, variant.IsError) {
			result := kernelOutcome(variant)
			if e.Type == events.EventConnect && variant.IsError && variant.Transport == connectVariantUnreachable {
				result = outcomeUnreachable
			}
			s.add(s.c.networkConnections, "network_connections_total",
				appendLabels(base, "tcp", result), count)
		}

	case events.EventTCPRetrans:
		s.add(s.c.networkRetransmits, "network_retransmits_total", base, count)

	case events.EventNetDevError:
		s.add(s.c.networkDeviceErrors, "network_device_errors_total", base, count)

	case events.EventSchedSwitch:
		s.kernelObserve("cpu_blocked_seconds", base, row, seconds)
		if e.TCPState == schedPreempted {
			s.kernelObserve("cpu_runqueue_latency_seconds", base, row, seconds)
		}

	case events.EventTCPRTT:
		s.kernelObserve("network_rtt_seconds", base, row, seconds)

	case events.EventLockContention:
		s.kernelObserve("lock_contention_seconds", base, row, seconds)

	case events.EventTLSHandshake:
		s.kernelObserve("tls_handshake_duration_seconds", base, row, seconds)

	case events.EventDBAcquire:
		s.kernelObserve("db_connection_acquire_seconds", base, row, seconds)

	case events.EventHTTPResp, events.EventGRPCMethod,
		events.EventFastCGIResp, events.EventRedisCmd, events.EventMemcachedCmd,
		events.EventKafkaProduce, events.EventKafkaFetch, events.EventDBQuery:
		if e.IsClientL7Response() {
			s.ingestKernelEdge(e, row, "", true, seconds, count)
			return true
		}
		variant := kernelagg.DecodeVariant(row.Key.Variant)
		protocol := protocolLabel(e)
		s.add(s.c.l7Requests, "l7_requests_total",
			appendLabels(base, protocol, kernelStatusClass(variant), kernelOutcome(variant)), count)
		s.kernelObserve("l7_request_duration_seconds", appendLabels(base, protocol), row, seconds)
		if !e.IsServerL7Response() {
			s.ingestKernelEdge(e, row, "", true, seconds, count)
		}

	default:
		return false
	}

	if kernelagg.DecodeVariant(row.Key.Variant).IsError {
		s.add(s.c.errors, "errors_total", appendLabels(base, errorKind(e.Type)), count)
	}
	return true
}

// kernelObserve admits the series against the budget before recording, so the
// kernel path is bounded by exactly the same cap as the event path.
func (s *Sink) kernelObserve(family string, labels []string, row *kernelagg.Row, seconds float64) {
	if row.Key.Bucket == kernelagg.BucketNone {
		return
	}
	if !s.admit(family, labels) {
		return
	}
	s.kernelHist.observeBucket(family, labels, row.Key.Bucket, row.Value.Count, seconds)
}

func kernelStatusClass(v kernelagg.Variant) string {
	switch v.StatusClass {
	case 1:
		return "1xx"
	case 2:
		return "2xx"
	case 3:
		return "3xx"
	case 4:
		return "4xx"
	case 5:
		return "5xx"
	default:
		return "unknown"
	}
}

// connectVariantUnreachable is the value bpf/agg.h puts in a connect row's
// protocol slot when connect() had no route for the address family.
const connectVariantUnreachable = 1

func kernelOutcome(v kernelagg.Variant) string {
	if v.IsError {
		return "error"
	}
	return "ok"
}
