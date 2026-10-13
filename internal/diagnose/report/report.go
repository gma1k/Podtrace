package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/analyzer"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/diagnose/formatter"
	"github.com/gma1k/podtrace/internal/diagnose/profiling"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
	"github.com/gma1k/podtrace/internal/sanitize"
)

type Diagnostician interface {
	GetEvents() []*events.Event
	FilterEvents(eventType events.EventType) []*events.Event
	CalculateRate(count int, duration time.Duration) float64
	StartTime() time.Time
	EndTime() time.Time
	RTTSpikeThreshold() float64
	FSSlowThreshold() float64
	ErrorRateThreshold() float64
	FastFilesystemOps() analyzer.FSKernelCounts
}

func GenerateSummarySection(d Diagnostician, duration time.Duration) string {
	events := d.GetEvents()
	eventsPerSec := d.CalculateRate(len(events), duration)
	var report string
	report += fmt.Sprintf("=== Diagnostic Report (collected over %v) ===\n\n", duration)
	report += "Summary:\n"
	report += fmt.Sprintf("  Total events: %d\n", len(events))
	report += fmt.Sprintf("  Events per second: %.1f\n", eventsPerSec)
	report += fmt.Sprintf("  Collection period: %v to %v\n\n", d.StartTime().Format("15:04:05"), d.EndTime().Format("15:04:05"))
	return report
}

func GenerateCgroupScopeSection(d Diagnostician) string {
	evs := d.GetEvents()
	if len(evs) == 0 {
		return ""
	}

	zero := 0
	counts := make(map[uint64]int)
	for _, e := range evs {
		if e == nil {
			continue
		}
		if e.CgroupID == 0 {
			zero++
			continue
		}
		counts[e.CgroupID]++
	}

	var report string
	report += "Cgroup Scope:\n"
	report += fmt.Sprintf("  Events with cgroup_id=0: %d (%.1f%%)\n", zero, float64(zero)*100.0/float64(len(evs)))
	report += fmt.Sprintf("  Distinct non-zero cgroup_ids: %d\n", len(counts))

	// Show top 3 cgroup ids by volume (helps detect "slipping" quickly).
	type kv struct {
		id    uint64
		count int
	}
	var top []kv
	for id, c := range counts {
		top = append(top, kv{id: id, count: c})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].count > top[j].count })
	limit := 3
	if len(top) < limit {
		limit = len(top)
	}
	if limit > 0 {
		report += "  Top cgroup_ids:\n"
		for i := 0; i < limit; i++ {
			report += fmt.Sprintf("    - %d: %d events (%.1f%%)\n", top[i].id, top[i].count, float64(top[i].count)*100.0/float64(len(evs)))
		}
	}
	if len(counts) > 1 {
		report += "  multiple cgroup_ids seen, expected in multi-pod mode\n"
	}
	if zero == len(evs) {
		report += "  Warning: all events have cgroup_id=0; your loaded BPF object may not include cgroup_id support.\n"
	}
	report += "\n"
	return report
}

// GenerateTLSSection reports the session's TLS handshakes: how many, how
// many failed, how long they took, and which processes failed.
func GenerateTLSSection(d Diagnostician, duration time.Duration) string {
	handshakes := d.FilterEvents(events.EventTLSHandshake)
	if len(handshakes) == 0 {
		return ""
	}
	avgLatency, maxLatency, failed, p50, p95, p99, _, _ := analyzer.AnalyzeTLS(handshakes)
	report := formatter.SectionHeader("TLS")
	report += formatter.TotalWithRate("handshakes", len(handshakes), d.CalculateRate(len(handshakes), duration))
	report += formatter.LatencyMetrics(avgLatency, maxLatency)
	report += formatter.Percentiles(p50, p95, p99)
	report += fmt.Sprintf("  Failed handshakes: %d (%.1f%%)\n", failed,
		float64(failed)*float64(config.Percent100)/float64(len(handshakes)))
	report += formatter.TopItems(analyzer.TLSFailingProcesses(handshakes), config.TopTargetsLimit,
		"processes with failed handshakes", "failed")
	report += "\n"
	return report
}

func GenerateDNSSection(d Diagnostician, duration time.Duration) string {
	queries := d.FilterEvents(events.EventDNSQuery)
	all := d.FilterEvents(events.EventDNS)
	responses := analyzer.DNSLookups(all, config.DNSPacketCaptureEnabled())
	encrypted := analyzer.DNSEncryptedResolvers(all)
	if len(queries) == 0 && len(responses) == 0 && len(encrypted) == 0 {
		return ""
	}

	report := formatter.SectionHeader("DNS")
	if len(queries) > 0 || len(responses) > 0 {
		report += dnsLookupLines(d, duration, queries, responses)
	}
	if len(encrypted) > 0 {
		report += "  Encrypted resolver connections (DoT/DoH; their answers cannot be read, so they are not lookups):\n"
		for _, r := range encrypted {
			report += fmt.Sprintf("    - %s: %d\n", r.Target, r.Count)
		}
	}
	report += "\n"
	return report
}

func dnsLookupLines(d Diagnostician, duration time.Duration, queries, responses []*events.Event) string {
	lookupCount := len(queries)
	if lookupCount < len(responses) {
		lookupCount = len(responses)
	}

	avgLatency, maxLatency, errors, p50, p95, p99, topTargets := analyzer.AnalyzeDNS(queries, responses)
	report := formatter.TotalWithRate("lookups", lookupCount, d.CalculateRate(lookupCount, duration))
	if analyzer.DNSAnswered(responses) > 0 {
		report += formatter.LatencyMetrics(avgLatency, maxLatency)
		report += formatter.Percentiles(p50, p95, p99)
	} else {
		report += "  No lookup was answered, so there is no latency to show\n"
	}
	report += formatter.ErrorRate(errors, lookupCount)
	if rcodes := analyzer.DNSRCodeBreakdown(responses); len(rcodes) > 0 {
		report += "  Response code breakdown:\n"
		for _, rc := range rcodes {
			report += fmt.Sprintf("    - %s: %d\n", rc.Target, rc.Count)
		}
	}
	if qtypes := analyzer.DNSQueryTypeBreakdown(responses); len(qtypes) > 0 {
		report += "  Query type breakdown:\n"
		for _, qt := range qtypes {
			report += fmt.Sprintf("    - %s: %d\n", qt.Target, qt.Count)
		}
	}
	report += formatter.TopTargets(topTargets, config.TopTargetsLimit, "targets", "lookups")
	report += formatter.ResolvedAddresses(analyzer.ResolvedAddresses(responses), config.TopTargetsLimit)
	return report
}

func GenerateTCPSection(d Diagnostician, duration time.Duration) string {
	tcpSendEvents := d.FilterEvents(events.EventTCPSend)
	tcpRecvEvents := d.FilterEvents(events.EventTCPRecv)
	if len(tcpSendEvents) == 0 && len(tcpRecvEvents) == 0 {
		return ""
	}

	var report string
	report += formatter.SectionHeader("TCP")
	sendRate := d.CalculateRate(len(tcpSendEvents), duration)
	recvRate := d.CalculateRate(len(tcpRecvEvents), duration)
	report += fmt.Sprintf("  Send operations: %d (%.1f/sec)\n", len(tcpSendEvents), sendRate)
	report += fmt.Sprintf("  Receive operations: %d (%.1f/sec)\n", len(tcpRecvEvents), recvRate)

	allTCP := append(tcpSendEvents, tcpRecvEvents...)
	if len(allTCP) > 0 {
		avgRTT, maxRTT, spikes, p50, p95, p99, errors, totalBytes, avgBytes, peakBytes := analyzer.AnalyzeTCP(allTCP, d.RTTSpikeThreshold())
		report += fmt.Sprintf("  Average RTT: %.2fms\n", avgRTT)
		report += fmt.Sprintf("  Max RTT: %.2fms\n", maxRTT)
		report += formatter.Percentiles(p50, p95, p99)
		report += fmt.Sprintf("  RTT spikes (>%dms): %d\n", config.RTTSpikeThresholdMS, spikes)
		report += formatter.ErrorRate(errors, len(allTCP))
		if totalBytes > 0 {
			report += formatter.BytesSection(totalBytes, avgBytes, calculateThroughput(totalBytes, duration))
			report += fmt.Sprintf("  Peak bytes per operation: %s\n", analyzer.FormatBytes(peakBytes))
		}
	}
	report += "\n"
	return report
}

func calculateThroughput(totalBytes uint64, duration time.Duration) uint64 {
	if duration.Seconds() > 0 {
		return uint64(float64(totalBytes) / duration.Seconds())
	}
	return 0
}

func GenerateConnectionSection(d Diagnostician, duration time.Duration) string {
	connectEvents := d.FilterEvents(events.EventConnect)
	if len(connectEvents) == 0 {
		return ""
	}

	avgLatency, maxLatency, _, p50, p95, p99, topTargets, _ := analyzer.AnalyzeConnections(connectEvents)
	attempts, errors, unreachable, errorBreakdown := analyzer.ConnectionOutcomes(connectEvents, d.FilterEvents(events.EventConnectResult))
	var report string
	report += formatter.SectionHeader("Connection")
	connRate := d.CalculateRate(len(connectEvents), duration)
	report += formatter.TotalWithRate("connections", len(connectEvents), connRate)
	report += formatter.LatencyMetrics(avgLatency, maxLatency)
	report += formatter.Percentiles(p50, p95, p99)
	report += fmt.Sprintf("  Failed connections: %d of %d attempts (%.1f%%)\n", errors, attempts, analyzer.FailurePercent(errors, attempts))
	if unreachable > 0 {
		report += fmt.Sprintf("  No route for address family: %d (IPv6-to-IPv4 fallback; not counted as failures)\n", unreachable)
	}
	if len(errorBreakdown) > 0 {
		report += "  Error breakdown:\n"
		for errCode, count := range errorBreakdown {
			report += fmt.Sprintf("    - Error %d: %d occurrences\n", errCode, count)
		}
	}
	report += formatter.TopTargets(topTargets, config.TopTargetsLimit, "connection targets", "connections")
	report += "\n"
	return report
}

func GenerateFileSystemSection(d Diagnostician, duration time.Duration) string {
	writeEvents := d.FilterEvents(events.EventWrite)
	readEvents := d.FilterEvents(events.EventRead)
	fsyncEvents := d.FilterEvents(events.EventFsync)
	allFS := append(append(writeEvents, readEvents...), fsyncEvents...)
	st := analyzer.AnalyzeFSWithKernelCounts(allFS, d.FastFilesystemOps(), d.FSSlowThreshold())
	if st.Ops() == 0 {
		return ""
	}

	var report string
	report += formatter.SectionHeader("File System")
	report += fmt.Sprintf("  Write operations: %d (%.1f/sec)\n", st.Writes, d.CalculateRate(safeconv.Uint64ToInt(st.Writes), duration))
	report += fmt.Sprintf("  Read operations: %d (%.1f/sec)\n", st.Reads, d.CalculateRate(safeconv.Uint64ToInt(st.Reads), duration))
	report += fmt.Sprintf("  Fsync operations: %d (%.1f/sec)\n", st.Fsyncs, d.CalculateRate(safeconv.Uint64ToInt(st.Fsyncs), duration))
	if st.KernelCounted > 0 {
		report += fmt.Sprintf("  Of these, under 1ms and counted in the kernel: %d\n", st.KernelCounted)
	}
	report += formatter.LatencyMetrics(st.AvgMs, st.MaxMs)
	if st.MaxIsKernelUpperBound {
		report += "  (no operation reached 1ms; the max is the upper bound of the slowest bucket)\n"
	}
	report += formatter.Percentiles(st.P50, st.P95, st.P99)
	report += fmt.Sprintf("  Slow operations (>%.1fms): %d\n", d.FSSlowThreshold(), st.SlowOps)
	if st.TotalBytes > 0 {
		report += formatter.BytesSection(st.TotalBytes, st.AvgBytes, calculateThroughput(st.TotalBytes, duration))
	}

	fileMap := buildFileMap(allFS)
	if len(fileMap) > 0 {
		label := "accessed files"
		if st.KernelCounted > 0 {
			label = "files with operations of 1ms or more"
		}
		report += formatter.TopItems(fileMap, config.TopFilesLimit, label, "operations")
	}
	report += "\n"
	return report
}

func buildFileMap(allFS []*events.Event) map[string]int {
	fileMap := make(map[string]int)
	for _, e := range allFS {
		if e.Target != "" && e.Target != "?" && e.Target != "unknown" && e.Target != "file" {
			fileMap[e.Target]++
		}
	}
	return fileMap
}

func GenerateUDPSection(d Diagnostician, duration time.Duration) string {
	udpSendEvents := d.FilterEvents(events.EventUDPSend)
	udpRecvEvents := d.FilterEvents(events.EventUDPRecv)
	if len(udpSendEvents) == 0 && len(udpRecvEvents) == 0 {
		return ""
	}

	var report string
	report += formatter.SectionHeader("UDP")
	report += fmt.Sprintf("  Send operations: %d (%.1f/sec)\n", len(udpSendEvents), d.CalculateRate(len(udpSendEvents), duration))
	report += fmt.Sprintf("  Receive operations: %d (%.1f/sec)\n", len(udpRecvEvents), d.CalculateRate(len(udpRecvEvents), duration))

	allUDP := append(udpSendEvents, udpRecvEvents...)
	if len(allUDP) > 0 {
		latencies, totalLatency, errors, totalBytes, peakBytes := analyzeUDPEvents(allUDP)
		avgLatency := totalLatency / float64(len(allUDP))
		avgBytes := totalBytes / uint64(len(allUDP))
		sort.Float64s(latencies)
		p50 := analyzer.Percentile(latencies, 50)
		p95 := analyzer.Percentile(latencies, 95)
		p99 := analyzer.Percentile(latencies, 99)
		report += fmt.Sprintf("  Average latency: %.2fms\n", avgLatency)
		report += formatter.Percentiles(p50, p95, p99)
		report += formatter.ErrorRate(errors, len(allUDP))
		if totalBytes > 0 {
			report += formatter.BytesSection(totalBytes, avgBytes, calculateThroughput(totalBytes, duration))
			report += fmt.Sprintf("  Peak bytes per operation: %s\n", analyzer.FormatBytes(peakBytes))
		}
	}
	report += "\n"
	return report
}

func analyzeUDPEvents(allUDP []*events.Event) ([]float64, float64, int, uint64, uint64) {
	var latencies []float64
	var totalLatency float64
	errors := 0
	var totalBytes, peakBytes uint64

	for _, e := range allUDP {
		latencyMs := float64(e.LatencyNS) / float64(config.NSPerMS)
		latencies = append(latencies, latencyMs)
		totalLatency += latencyMs
		if e.Error < 0 {
			errors++
		}
		if e.Bytes > 0 && e.Bytes < safeconv.Int64ToUint64(config.MaxBytesForBandwidth) {
			totalBytes += e.Bytes
			if e.Bytes > peakBytes {
				peakBytes = e.Bytes
			}
		}
	}
	return latencies, totalLatency, errors, totalBytes, peakBytes
}

func GenerateHTTPSection(d Diagnostician, duration time.Duration) string {
	httpReqEvents := d.FilterEvents(events.EventHTTPReq)
	httpRespEvents := d.FilterEvents(events.EventHTTPResp)
	if len(httpReqEvents) == 0 && len(httpRespEvents) == 0 {
		return ""
	}

	var report string
	report += formatter.SectionHeader("HTTP")
	reqRate := d.CalculateRate(len(httpReqEvents), duration)
	respRate := d.CalculateRate(len(httpRespEvents), duration)
	report += fmt.Sprintf("  Requests: %d (%.1f/sec)\n", len(httpReqEvents), reqRate)
	report += fmt.Sprintf("  Responses: %d (%.1f/sec)\n", len(httpRespEvents), respRate)
	if line := httpTransportBreakdown(httpReqEvents, httpRespEvents); line != "" {
		report += "  Transport: " + line + "\n"
	}

	if len(httpRespEvents) > 0 {
		latencies, totalLatency, totalBytes := analyzeHTTPEvents(httpRespEvents)
		avgLatency := totalLatency / float64(len(httpRespEvents))
		avgBytes := totalBytes / uint64(len(httpRespEvents))
		sort.Float64s(latencies)
		p50 := analyzer.Percentile(latencies, 50)
		p95 := analyzer.Percentile(latencies, 95)
		p99 := analyzer.Percentile(latencies, 99)
		report += fmt.Sprintf("  Average latency: %.2fms\n", avgLatency)
		report += formatter.Percentiles(p50, p95, p99)
		if totalBytes > 0 {
			bytesSection := formatter.BytesSection(totalBytes, avgBytes, calculateThroughput(totalBytes, duration))
			bytesSection = strings.Replace(bytesSection, "Average bytes per operation", "Average bytes per response", 1)
			report += bytesSection
		}
	}
	if len(httpReqEvents) > 0 {
		urlMap := buildURLMap(httpReqEvents)
		if len(urlMap) > 0 {
			report += formatter.TopItemsWithRate(urlMap, config.TopURLsLimit, "requested endpoints", "requests", duration)
		}
	}
	if len(httpRespEvents) > 0 {
		endpointMap := buildResponseEndpointMap(httpRespEvents)
		if len(endpointMap) > 0 {
			report += formatter.TopItemsWithRate(endpointMap, config.TopURLsLimit, "response endpoints", "responses", duration)
		}
		statusMap := buildStatusMap(httpRespEvents)
		if len(statusMap) > 0 {
			report += formatter.TopItemsWithRate(statusMap, config.TopURLsLimit, "response status codes", "responses", duration)
		}
	}
	if tp := traceContextCount(httpReqEvents); tp > 0 {
		report += fmt.Sprintf("  Trace context: %d/%d requests carried a W3C traceparent\n",
			tp, len(httpReqEvents))
	}
	peerEvents := make([]*events.Event, 0, len(httpReqEvents)+len(httpRespEvents))
	peerEvents = append(peerEvents, httpReqEvents...)
	peerEvents = append(peerEvents, httpRespEvents...)
	peerMap := buildPeerMap(peerEvents)
	if len(peerMap) > 0 {
		report += formatter.TopItemsWithRate(peerMap, config.TopURLsLimit, "L7 peers", "events", duration)
	}
	report += "\n"
	return report
}

func traceContextCount(httpReqEvents []*events.Event) int {
	n := 0
	for _, e := range httpReqEvents {
		if e.TraceID != "" || strings.HasPrefix(e.Details, "traceparent: ") {
			n++
		}
	}
	return n
}

// buildPeerMap counts L7 events by their fused L4 remote peer (ip:port).
func buildPeerMap(httpEvents []*events.Event) map[string]int {
	m := make(map[string]int)
	for _, e := range httpEvents {
		if e.PeerDstIP == "" {
			continue
		}
		m[fmt.Sprintf("%s:%d", e.PeerDstIP, e.PeerDstPort)]++
	}
	return m
}

// GenerateHTTP3Section reports observed HTTP/3 (QUIC) connections by peer.
func GenerateHTTP3Section(d Diagnostician, duration time.Duration) string {
	h3 := d.FilterEvents(events.EventHTTP3)
	if len(h3) == 0 {
		return ""
	}
	report := "HTTP/3 (QUIC) Connections:\n"
	report += fmt.Sprintf("  Connections: %d (%.1f/sec)\n", len(h3), d.CalculateRate(len(h3), duration))
	peerMap := make(map[string]int, len(h3))
	sniMap := make(map[string]int)
	alpnMap := make(map[string]int)
	for _, e := range h3 {
		if e.Target != "" {
			peerMap[e.Target]++
		}
		if name, ok := strings.CutPrefix(e.Details, "sni: "); ok && name != "" {
			var alpn string
			if i := strings.Index(name, " alpn: "); i >= 0 {
				alpn = name[i+len(" alpn: "):]
				name = name[:i]
			}
			if name != "" {
				sniMap[name]++
			}
			for _, proto := range strings.Split(alpn, ",") {
				if proto != "" {
					alpnMap[proto]++
				}
			}
		}
	}
	if len(peerMap) > 0 {
		report += formatter.TopItemsWithRate(peerMap, config.TopURLsLimit, "h3 peers", "connections", duration)
	}
	if len(sniMap) > 0 {
		report += formatter.TopItemsWithRate(sniMap, config.TopURLsLimit, "h3 server names (SNI)", "connections", duration)
	}
	if len(alpnMap) > 0 {
		report += formatter.TopItemsWithRate(alpnMap, config.TopURLsLimit, "h3 ALPN protocols", "connections", duration)
	}
	report += "\n"
	return report
}

func analyzeHTTPEvents(allHTTP []*events.Event) ([]float64, float64, uint64) {
	var latencies []float64
	var totalLatency float64
	var totalBytes uint64

	for _, e := range allHTTP {
		latencyMs := float64(e.LatencyNS) / float64(config.NSPerMS)
		latencies = append(latencies, latencyMs)
		totalLatency += latencyMs
		if e.Bytes > 0 && e.Bytes < safeconv.Int64ToUint64(config.MaxBytesForBandwidth) {
			totalBytes += e.Bytes
		}
	}
	return latencies, totalLatency, totalBytes
}

func buildURLMap(httpReqEvents []*events.Event) map[string]int {
	urlMap := make(map[string]int)
	for _, e := range httpReqEvents {
		if e.Target != "" {
			urlMap[fmt.Sprintf("%s (%s)", e.Target, e.HTTPScheme())]++
		}
	}
	return urlMap
}

// buildResponseEndpointMap counts HTTP response events by endpoint + status,
// mirroring buildURLMap for the request side.
func buildResponseEndpointMap(httpRespEvents []*events.Event) map[string]int {
	endpointMap := make(map[string]int)
	for _, e := range httpRespEvents {
		if !strings.Contains(e.Target, "/") {
			continue
		}
		label := fmt.Sprintf("%s (%s)", e.Target, e.HTTPScheme())
		if code := responseStatus(e); code != "" {
			label += " -> " + code
		}
		endpointMap[label]++
	}
	return endpointMap
}

// buildStatusMap counts HTTP response events by status code so the report can
// surface the response side.
func buildStatusMap(httpRespEvents []*events.Event) map[string]int {
	statusMap := make(map[string]int)
	for _, e := range httpRespEvents {
		if code := responseStatus(e); code != "" {
			statusMap[code]++
		}
	}
	return statusMap
}

// responseStatus extracts the 3-digit status code from a response event. The
// code is carried on the first line of Details.
func responseStatus(e *events.Event) string {
	if code, ok := e.ResponseStatus(); ok {
		return strconv.Itoa(code)
	}
	return ""
}

// httpTransportBreakdown tallies HTTP events by protocol label (HTTP, HTTPS,
// HTTP/2, HTTP/3) and renders a one-line summary. Returns "" when every event is
// plain cleartext HTTP/1.x, so the line only appears when there is something to
// distinguish (TLS, h2c, or h3 traffic present).
func httpTransportBreakdown(eventGroups ...[]*events.Event) string {
	counts := make(map[string]int)
	total := 0
	for _, group := range eventGroups {
		for _, e := range group {
			counts[e.HTTPProtoLabel()]++
			total++
		}
	}
	if total == 0 || counts["HTTP"] == total {
		return ""
	}
	parts := make([]string, 0, len(counts))
	for _, label := range []string{"HTTP", "HTTPS", "HTTP/2", "HTTP/3"} {
		if n := counts[label]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, label))
		}
	}
	return strings.Join(parts, ", ")
}

func GenerateCPUSection(d Diagnostician, duration time.Duration) string {
	schedEvents := d.FilterEvents(events.EventSchedSwitch)
	if len(schedEvents) == 0 {
		return ""
	}

	avgBlock, maxBlock, p50, p95, p99 := analyzer.AnalyzeCPU(schedEvents)
	var report string
	report += formatter.SectionHeader("CPU")
	schedRate := d.CalculateRate(len(schedEvents), duration)
	report += fmt.Sprintf("  Thread switches: %d (%.1f/sec)\n", len(schedEvents), schedRate)
	report += fmt.Sprintf("  Average block time: %.2fms\n", avgBlock)
	report += fmt.Sprintf("  Max block time: %.2fms\n", maxBlock)
	report += formatter.Percentiles(p50, p95, p99)
	report += "\n"
	return report
}

func GenerateTCPStateSection(d Diagnostician, duration time.Duration) string {
	tcpStateEvents := d.FilterEvents(events.EventTCPState)
	if len(tcpStateEvents) == 0 {
		return ""
	}

	var report string
	report += "TCP Connection State Tracking:\n"
	stateRate := d.CalculateRate(len(tcpStateEvents), duration)
	report += fmt.Sprintf("  State changes: %d (%.1f/sec)\n", len(tcpStateEvents), stateRate)
	stateCounts := buildStateCounts(tcpStateEvents)
	if len(stateCounts) > 0 {
		report += formatStateDistribution(stateCounts)
	}
	report += "\n"
	return report
}

func buildStateCounts(tcpStateEvents []*events.Event) map[string]int {
	stateCounts := make(map[string]int)
	for _, e := range tcpStateEvents {
		stateStr := events.TCPStateString(e.TCPState)
		stateCounts[stateStr]++
	}
	return stateCounts
}

func formatStateDistribution(stateCounts map[string]int) string {
	type stateInfo struct {
		state string
		count int
	}
	var states []stateInfo
	for state, count := range stateCounts {
		states = append(states, stateInfo{state: state, count: count})
	}
	sort.Slice(states, func(i, j int) bool {
		return states[i].count > states[j].count
	})
	var result string
	result += "  State distribution:\n"
	for i, s := range states {
		if i >= config.TopStatesLimit {
			break
		}
		result += fmt.Sprintf("    - %s: %d\n", s.state, s.count)
	}
	return result
}

func GenerateMemorySection(d Diagnostician, duration time.Duration) string {
	pageFaultEvents := d.FilterEvents(events.EventPageFault)
	oomKillEvents := d.FilterEvents(events.EventOOMKill)
	if len(pageFaultEvents) == 0 && len(oomKillEvents) == 0 {
		return ""
	}

	var report string
	report += formatter.SectionHeader("Memory")
	if len(pageFaultEvents) > 0 {
		report += formatPageFaults(pageFaultEvents, duration, d)
	}
	if len(oomKillEvents) > 0 {
		report += formatOOMKills(oomKillEvents)
	}
	report += "\n"
	return report
}

func formatPageFaults(pageFaultEvents []*events.Event, duration time.Duration, d Diagnostician) string {
	var result string
	faultRate := d.CalculateRate(len(pageFaultEvents), duration)
	result += fmt.Sprintf("  Page faults: %d (%.1f/sec)\n", len(pageFaultEvents), faultRate)
	errorCounts := buildErrorCounts(pageFaultEvents)
	if len(errorCounts) > 0 {
		result += "  Page fault error codes:\n"
		for errCode, count := range errorCounts {
			result += fmt.Sprintf("    - Error %d: %d occurrences\n", errCode, count)
		}
	}
	return result
}

func buildErrorCounts(pageFaultEvents []*events.Event) map[int32]int {
	errorCounts := make(map[int32]int)
	for _, e := range pageFaultEvents {
		errorCounts[e.Error]++
	}
	return errorCounts
}

func formatOOMKills(oomKillEvents []*events.Event) string {
	var result string
	result += fmt.Sprintf("  OOM kills: %d\n", len(oomKillEvents))
	var totalMem uint64
	for _, e := range oomKillEvents {
		totalMem += e.Bytes
	}
	if len(oomKillEvents) > 0 {
		if totalMem > 0 {
			result += fmt.Sprintf("  Total memory killed: %s\n", analyzer.FormatBytes(totalMem))
			result += fmt.Sprintf("  Average memory per kill: %s\n", analyzer.FormatBytes(totalMem/uint64(len(oomKillEvents))))
		} else {
			result += "  Memory at kill: not reported by this kernel\n"
		}
		result += "  Killed processes:\n"
		for i, e := range oomKillEvents {
			if i >= config.MaxOOMKillsDisplay {
				break
			}
			procName := e.Target
			if procName == "" {
				procName = fmt.Sprintf("PID %d", e.PID)
			}
			if e.Bytes > 0 {
				result += fmt.Sprintf("    - %s (%s)\n", sanitize.Terminal(procName), analyzer.FormatBytes(e.Bytes))
			} else {
				result += fmt.Sprintf("    - %s\n", sanitize.Terminal(procName))
			}
		}
	}
	return result
}

func GenerateIssuesSection(d Diagnostician) string {
	events := d.GetEvents()
	issues := detector.DetectIssues(events, d.ErrorRateThreshold(), d.RTTSpikeThreshold())
	if len(issues) == 0 {
		return ""
	}

	manager := alerting.GetGlobalManager()
	if manager != nil {
		for _, issue := range issues {
			recommendations := []string{issue.Remediation}
			context := map[string]interface{}{"issue_id": string(issue.ID)}
			for _, ev := range issue.Evidence {
				context[ev.Name] = ev.Value
			}
			alert := &alerting.Alert{
				Severity:        issue.Severity,
				Title:           "Diagnostic Issue: " + string(issue.ID),
				Message:         issue.Message,
				Timestamp:       time.Now(),
				Source:          alerting.AlertSourceIssue,
				PodName:         issue.Subject.Workload,
				Namespace:       issue.Subject.Namespace,
				Context:         context,
				Recommendations: recommendations,
			}
			manager.SendAlert(alert)
		}
	}

	var report string
	report += formatter.SectionHeader("Potential Issues Detected")
	for _, issue := range issues {
		report += fmt.Sprintf("  %s\n", issue)
	}
	report += "\n"
	return report
}

// poolCapacityBlock renders what a Go database/sql pool reported about its own
// occupancy.
func poolCapacityBlock(capacitySamples []*events.Event, precededByABlock bool) string {
	capacity := analyzer.AnalyzePoolCapacity(capacitySamples)
	if capacity.Samples == 0 {
		return ""
	}

	var report string
	if precededByABlock {
		report += "\n"
	}
	report += "Pool capacity (Go database/sql):\n"
	report += fmt.Sprintf("  Samples: %d\n", capacity.Samples)
	if capacity.Limited {
		report += fmt.Sprintf("  Peak connections open: %d of %d (%d%% utilized)\n",
			capacity.PeakOpen, capacity.MaxOpen, capacity.PeakPercent)
	} else {
		report += fmt.Sprintf("  Peak connections open: %d (SetMaxOpenConns unlimited)\n",
			capacity.PeakOpen)
		report += "  Note: with no ceiling there is no utilization to report; a count\n"
		report += "        that only grows is the leak signal here.\n"
	}
	return report
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func GeneratePoolSection(d Diagnostician, duration time.Duration) string {
	acquireEvents := d.FilterEvents(events.EventPoolAcquire)
	releaseEvents := d.FilterEvents(events.EventPoolRelease)
	exhaustedEvents := d.FilterEvents(events.EventPoolExhausted)
	acquireWaits := d.FilterEvents(events.EventDBAcquire)
	capacitySamples := d.FilterEvents(events.EventDBPoolStats)

	if len(acquireEvents) == 0 && len(releaseEvents) == 0 && len(acquireWaits) == 0 &&
		len(capacitySamples) == 0 {
		return ""
	}

	var report string
	report += formatter.SectionHeader("Connection Pool")

	stats := analyzer.AnalyzePool(acquireEvents, releaseEvents, exhaustedEvents)

	if len(acquireEvents) > 0 || len(releaseEvents) > 0 {
		acquireRate := d.CalculateRate(stats.TotalAcquires, duration)
		releaseRate := d.CalculateRate(stats.TotalReleases, duration)
		report += fmt.Sprintf("  Total acquires: %d (%.1f/sec)\n", stats.TotalAcquires, acquireRate)
		report += fmt.Sprintf("  Total releases: %d (%.1f/sec)\n", stats.TotalReleases, releaseRate)
		report += fmt.Sprintf("  Release ratio: %.2f%% (releases/acquires)\n", stats.ReleaseRatio*100)
		report += fmt.Sprintf("  Peak connections: %d\n", stats.PeakConnections)
		report += fmt.Sprintf("  Average connections: %.1f\n", stats.AvgConnections)
		report += fmt.Sprintf("  Status: %s\n", determinePoolHealth(stats))
	}

	if stats.ExhaustedCount > 0 {
		exhaustedRate := d.CalculateRate(stats.ExhaustedCount, duration)
		report += fmt.Sprintf("  Pool exhaustion events: %d (%.1f/sec)\n", stats.ExhaustedCount, exhaustedRate)
		report += fmt.Sprintf("  Average connection age at query: %.2fms\n", float64(stats.AvgWaitTime.Nanoseconds())/float64(config.NSPerMS))
		report += fmt.Sprintf("  Max connection age at query: %.2fms\n", float64(stats.MaxWaitTime.Nanoseconds())/float64(config.NSPerMS))
		if stats.P50WaitTime > 0 || stats.P95WaitTime > 0 || stats.P99WaitTime > 0 {
			report += formatter.Percentiles(stats.P50WaitTime, stats.P95WaitTime, stats.P99WaitTime)
		}
	}

	if waits := analyzer.AnalyzeAcquireWaits(acquireWaits); waits.Count > 0 {
		if len(acquireEvents) > 0 || len(releaseEvents) > 0 {
			report += "\n"
		}
		report += "Connection acquisition (Go database/sql):\n"
		report += fmt.Sprintf("  Blocking acquisitions: %d (%.1f/sec)\n",
			waits.Count, d.CalculateRate(waits.Count, duration))
		report += fmt.Sprintf("  Total time waiting: %.2fms\n",
			float64(waits.Total.Nanoseconds())/float64(config.NSPerMS))
		report += fmt.Sprintf("  Average wait: %.2fms\n",
			float64(waits.Avg.Nanoseconds())/float64(config.NSPerMS))
		report += fmt.Sprintf("  Max wait: %.2fms\n",
			float64(waits.Max.Nanoseconds())/float64(config.NSPerMS))
		report += formatter.Percentiles(waits.P50, waits.P95, waits.P99)
		report += "  Note: covers queueing for a free slot and establishing a new\n"
		report += "        connection; compare with the app's sql.DBStats.WaitCount to\n"
		report += "        tell them apart. Only acquisitions slower than 1ms appear.\n"
		if len(capacitySamples) == 0 {
			report += "        Pool capacity is not shown: reading it needs the binary's\n"
			report += "        DWARF, which -ldflags=-w strips.\n"
		}
	}

	report += poolCapacityBlock(capacitySamples,
		len(acquireEvents) > 0 || len(releaseEvents) > 0 || len(acquireWaits) > 0)

	poolSummaries := tracker.GetPoolSummaryFromEvents(acquireEvents, releaseEvents, exhaustedEvents)
	if len(poolSummaries) > 0 {
		report += "\n"
		report += "Connection Pool Tracking:\n"
		report += fmt.Sprintf("  Active pools: %d\n", len(poolSummaries))
		report += "  Pool statistics:\n"
		for i, summary := range poolSummaries {
			if i >= config.MaxConnectionTargets {
				break
			}
			report += fmt.Sprintf("    - %s:\n", sanitize.Terminal(summary.PoolID))
			report += fmt.Sprintf("        Acquires: %d, Releases: %d\n", summary.AcquireCount, summary.ReleaseCount)
			report += fmt.Sprintf("        Release ratio: %.2f%% (releases/acquires)\n", summary.ReleaseRatio*100)
			report += fmt.Sprintf("        Current connections: %d (peak: %d)\n", summary.CurrentConns, summary.MaxConns)

			poolHealthStatus := determinePoolHealthFromSummary(summary)
			report += fmt.Sprintf("        Status: %s\n", poolHealthStatus)

			if summary.ExhaustedCount > 0 {
				report += fmt.Sprintf("        Exhaustion events: %d\n", summary.ExhaustedCount)
				report += fmt.Sprintf("        Avg connection age at query: %.2fms\n", float64(summary.AvgWaitTime.Nanoseconds())/float64(config.NSPerMS))
				report += fmt.Sprintf("        Max connection age at query: %.2fms\n", float64(summary.MaxWaitTime.Nanoseconds())/float64(config.NSPerMS))
			}
			if !summary.LastAcquire.IsZero() {
				report += fmt.Sprintf("        Last acquire: %s\n", summary.LastAcquire.Format("15:04:05.000"))
			}
		}
	}

	report += "\n"
	return report
}

func determinePoolHealth(stats analyzer.PoolStats) string {
	if stats.ExhaustedCount > 0 {
		if stats.TotalAcquires == 0 {
			return "CRITICAL - Pool exhausted with no successful acquisitions"
		}
		exhaustionRate := float64(stats.ExhaustedCount) / float64(stats.TotalAcquires)
		if exhaustionRate > 0.1 {
			return "CRITICAL - High pool exhaustion rate (>10%)"
		} else if exhaustionRate > 0.05 {
			return "WARNING - Moderate pool exhaustion rate (>5%)"
		}
	}

	if stats.ReleaseRatio < 0.5 {
		return "WARNING - Under half of acquired connections released (<50%, possible leak)"
	}

	if stats.MaxWaitTime > 1000*time.Millisecond {
		return "WARNING - High wait times detected"
	}

	return "OK - Pool operating normally"
}

func determinePoolHealthFromSummary(summary tracker.PoolSummary) string {
	if summary.ExhaustedCount > 0 && summary.AcquireCount > 0 {
		exhaustionRate := float64(summary.ExhaustedCount) / float64(summary.AcquireCount)
		if exhaustionRate > 0.1 {
			return "CRITICAL - High pool exhaustion rate (>10%)"
		} else if exhaustionRate > 0.05 {
			return "WARNING - Moderate pool exhaustion rate (>5%)"
		}
	}

	if summary.ReleaseRatio < 0.5 {
		return "WARNING - Under half of acquired connections released (<50%, possible leak)"
	}

	if summary.MaxWaitTime > 1000*time.Millisecond {
		return "WARNING - High wait times detected"
	}

	return "OK - Pool operating normally"
}

// GenerateSecuritySection warns when an AF_ALG "aead" socket was bound by an
// unprivileged process.
func GenerateSecuritySection(d Diagnostician) string {
	victims := map[string]string{} // pod -> "process, uid N"
	for _, e := range d.FilterEvents(events.EventAFALG) {
		if !e.IsCopyFailSignal() {
			continue
		}
		pod := "(unknown pod)"
		if e.K8s != nil && e.K8s.PodName != "" {
			pod = e.K8s.PodName
		}
		victims[pod] = fmt.Sprintf("%s, uid %d", sanitize.Terminal(e.ProcessName), e.Bytes)
	}
	if len(victims) == 0 {
		return ""
	}

	pods := make([]string, 0, len(victims))
	for p := range victims {
		pods = append(pods, p)
	}
	sort.Strings(pods)

	report := "Security Findings:\n"
	report += "  Possible privilege-escalation attempt: Copy-Fail (CVE-2026-31431)\n"
	report += "  A non-root process could gain root on unpatched nodes.\n"
	for _, p := range pods {
		report += fmt.Sprintf("    - %s (%s)\n", p, victims[p])
	}
	report += "    Fix: patch the node kernel\n"
	return report
}

func GenerateResourceSection(d Diagnostician) string {
	resourceEvents := d.FilterEvents(events.EventResourceLimit)
	if len(resourceEvents) == 0 {
		return ""
	}

	var report string
	report += formatter.SectionHeader("Resource Limits")

	resourceStats := make(map[uint32]struct {
		count       int
		maxUtil     uint32
		avgUtil     float64
		totalUsage  uint64
		totalLimit  uint64
		alertCounts map[string]int
	})

	for _, e := range resourceEvents {
		resourceType := e.TCPState
		utilization := safeconv.Int32ToUint32(e.Error)
		usage := e.Bytes

		stats, ok := resourceStats[resourceType]
		if !ok {
			stats = struct {
				count       int
				maxUtil     uint32
				avgUtil     float64
				totalUsage  uint64
				totalLimit  uint64
				alertCounts map[string]int
			}{
				alertCounts: make(map[string]int),
			}
		}

		stats.count++
		if utilization > stats.maxUtil {
			stats.maxUtil = utilization
		}
		stats.avgUtil = (stats.avgUtil*float64(stats.count-1) + float64(utilization)) / float64(stats.count)
		stats.totalUsage += usage

		if utilization >= 95 {
			stats.alertCounts["EMERGENCY"]++
		} else if utilization >= 90 {
			stats.alertCounts["CRITICAL"]++
		} else if utilization >= 80 {
			stats.alertCounts["WARNING"]++
		}

		resourceStats[resourceType] = stats
	}

	resourceNames := map[uint32]string{
		0: "CPU",
		1: "Memory",
		2: "I/O",
	}

	for resourceType, stats := range resourceStats {
		resourceName := resourceNames[resourceType]
		if resourceName == "" {
			resourceName = fmt.Sprintf("Resource-%d", resourceType)
		}

		report += fmt.Sprintf("  %s:\n", resourceName)
		report += fmt.Sprintf("    Events: %d\n", stats.count)
		report += fmt.Sprintf("    Max utilization: %d%%\n", stats.maxUtil)
		report += fmt.Sprintf("    Average utilization: %.1f%%\n", stats.avgUtil)

		if stats.totalUsage > 0 {
			report += fmt.Sprintf("    Current usage: %s\n", analyzer.FormatBytes(stats.totalUsage))
		}

		if len(stats.alertCounts) > 0 {
			report += "    Alerts:\n"
			for severity, count := range stats.alertCounts {
				report += fmt.Sprintf("      - %s: %d\n", severity, count)
			}
		}

		if stats.maxUtil >= 95 {
			report += "    Status: EMERGENCY - Resource limit nearly exceeded!\n"
		} else if stats.maxUtil >= 90 {
			report += "    Status: CRITICAL - Resource limit approaching!\n"
		} else if stats.maxUtil >= 80 {
			report += "    Status: WARNING - Resource usage high\n"
		} else {
			report += "    Status: OK\n"
		}
		report += "\n"
	}

	return report
}

func GenerateApplicationTracing(d Diagnostician, duration time.Duration) string {
	var report string

	allEvents := d.GetEvents()
	report += formatProcessActivity(allEvents)
	report += formatTimeline(allEvents, d.StartTime(), duration)
	report += formatBursts(allEvents, d.StartTime(), duration)
	report += formatConnectionPatterns(d, duration)
	report += formatIOPatterns(d, duration)
	report += formatFastCGIActivity(d, duration)

	return report
}

func formatFastCGIActivity(d Diagnostician, duration time.Duration) string {
	reqs := d.FilterEvents(events.EventFastCGIReq)
	resps := d.FilterEvents(events.EventFastCGIResp)
	if len(reqs) == 0 && len(resps) == 0 {
		return ""
	}

	trimURI := func(uri string) string {
		for i := 0; i < len(uri); i++ {
			c := uri[i]
			if c <= 0x20 || c >= 0x7F {
				return uri[:i]
			}
		}
		return uri
	}
	trimMethod := func(m string) string {
		for i := 0; i < len(m); i++ {
			c := m[i]
			if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
				return m[:i]
			}
		}
		return m
	}

	var result string
	result += "FastCGI Activity:\n"
	if len(reqs) > 0 {
		reqRate := d.CalculateRate(len(reqs), duration)
		result += fmt.Sprintf("  Requests:  %d (%.1f/sec)\n", len(reqs), reqRate)
	}
	if len(resps) > 0 {
		respRate := d.CalculateRate(len(resps), duration)
		result += fmt.Sprintf("  Responses: %d (%.1f/sec)\n", len(resps), respRate)
	}

	// --- Method breakdown -------------------------------------------------
	methodCounts := map[string]int{}
	for _, e := range reqs {
		if e == nil {
			continue
		}
		m := trimMethod(e.Details)
		if m == "" {
			m = "?"
		}
		methodCounts[m]++
	}
	if len(methodCounts) > 0 {
		type methodKV struct {
			method string
			count  int
		}
		ms := make([]methodKV, 0, len(methodCounts))
		for m, c := range methodCounts {
			ms = append(ms, methodKV{m, c})
		}
		sort.Slice(ms, func(i, j int) bool {
			if ms[i].count != ms[j].count {
				return ms[i].count > ms[j].count
			}
			return ms[i].method < ms[j].method
		})
		result += "  Methods:\n"
		for _, m := range ms {
			result += fmt.Sprintf("    %s: %d\n", m.method, m.count)
		}
	}

	// --- Per-worker (PID) breakdown --------------------------------------
	type workerStat struct {
		pid   uint32
		name  string
		count int
	}
	workerMap := map[uint32]*workerStat{}
	for _, e := range reqs {
		if e == nil {
			continue
		}
		w, ok := workerMap[e.PID]
		if !ok {
			w = &workerStat{pid: e.PID, name: e.ProcessName}
			workerMap[e.PID] = w
		}
		if w.name == "" && e.ProcessName != "" {
			w.name = e.ProcessName
		}
		w.count++
	}
	if len(workerMap) > 0 {
		workers := make([]*workerStat, 0, len(workerMap))
		for _, w := range workerMap {
			workers = append(workers, w)
		}
		sort.Slice(workers, func(i, j int) bool {
			if workers[i].count != workers[j].count {
				return workers[i].count > workers[j].count
			}
			return workers[i].pid < workers[j].pid
		})
		result += "  Workers:\n"
		for i, w := range workers {
			if i >= config.TopProcessesLimit {
				break
			}
			name := w.name
			if name == "" {
				name = "unknown"
			}
			result += fmt.Sprintf("    PID %d (%s): %d req\n", w.pid, sanitize.Terminal(name), w.count)
		}
	}

	// --- Per-URI stats with percentiles + errors -------------------------
	type uriStat struct {
		uri       string
		method    string
		count     int
		latencies []uint64
		appErrors int
	}
	byURI := map[string]*uriStat{}
	for _, e := range reqs {
		if e == nil {
			continue
		}
		uri := trimURI(e.Target)
		if uri == "" {
			uri = "/"
		}
		method := trimMethod(e.Details)
		s, ok := byURI[uri]
		if !ok {
			s = &uriStat{uri: uri, method: method}
			byURI[uri] = s
		}
		s.count++
		if s.method == "" {
			s.method = method
		}
	}
	for _, e := range resps {
		if e == nil {
			continue
		}
		uri := trimURI(e.Target)
		if uri == "" {
			uri = "/"
		}
		s, ok := byURI[uri]
		if !ok {
			s = &uriStat{uri: uri}
			byURI[uri] = s
		}
		s.latencies = append(s.latencies, uint64(e.LatencyNS))
		if e.Error != 0 {
			s.appErrors++
		}
	}

	stats := make([]*uriStat, 0, len(byURI))
	for _, s := range byURI {
		sort.Slice(s.latencies, func(i, j int) bool { return s.latencies[i] < s.latencies[j] })
		stats = append(stats, s)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].count != stats[j].count {
			return stats[i].count > stats[j].count
		}
		return stats[i].uri < stats[j].uri
	})

	result += "  Top URIs:\n"
	for i, s := range stats {
		if i >= config.TopProcessesLimit {
			break
		}
		method := s.method
		if method == "" {
			method = "REQ"
		}
		line := fmt.Sprintf("    - %s %s: %d req", sanitize.Terminal(method), sanitize.Terminal(s.uri), s.count)
		if len(s.latencies) > 0 {
			line += fmt.Sprintf(", p50=%.2fms, p95=%.2fms, p99=%.2fms, max=%.2fms",
				percentileMs(s.latencies, 50), percentileMs(s.latencies, 95),
				percentileMs(s.latencies, 99), percentileMs(s.latencies, 100))
		}
		if s.appErrors > 0 {
			line += fmt.Sprintf(", errors=%d", s.appErrors)
		}
		result += line + "\n"
	}

	// --- Latency histogram (overall responses) ---------------------------
	if len(resps) > 0 {
		var sub1, sub10, sub100, plus int
		for _, e := range resps {
			if e == nil {
				continue
			}
			ms := float64(e.LatencyNS) / 1e6
			switch {
			case ms < 1:
				sub1++
			case ms < 10:
				sub10++
			case ms < 100:
				sub100++
			default:
				plus++
			}
		}
		total := len(resps)
		pct := func(n int) float64 { return 100 * float64(n) / float64(total) }
		result += "  Latency distribution:\n"
		result += fmt.Sprintf("    <1ms:     %d (%5.1f%%)\n", sub1, pct(sub1))
		result += fmt.Sprintf("    1-10ms:   %d (%5.1f%%)\n", sub10, pct(sub10))
		result += fmt.Sprintf("    10-100ms: %d (%5.1f%%)\n", sub100, pct(sub100))
		result += fmt.Sprintf("    >100ms:   %d (%5.1f%%)\n", plus, pct(plus))
	}

	// --- Recent samples (last N events, newest first) --------------------
	type sample struct {
		ts     uint64
		pid    uint32
		method string
		uri    string
		latNS  uint64
		status int32
		isResp bool
	}
	samples := make([]sample, 0, len(reqs)+len(resps))
	for _, e := range reqs {
		if e == nil {
			continue
		}
		samples = append(samples, sample{
			ts:     e.Timestamp,
			pid:    e.PID,
			method: trimMethod(e.Details),
			uri:    trimURI(e.Target),
		})
	}
	for _, e := range resps {
		if e == nil {
			continue
		}
		samples = append(samples, sample{
			ts:     e.Timestamp,
			pid:    e.PID,
			uri:    trimURI(e.Target),
			latNS:  uint64(e.LatencyNS),
			status: e.Error,
			isResp: true,
		})
	}
	if len(samples) > 0 {
		sort.Slice(samples, func(i, j int) bool { return samples[i].ts > samples[j].ts })

		oldest := samples[len(samples)-1].ts

		const sampleLimit = 10
		n := sampleLimit
		if len(samples) < n {
			n = len(samples)
		}
		result += "  Recent events:\n"
		for i := 0; i < n; i++ {
			s := samples[i]
			uri := s.uri
			if uri == "" {
				uri = "/"
			}
			deltaSec := float64(s.ts-oldest) / 1e9
			if s.isResp {
				result += fmt.Sprintf("    +%6.2fs  pid=%-7d  RESP  %-24s  %.2fms  status=%d\n",
					deltaSec, s.pid, uri, float64(s.latNS)/1e6, s.status)
			} else {
				method := s.method
				if method == "" {
					method = "REQ"
				}
				result += fmt.Sprintf("    +%6.2fs  pid=%-7d  %-4s  %s\n",
					deltaSec, s.pid, method, uri)
			}
		}
	}

	result += "\n"
	return result
}

// percentileMs linearly interpolates the p-th percentile of sorted
// nanosecond latencies, in milliseconds.
func percentileMs(sorted []uint64, p int) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n == 1 || p <= 0 {
		return float64(sorted[0]) / 1e6
	}
	if p >= 100 {
		return float64(sorted[n-1]) / 1e6
	}
	rank := (float64(p) / 100) * float64(n-1)
	lo := int(rank)
	frac := rank - float64(lo)
	val := float64(sorted[lo]) + frac*(float64(sorted[lo+1])-float64(sorted[lo]))
	return val / 1e6
}

func formatProcessActivity(allEvents []*events.Event) string {
	pidActivity := tracker.AnalyzeProcessActivity(allEvents)
	if len(pidActivity) == 0 {
		return ""
	}
	var result string
	result += "Process Activity:\n"
	result += fmt.Sprintf("  Active processes: %d\n", len(pidActivity))
	result += "  Top active processes:\n"
	for i, pidInfo := range pidActivity {
		if i >= config.TopProcessesLimit {
			break
		}
		result += fmt.Sprintf("    - PID %d (%s)%s: %d events (%.1f%%)\n",
			pidInfo.Pid, sanitize.Terminal(pidInfo.Name), pidInfo.PodSuffix(), pidInfo.Count, pidInfo.Percentage)
	}
	result += "\n"
	return result
}

func formatTimeline(allEvents []*events.Event, startTime time.Time, duration time.Duration) string {
	timeline := profiling.AnalyzeTimeline(allEvents, startTime, duration)
	if len(timeline) == 0 {
		return ""
	}
	var result string
	result += "Activity Timeline:\n"
	result += "  Activity distribution:\n"
	for _, bucket := range timeline {
		result += fmt.Sprintf("    - %s: %d events (%.1f%%)\n",
			bucket.Period, bucket.Count, bucket.Percentage)
	}
	result += "\n"
	return result
}

func formatBursts(allEvents []*events.Event, startTime time.Time, duration time.Duration) string {
	bursts := profiling.DetectBursts(allEvents, startTime, duration)
	if len(bursts) == 0 {
		return ""
	}
	var result string
	result += "Activity Bursts:\n"
	result += fmt.Sprintf("  Detected %d burst period(s):\n", len(bursts))
	for i, burst := range bursts {
		if i >= config.MaxBurstsDisplay {
			break
		}
		result += fmt.Sprintf("    - %s: %.1f events/sec (%.1fx normal rate)\n",
			burst.Time.Format("15:04:05"), burst.Rate, burst.Multiplier)
	}
	result += "\n"
	return result
}

func formatConnectionPatterns(d Diagnostician, duration time.Duration) string {
	connectEvents := d.FilterEvents(events.EventConnect)
	if len(connectEvents) == 0 {
		return ""
	}
	pattern := profiling.AnalyzeConnectionPattern(connectEvents, d.StartTime(), d.EndTime(), duration)
	var result string
	result += "Connection Patterns:\n"
	result += fmt.Sprintf("  Pattern: %s\n", pattern.Pattern)
	avgRate := d.CalculateRate(len(connectEvents), duration)
	result += fmt.Sprintf("  Average rate: %.1f connections/sec\n", avgRate)
	if pattern.BurstRate > 0 {
		result += fmt.Sprintf("  Peak rate: %.1f connections/sec\n", pattern.BurstRate)
	}
	if pattern.UniqueTargets > 0 {
		result += fmt.Sprintf("  Unique targets: %d\n", pattern.UniqueTargets)
	}
	result += "\n"
	return result
}

func formatIOPatterns(d Diagnostician, duration time.Duration) string {
	tcpEvents := append(d.FilterEvents(events.EventTCPSend), d.FilterEvents(events.EventTCPRecv)...)
	if len(tcpEvents) == 0 {
		return ""
	}
	ioPattern := profiling.AnalyzeIOPattern(tcpEvents, d.StartTime(), duration)
	var result string
	result += "Network I/O Pattern:\n"
	result += fmt.Sprintf("  Send/Receive ratio: %.2f:1\n", ioPattern.SendRecvRatio)
	result += fmt.Sprintf("  Average throughput: %.1f ops/sec\n", ioPattern.AvgThroughput)
	if ioPattern.PeakThroughput > 0 {
		result += fmt.Sprintf("  Peak throughput: %.1f ops/sec\n", ioPattern.PeakThroughput)
	}
	result += "\n"
	return result
}

func GenerateSyscallSection(d Diagnostician, duration time.Duration) string {
	allEvents := d.GetEvents()
	if len(allEvents) == 0 {
		return ""
	}

	execEvents, forkEvents, openEvents, closeEvents := categorizeSyscallEvents(allEvents)
	if len(execEvents) == 0 && len(forkEvents) == 0 && len(openEvents) == 0 && len(closeEvents) == 0 {
		return ""
	}

	var report string
	report += "Process and Syscall Activity:\n"
	report += formatSyscallCounts(execEvents, forkEvents, openEvents, closeEvents, duration, d)
	report += formatFileDescriptorLeak(openEvents, closeEvents)
	report += formatTopOpenedFiles(openEvents)
	report += "\n"
	return report
}

func categorizeSyscallEvents(allEvents []*events.Event) ([]*events.Event, []*events.Event, []*events.Event, []*events.Event) {
	var execEvents, forkEvents, openEvents, closeEvents []*events.Event
	for _, e := range allEvents {
		if e == nil {
			continue
		}
		switch e.Type {
		case events.EventExec:
			execEvents = append(execEvents, e)
		case events.EventFork:
			forkEvents = append(forkEvents, e)
		case events.EventOpen:
			openEvents = append(openEvents, e)
		case events.EventClose:
			closeEvents = append(closeEvents, e)
		}
	}
	return execEvents, forkEvents, openEvents, closeEvents
}

func formatSyscallCounts(execEvents, forkEvents, openEvents, closeEvents []*events.Event, duration time.Duration, d Diagnostician) string {
	var result string
	if len(execEvents) > 0 {
		execRate := d.CalculateRate(len(execEvents), duration)
		result += fmt.Sprintf("  Execve calls: %d (%.1f/sec)\n", len(execEvents), execRate)
	}
	if len(forkEvents) > 0 {
		forkRate := d.CalculateRate(len(forkEvents), duration)
		result += fmt.Sprintf("  Fork events: %d (%.1f/sec)\n", len(forkEvents), forkRate)
	}
	if len(openEvents) > 0 || len(closeEvents) > 0 {
		openRate := d.CalculateRate(len(openEvents), duration)
		closeRate := d.CalculateRate(len(closeEvents), duration)
		result += fmt.Sprintf("  Open calls: %d (%.1f/sec)\n", len(openEvents), openRate)
		result += fmt.Sprintf("  Close calls: %d (%.1f/sec)\n", len(closeEvents), closeRate)
	}
	return result
}

// formatFileDescriptorLeak compares the opens that returned a descriptor
// with the closes.
func formatFileDescriptorLeak(openEvents, closeEvents []*events.Event) string {
	opened := 0
	for _, e := range openEvents {
		if e.Error == 0 {
			opened++
		}
	}
	diff := opened - len(closeEvents)
	if diff > 0 {
		return fmt.Sprintf("  Potential descriptor leak: %d more opens than closes\n", diff)
	}
	return ""
}

func formatTopOpenedFiles(openEvents []*events.Event) string {
	fileCounts := buildFileCounts(openEvents)
	if len(fileCounts) > 0 {
		return formatter.TopItems(fileCounts, config.TopFilesLimit, "opened files", "opens")
	}
	return ""
}

func buildFileCounts(openEvents []*events.Event) map[string]int {
	fileCounts := make(map[string]int)
	for _, e := range openEvents {
		if e.Error != 0 {
			continue
		}
		name := e.Target
		if name != "" && name != "?" && name != "unknown" {
			fileCounts[name]++
		}
	}
	return fileCounts
}
