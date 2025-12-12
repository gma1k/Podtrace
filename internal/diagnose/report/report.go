package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
	"github.com/podtrace/podtrace/internal/diagnose/detector"
	"github.com/podtrace/podtrace/internal/diagnose/formatter"
	"github.com/podtrace/podtrace/internal/diagnose/profiling"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
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

func GenerateDNSSection(d Diagnostician, duration time.Duration) string {
	dnsEvents := d.FilterEvents(events.EventDNS)
	if len(dnsEvents) == 0 {
		return ""
	}

	avgLatency, maxLatency, errors, p50, p95, p99, topTargets := analyzer.AnalyzeDNS(dnsEvents)
	var report string
	report += formatter.SectionHeader("DNS")
	dnsRate := d.CalculateRate(len(dnsEvents), duration)
	report += formatter.TotalWithRate("lookups", len(dnsEvents), dnsRate)
	report += formatter.LatencyMetrics(avgLatency, maxLatency)
	report += formatter.Percentiles(p50, p95, p99)
	report += formatter.ErrorRate(errors, len(dnsEvents))
	report += formatter.TopTargets(topTargets, config.TopTargetsLimit, "targets", "lookups")
	report += "\n"
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

	avgLatency, maxLatency, errors, p50, p95, p99, topTargets, errorBreakdown := analyzer.AnalyzeConnections(connectEvents)
	var report string
	report += formatter.SectionHeader("Connection")
	connRate := d.CalculateRate(len(connectEvents), duration)
	report += formatter.TotalWithRate("connections", len(connectEvents), connRate)
	report += formatter.LatencyMetrics(avgLatency, maxLatency)
	report += formatter.Percentiles(p50, p95, p99)
	report += fmt.Sprintf("  Failed connections: %d (%.1f%%)\n", errors, float64(errors)*float64(config.Percent100)/float64(len(connectEvents)))
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
	if len(writeEvents) == 0 && len(readEvents) == 0 && len(fsyncEvents) == 0 {
		return ""
	}

	var report string
	report += formatter.SectionHeader("File System")
	writeRate := d.CalculateRate(len(writeEvents), duration)
	readRate := d.CalculateRate(len(readEvents), duration)
	fsyncRate := d.CalculateRate(len(fsyncEvents), duration)
	report += fmt.Sprintf("  Write operations: %d (%.1f/sec)\n", len(writeEvents), writeRate)
	report += fmt.Sprintf("  Read operations: %d (%.1f/sec)\n", len(readEvents), readRate)
	report += fmt.Sprintf("  Fsync operations: %d (%.1f/sec)\n", len(fsyncEvents), fsyncRate)

	allFS := append(append(writeEvents, readEvents...), fsyncEvents...)
	if len(allFS) > 0 {
		avgLatency, maxLatency, slowOps, p50, p95, p99, totalBytes, avgBytes := analyzer.AnalyzeFS(allFS, d.FSSlowThreshold())
		report += formatter.LatencyMetrics(avgLatency, maxLatency)
		report += formatter.Percentiles(p50, p95, p99)
		report += fmt.Sprintf("  Slow operations (>%.1fms): %d\n", d.FSSlowThreshold(), slowOps)
		if totalBytes > 0 {
			report += formatter.BytesSection(totalBytes, avgBytes, calculateThroughput(totalBytes, duration))
		}

		fileMap := buildFileMap(allFS)
		if len(fileMap) > 0 {
			report += formatter.TopItems(fileMap, config.TopFilesLimit, "accessed files", "operations")
		}
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
		if e.Bytes > 0 && e.Bytes < config.MaxBytesForBandwidth {
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

	allHTTP := append(httpReqEvents, httpRespEvents...)
	if len(allHTTP) > 0 {
		latencies, totalLatency, totalBytes := analyzeHTTPEvents(allHTTP)
		avgLatency := totalLatency / float64(len(allHTTP))
		avgBytes := totalBytes / uint64(len(allHTTP))
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
		if len(httpReqEvents) > 0 {
			urlMap := buildURLMap(httpReqEvents)
			if len(urlMap) > 0 {
				report += formatter.TopItems(urlMap, config.TopURLsLimit, "requested URLs", "requests")
			}
		}
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
		if e.Bytes > 0 && e.Bytes < config.MaxBytesForBandwidth {
			totalBytes += e.Bytes
		}
	}
	return latencies, totalLatency, totalBytes
}

func buildURLMap(httpReqEvents []*events.Event) map[string]int {
	urlMap := make(map[string]int)
	for _, e := range httpReqEvents {
		if e.Target != "" {
			urlMap[e.Target]++
		}
	}
	return urlMap
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
		result += fmt.Sprintf("  Total memory killed: %s\n", analyzer.FormatBytes(totalMem))
		result += fmt.Sprintf("  Average memory per kill: %s\n", analyzer.FormatBytes(totalMem/uint64(len(oomKillEvents))))
		result += "  Killed processes:\n"
		for i, e := range oomKillEvents {
			if i >= config.MaxOOMKillsDisplay {
				break
			}
			procName := e.Target
			if procName == "" {
				procName = fmt.Sprintf("PID %d", e.PID)
			}
			result += fmt.Sprintf("    - %s (%s)\n", procName, analyzer.FormatBytes(e.Bytes))
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
			var severity alerting.AlertSeverity
			if contains(issue, "CRITICAL") || contains(issue, "EMERGENCY") {
				severity = alerting.SeverityCritical
			} else if contains(issue, "WARNING") {
				severity = alerting.SeverityWarning
			} else {
				severity = alerting.SeverityWarning
			}
			alert := &alerting.Alert{
				Severity:  severity,
				Title:      "Diagnostic Issue Detected",
				Message:    issue,
				Timestamp:  time.Now(),
				Source:     "error_detector",
				PodName:    "",
				Namespace:  "",
				Context:    make(map[string]interface{}),
				Recommendations: []string{
					"Review diagnostic report for details",
					"Check application logs",
					"Verify resource limits",
				},
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

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func GeneratePoolSection(d Diagnostician, duration time.Duration) string {
	acquireEvents := d.FilterEvents(events.EventPoolAcquire)
	releaseEvents := d.FilterEvents(events.EventPoolRelease)
	exhaustedEvents := d.FilterEvents(events.EventPoolExhausted)

	if len(acquireEvents) == 0 && len(releaseEvents) == 0 {
		return ""
	}

	var report string
	report += formatter.SectionHeader("Connection Pool")

	stats := analyzer.AnalyzePool(acquireEvents, releaseEvents, exhaustedEvents)
	acquireRate := d.CalculateRate(stats.TotalAcquires, duration)
	releaseRate := d.CalculateRate(stats.TotalReleases, duration)
	report += fmt.Sprintf("  Total acquires: %d (%.1f/sec)\n", stats.TotalAcquires, acquireRate)
	report += fmt.Sprintf("  Total releases: %d (%.1f/sec)\n", stats.TotalReleases, releaseRate)
	report += fmt.Sprintf("  Reuse rate: %.2f%%\n", stats.ReuseRate*100)
	report += fmt.Sprintf("  Peak connections: %d\n", stats.PeakConnections)
	report += fmt.Sprintf("  Average connections: %.1f\n", stats.AvgConnections)

	healthStatus := determinePoolHealth(stats)
	report += fmt.Sprintf("  Status: %s\n", healthStatus)

	if stats.ExhaustedCount > 0 {
		exhaustedRate := d.CalculateRate(stats.ExhaustedCount, duration)
		report += fmt.Sprintf("  Pool exhaustion events: %d (%.1f/sec)\n", stats.ExhaustedCount, exhaustedRate)
		report += fmt.Sprintf("  Average wait time: %.2fms\n", float64(stats.AvgWaitTime.Nanoseconds())/float64(config.NSPerMS))
		report += fmt.Sprintf("  Max wait time: %.2fms\n", float64(stats.MaxWaitTime.Nanoseconds())/float64(config.NSPerMS))
		if stats.P50WaitTime > 0 || stats.P95WaitTime > 0 || stats.P99WaitTime > 0 {
			report += formatter.Percentiles(stats.P50WaitTime, stats.P95WaitTime, stats.P99WaitTime)
		}
	}

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
			report += fmt.Sprintf("    - %s:\n", summary.PoolID)
			report += fmt.Sprintf("        Acquires: %d, Releases: %d\n", summary.AcquireCount, summary.ReleaseCount)
			report += fmt.Sprintf("        Reuse rate: %.2f%%\n", summary.ReuseRate*100)
			report += fmt.Sprintf("        Current connections: %d (peak: %d)\n", summary.CurrentConns, summary.MaxConns)

			poolHealthStatus := determinePoolHealthFromSummary(summary)
			report += fmt.Sprintf("        Status: %s\n", poolHealthStatus)

			if summary.ExhaustedCount > 0 {
				report += fmt.Sprintf("        Exhaustion events: %d\n", summary.ExhaustedCount)
				report += fmt.Sprintf("        Avg wait time: %.2fms\n", float64(summary.AvgWaitTime.Nanoseconds())/float64(config.NSPerMS))
				report += fmt.Sprintf("        Max wait time: %.2fms\n", float64(summary.MaxWaitTime.Nanoseconds())/float64(config.NSPerMS))
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
		exhaustionRate := float64(stats.ExhaustedCount) / float64(stats.TotalAcquires)
		if exhaustionRate > 0.1 {
			return "CRITICAL - High pool exhaustion rate (>10%)"
		} else if exhaustionRate > 0.05 {
			return "WARNING - Moderate pool exhaustion rate (>5%)"
		}
	}

	if stats.ReuseRate < 0.5 {
		return "WARNING - Low connection reuse rate (<50%)"
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

	if summary.ReuseRate < 0.5 {
		return "WARNING - Low connection reuse rate (<50%)"
	}

	if summary.MaxWaitTime > 1000*time.Millisecond {
		return "WARNING - High wait times detected"
	}

	return "OK - Pool operating normally"
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
		utilization := uint32(e.Error)
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

	return report
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
		name := pidInfo.Name
		if name == "" {
			name = "unknown"
		}
		result += fmt.Sprintf("    - PID %d (%s): %d events (%.1f%%)\n",
			pidInfo.Pid, name, pidInfo.Count, pidInfo.Percentage)
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

func formatFileDescriptorLeak(openEvents, closeEvents []*events.Event) string {
	diff := len(openEvents) - len(closeEvents)
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
		name := e.Target
		if name != "" && name != "?" && name != "unknown" {
			fileCounts[name]++
		}
	}
	return fileCounts
}
