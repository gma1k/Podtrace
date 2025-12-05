package diagnose

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
	"github.com/podtrace/podtrace/internal/diagnose/detector"
	"github.com/podtrace/podtrace/internal/diagnose/profiling"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/validation"
)

// Diagnostician collects and analyzes events
type Diagnostician struct {
	mu                 sync.RWMutex
	events             []*events.Event
	startTime          time.Time
	endTime            time.Time
	errorRateThreshold float64
	rttSpikeThreshold  float64
	fsSlowThreshold    float64
	maxEvents          int
	eventCount         int
	droppedEvents      int
}

func NewDiagnostician() *Diagnostician {
	return &Diagnostician{
		events:             make([]*events.Event, 0),
		startTime:          time.Now(),
		errorRateThreshold: config.DefaultErrorRateThreshold,
		rttSpikeThreshold:  config.DefaultRTTThreshold,
		fsSlowThreshold:    config.DefaultFSSlowThreshold,
		maxEvents:          config.MaxEvents,
	}
}

func NewDiagnosticianWithThresholds(errorRate, rttSpike, fsSlow float64) *Diagnostician {
	return &Diagnostician{
		events:             make([]*events.Event, 0),
		startTime:          time.Now(),
		errorRateThreshold: errorRate,
		rttSpikeThreshold:  rttSpike,
		fsSlowThreshold:    fsSlow,
		maxEvents:          config.MaxEvents,
	}
}

func (d *Diagnostician) AddEvent(event *events.Event) {
	if event == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.eventCount++
	if len(d.events) >= d.maxEvents {
		if d.eventCount%config.EventSamplingRate == 0 {
			d.events = append(d.events, event)
		} else {
			d.droppedEvents++
		}
		if d.droppedEvents%10000 == 0 {
			logger.Warn("Event limit reached, sampling events",
				zap.Int("max_events", d.maxEvents),
				zap.Int("dropped", d.droppedEvents))
		}
		return
	}

	d.events = append(d.events, event)
}

func (d *Diagnostician) GetEvents() []*events.Event {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]*events.Event, len(d.events))
	copy(result, d.events)
	return result
}

func (d *Diagnostician) Finish() {
	d.endTime = time.Now()
}

func (d *Diagnostician) calculateRate(count int, duration time.Duration) float64 {
	if duration.Seconds() > 0 {
		return float64(count) / duration.Seconds()
	}
	return 0
}

func formatSectionHeader(title string) string {
	return fmt.Sprintf("%s Statistics:\n", title)
}

func formatTotalWithRate(label string, count int, rate float64) string {
	return fmt.Sprintf("  Total %s: %d (%.1f/sec)\n", label, count, rate)
}

func formatLatencyMetrics(avgLatency, maxLatency float64) string {
	return fmt.Sprintf("  Average latency: %.2fms\n  Max latency: %.2fms\n", avgLatency, maxLatency)
}

func formatPercentiles(p50, p95, p99 float64) string {
	return fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
}

func formatErrorRate(errors, total int) string {
	if total == 0 {
		return fmt.Sprintf("  Errors: %d (0.0%%)\n", errors)
	}
	return fmt.Sprintf("  Errors: %d (%.1f%%)\n", errors, float64(errors)*100/float64(total))
}

func formatTopTargets(targets []analyzer.TargetCount, limit int, headerLabel, countLabel string) string {
	if len(targets) == 0 {
		return ""
	}
	var result string
	result += fmt.Sprintf("  Top %s:\n", headerLabel)
	for i, target := range targets {
		if i >= limit {
			break
		}
		result += fmt.Sprintf("    - %s (%d %s)\n", target.Target, target.Count, countLabel)
	}
	return result
}

func (d *Diagnostician) generateSummarySection(duration time.Duration) string {
	events := d.GetEvents()
	eventsPerSec := d.calculateRate(len(events), duration)
	var report string
	report += fmt.Sprintf("=== Diagnostic Report (collected over %v) ===\n\n", duration)
	report += "Summary:\n"
	report += fmt.Sprintf("  Total events: %d\n", len(events))
	report += fmt.Sprintf("  Events per second: %.1f\n", eventsPerSec)
	report += fmt.Sprintf("  Collection period: %v to %v\n\n", d.startTime.Format("15:04:05"), d.endTime.Format("15:04:05"))
	return report
}

func (d *Diagnostician) generateDNSSection(duration time.Duration) string {
	dnsEvents := d.filterEvents(events.EventDNS)
	if len(dnsEvents) == 0 {
		return ""
	}

	avgLatency, maxLatency, errors, p50, p95, p99, topTargets := analyzer.AnalyzeDNS(dnsEvents)
	var report string
	report += formatSectionHeader("DNS")
	dnsRate := d.calculateRate(len(dnsEvents), duration)
	report += formatTotalWithRate("lookups", len(dnsEvents), dnsRate)
	report += formatLatencyMetrics(avgLatency, maxLatency)
	report += formatPercentiles(p50, p95, p99)
	report += formatErrorRate(errors, len(dnsEvents))
	report += formatTopTargets(topTargets, config.TopTargetsLimit, "targets", "lookups")
	report += "\n"
	return report
}

func (d *Diagnostician) generateTCPSection(duration time.Duration) string {
	tcpSendEvents := d.filterEvents(events.EventTCPSend)
	tcpRecvEvents := d.filterEvents(events.EventTCPRecv)
	if len(tcpSendEvents) == 0 && len(tcpRecvEvents) == 0 {
		return ""
	}

	var report string
	report += formatSectionHeader("TCP")
	sendRate := d.calculateRate(len(tcpSendEvents), duration)
	recvRate := d.calculateRate(len(tcpRecvEvents), duration)
	report += fmt.Sprintf("  Send operations: %d (%.1f/sec)\n", len(tcpSendEvents), sendRate)
	report += fmt.Sprintf("  Receive operations: %d (%.1f/sec)\n", len(tcpRecvEvents), recvRate)

	allTCP := append(tcpSendEvents, tcpRecvEvents...)
	if len(allTCP) > 0 {
		avgRTT, maxRTT, spikes, p50, p95, p99, errors, totalBytes, avgBytes, peakBytes := analyzer.AnalyzeTCP(allTCP, d.rttSpikeThreshold)
		report += fmt.Sprintf("  Average RTT: %.2fms\n", avgRTT)
		report += fmt.Sprintf("  Max RTT: %.2fms\n", maxRTT)
		report += formatPercentiles(p50, p95, p99)
		report += fmt.Sprintf("  RTT spikes (>100ms): %d\n", spikes)
		report += formatErrorRate(errors, len(allTCP))
		if totalBytes > 0 {
			report += fmt.Sprintf("  Total bytes transferred: %s\n", analyzer.FormatBytes(totalBytes))
			report += fmt.Sprintf("  Average bytes per operation: %s\n", analyzer.FormatBytes(avgBytes))
			report += fmt.Sprintf("  Peak bytes per operation: %s\n", analyzer.FormatBytes(peakBytes))
			var throughput uint64
			if duration.Seconds() > 0 {
				throughput = uint64(float64(totalBytes) / duration.Seconds())
			}
			report += fmt.Sprintf("  Average throughput: %s/sec\n", analyzer.FormatBytes(throughput))
		}
	}
	report += "\n"
	return report
}

func (d *Diagnostician) generateConnectionSection(duration time.Duration) string {
	connectEvents := d.filterEvents(events.EventConnect)
	if len(connectEvents) == 0 {
		return ""
	}

	avgLatency, maxLatency, errors, p50, p95, p99, topTargets, errorBreakdown := analyzer.AnalyzeConnections(connectEvents)
	var report string
	report += formatSectionHeader("Connection")
	connRate := d.calculateRate(len(connectEvents), duration)
	report += formatTotalWithRate("connections", len(connectEvents), connRate)
	report += formatLatencyMetrics(avgLatency, maxLatency)
	report += formatPercentiles(p50, p95, p99)
	report += fmt.Sprintf("  Failed connections: %d (%.1f%%)\n", errors, float64(errors)*100/float64(len(connectEvents)))
	if len(errorBreakdown) > 0 {
		report += "  Error breakdown:\n"
		for errCode, count := range errorBreakdown {
			report += fmt.Sprintf("    - Error %d: %d occurrences\n", errCode, count)
		}
	}
	report += formatTopTargets(topTargets, config.TopTargetsLimit, "connection targets", "connections")
	report += "\n"
	return report
}

func (d *Diagnostician) generateFileSystemSection(duration time.Duration) string {
	writeEvents := d.filterEvents(events.EventWrite)
	readEvents := d.filterEvents(events.EventRead)
	fsyncEvents := d.filterEvents(events.EventFsync)
	if len(writeEvents) == 0 && len(readEvents) == 0 && len(fsyncEvents) == 0 {
		return ""
	}

	var report string
	report += formatSectionHeader("File System")
	writeRate := d.calculateRate(len(writeEvents), duration)
	readRate := d.calculateRate(len(readEvents), duration)
	fsyncRate := d.calculateRate(len(fsyncEvents), duration)
	report += fmt.Sprintf("  Write operations: %d (%.1f/sec)\n", len(writeEvents), writeRate)
	report += fmt.Sprintf("  Read operations: %d (%.1f/sec)\n", len(readEvents), readRate)
	report += fmt.Sprintf("  Fsync operations: %d (%.1f/sec)\n", len(fsyncEvents), fsyncRate)

	allFS := append(append(writeEvents, readEvents...), fsyncEvents...)
	if len(allFS) > 0 {
		avgLatency, maxLatency, slowOps, p50, p95, p99, totalBytes, avgBytes := analyzer.AnalyzeFS(allFS, d.fsSlowThreshold)
		report += formatLatencyMetrics(avgLatency, maxLatency)
		report += formatPercentiles(p50, p95, p99)
		thresholdMs := d.fsSlowThreshold
		report += fmt.Sprintf("  Slow operations (>%.1fms): %d\n", thresholdMs, slowOps)
		if totalBytes > 0 {
			report += fmt.Sprintf("  Total bytes transferred: %s\n", analyzer.FormatBytes(totalBytes))
			report += fmt.Sprintf("  Average bytes per operation: %s\n", analyzer.FormatBytes(avgBytes))
			throughput := uint64(float64(totalBytes) / duration.Seconds())
			report += fmt.Sprintf("  Average throughput: %s/sec\n", analyzer.FormatBytes(throughput))
		}

		fileMap := make(map[string]int)
		for _, e := range allFS {
			if e.Target != "" && e.Target != "?" && e.Target != "unknown" && e.Target != "file" {
				fileMap[e.Target]++
			}
		}
		if len(fileMap) > 0 {
			type fileCount struct {
				file  string
				count int
			}
			var fileCounts []fileCount
			for file, count := range fileMap {
				fileCounts = append(fileCounts, fileCount{file: file, count: count})
			}
			sort.Slice(fileCounts, func(i, j int) bool {
				return fileCounts[i].count > fileCounts[j].count
			})
			report += "  Top accessed files:\n"
			for i, fc := range fileCounts {
				if i >= config.TopFilesLimit {
					break
				}
				report += fmt.Sprintf("    - %s (%d operations)\n", fc.file, fc.count)
			}
		}
	}
	report += "\n"
	return report
}

func (d *Diagnostician) generateUDPSection(duration time.Duration) string {
	udpSendEvents := d.filterEvents(events.EventUDPSend)
	udpRecvEvents := d.filterEvents(events.EventUDPRecv)
	if len(udpSendEvents) == 0 && len(udpRecvEvents) == 0 {
		return ""
	}

	var report string
	report += formatSectionHeader("UDP")
	report += fmt.Sprintf("  Send operations: %d (%.1f/sec)\n", len(udpSendEvents), d.calculateRate(len(udpSendEvents), duration))
	report += fmt.Sprintf("  Receive operations: %d (%.1f/sec)\n", len(udpRecvEvents), d.calculateRate(len(udpRecvEvents), duration))

	allUDP := append(udpSendEvents, udpRecvEvents...)
	if len(allUDP) > 0 {
		var totalBytes, avgBytes, peakBytes uint64
		var totalLatency float64
		var latencies []float64
		errors := 0
		for _, e := range allUDP {
			latencyMs := float64(e.LatencyNS) / 1e6
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
		if len(allUDP) > 0 {
			avgLatency := totalLatency / float64(len(allUDP))
			if len(allUDP) > 0 {
				avgBytes = totalBytes / uint64(len(allUDP))
			}
			sort.Float64s(latencies)
			p50 := analyzer.Percentile(latencies, 50)
			p95 := analyzer.Percentile(latencies, 95)
			p99 := analyzer.Percentile(latencies, 99)
			report += fmt.Sprintf("  Average latency: %.2fms\n", avgLatency)
			report += formatPercentiles(p50, p95, p99)
			report += formatErrorRate(errors, len(allUDP))
			if totalBytes > 0 {
				report += fmt.Sprintf("  Total bytes transferred: %s\n", analyzer.FormatBytes(totalBytes))
				report += fmt.Sprintf("  Average bytes per operation: %s\n", analyzer.FormatBytes(avgBytes))
				report += fmt.Sprintf("  Peak bytes per operation: %s\n", analyzer.FormatBytes(peakBytes))
				var throughput uint64
				if duration.Seconds() > 0 {
					throughput = uint64(float64(totalBytes) / duration.Seconds())
				}
				report += fmt.Sprintf("  Average throughput: %s/sec\n", analyzer.FormatBytes(throughput))
			}
		}
	}
	report += "\n"
	return report
}

func (d *Diagnostician) generateHTTPSection(duration time.Duration) string {
	httpReqEvents := d.filterEvents(events.EventHTTPReq)
	httpRespEvents := d.filterEvents(events.EventHTTPResp)
	if len(httpReqEvents) == 0 && len(httpRespEvents) == 0 {
		return ""
	}

	var report string
	report += formatSectionHeader("HTTP")
	reqRate := d.calculateRate(len(httpReqEvents), duration)
	respRate := d.calculateRate(len(httpRespEvents), duration)
	report += fmt.Sprintf("  Requests: %d (%.1f/sec)\n", len(httpReqEvents), reqRate)
	report += fmt.Sprintf("  Responses: %d (%.1f/sec)\n", len(httpRespEvents), respRate)

	allHTTP := append(httpReqEvents, httpRespEvents...)
	if len(allHTTP) > 0 {
		var totalBytes, avgBytes uint64
		var totalLatency float64
		var latencies []float64
		for _, e := range allHTTP {
			latencyMs := float64(e.LatencyNS) / 1e6
			latencies = append(latencies, latencyMs)
			totalLatency += latencyMs
			if e.Bytes > 0 && e.Bytes < config.MaxBytesForBandwidth {
				totalBytes += e.Bytes
			}
		}
		if len(allHTTP) > 0 {
			avgLatency := totalLatency / float64(len(allHTTP))
			if len(allHTTP) > 0 {
				avgBytes = totalBytes / uint64(len(allHTTP))
			}
			sort.Float64s(latencies)
			p50 := analyzer.Percentile(latencies, 50)
			p95 := analyzer.Percentile(latencies, 95)
			p99 := analyzer.Percentile(latencies, 99)
			report += fmt.Sprintf("  Average latency: %.2fms\n", avgLatency)
			report += formatPercentiles(p50, p95, p99)
			if totalBytes > 0 {
				report += fmt.Sprintf("  Total bytes transferred: %s\n", analyzer.FormatBytes(totalBytes))
				report += fmt.Sprintf("  Average bytes per response: %s\n", analyzer.FormatBytes(avgBytes))
				throughput := uint64(float64(totalBytes) / duration.Seconds())
				report += fmt.Sprintf("  Average throughput: %s/sec\n", analyzer.FormatBytes(throughput))
			}
			if len(httpReqEvents) > 0 {
				urlMap := make(map[string]int)
				for _, e := range httpReqEvents {
					if e.Target != "" {
						urlMap[e.Target]++
					}
				}
				if len(urlMap) > 0 {
					type urlCount struct {
						url   string
						count int
					}
					var urlCounts []urlCount
					for url, count := range urlMap {
						urlCounts = append(urlCounts, urlCount{url: url, count: count})
					}
					sort.Slice(urlCounts, func(i, j int) bool {
						return urlCounts[i].count > urlCounts[j].count
					})
					report += "  Top requested URLs:\n"
					for i, uc := range urlCounts {
						if i >= config.TopURLsLimit {
							break
						}
						report += fmt.Sprintf("    - %s (%d requests)\n", uc.url, uc.count)
					}
				}
			}
		}
	}
	report += "\n"
	return report
}

func (d *Diagnostician) generateCPUSection(duration time.Duration) string {
	schedEvents := d.filterEvents(events.EventSchedSwitch)
	if len(schedEvents) == 0 {
		return ""
	}

	avgBlock, maxBlock, p50, p95, p99 := analyzer.AnalyzeCPU(schedEvents)
	var report string
	report += formatSectionHeader("CPU")
	schedRate := d.calculateRate(len(schedEvents), duration)
	report += fmt.Sprintf("  Thread switches: %d (%.1f/sec)\n", len(schedEvents), schedRate)
	report += fmt.Sprintf("  Average block time: %.2fms\n", avgBlock)
	report += fmt.Sprintf("  Max block time: %.2fms\n", maxBlock)
	report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
	report += "\n"
	return report
}

func (d *Diagnostician) generateTCPStateSection(duration time.Duration) string {
	tcpStateEvents := d.filterEvents(events.EventTCPState)
	if len(tcpStateEvents) == 0 {
		return ""
	}

	var report string
	report += "TCP Connection State Tracking:\n"
	stateRate := d.calculateRate(len(tcpStateEvents), duration)
	report += fmt.Sprintf("  State changes: %d (%.1f/sec)\n", len(tcpStateEvents), stateRate)
	stateCounts := make(map[string]int)
	for _, e := range tcpStateEvents {
		stateStr := events.TCPStateString(e.TCPState)
		stateCounts[stateStr]++
	}
	if len(stateCounts) > 0 {
		report += "  State distribution:\n"
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
		for i, s := range states {
			if i >= config.TopStatesLimit {
				break
			}
			report += fmt.Sprintf("    - %s: %d\n", s.state, s.count)
		}
	}
	report += "\n"
	return report
}

func (d *Diagnostician) generateMemorySection(duration time.Duration) string {
	pageFaultEvents := d.filterEvents(events.EventPageFault)
	oomKillEvents := d.filterEvents(events.EventOOMKill)
	if len(pageFaultEvents) == 0 && len(oomKillEvents) == 0 {
		return ""
	}

	var report string
	report += formatSectionHeader("Memory")
	if len(pageFaultEvents) > 0 {
		faultRate := d.calculateRate(len(pageFaultEvents), duration)
		report += fmt.Sprintf("  Page faults: %d (%.1f/sec)\n", len(pageFaultEvents), faultRate)
		errorCounts := make(map[int32]int)
		for _, e := range pageFaultEvents {
			errorCounts[e.Error]++
		}
		if len(errorCounts) > 0 {
			report += "  Page fault error codes:\n"
			for errCode, count := range errorCounts {
				report += fmt.Sprintf("    - Error %d: %d occurrences\n", errCode, count)
			}
		}
	}
	if len(oomKillEvents) > 0 {
		report += fmt.Sprintf("  OOM kills: %d\n", len(oomKillEvents))
		var totalMem uint64
		for _, e := range oomKillEvents {
			totalMem += e.Bytes
		}
		if len(oomKillEvents) > 0 {
			report += fmt.Sprintf("  Total memory killed: %s\n", analyzer.FormatBytes(totalMem))
			if len(oomKillEvents) > 0 {
				report += fmt.Sprintf("  Average memory per kill: %s\n", analyzer.FormatBytes(totalMem/uint64(len(oomKillEvents))))
			}
			report += "  Killed processes:\n"
			for i, e := range oomKillEvents {
				if i >= config.MaxOOMKillsDisplay {
					break
				}
				procName := e.Target
				if procName == "" {
					procName = fmt.Sprintf("PID %d", e.PID)
				}
				report += fmt.Sprintf("    - %s (%s)\n", procName, analyzer.FormatBytes(e.Bytes))
			}
		}
	}
	report += "\n"
	return report
}

func (d *Diagnostician) generateIssuesSection() string {
	events := d.GetEvents()
	issues := detector.DetectIssues(events, d.errorRateThreshold, d.rttSpikeThreshold)
	if len(issues) == 0 {
		return ""
	}

	var report string
	report += "Potential Issues Detected:\n"
	for _, issue := range issues {
		report += fmt.Sprintf("  %s\n", issue)
	}
	report += "\n"
	return report
}

func (d *Diagnostician) GenerateReport() string {
	return d.GenerateReportWithContext(context.Background())
}

func (d *Diagnostician) GenerateReportWithContext(ctx context.Context) string {
	allEvents := d.GetEvents()
	if len(allEvents) == 0 {
		return "No events collected during the diagnostic period.\n"
	}

	select {
	case <-ctx.Done():
		return fmt.Sprintf("Report generation cancelled: %v\n", ctx.Err())
	default:
	}

	duration := d.endTime.Sub(d.startTime)
	var report string

	report += d.generateSummarySection(duration)
	report += d.generateDNSSection(duration)
	report += d.generateTCPSection(duration)
	report += d.generateConnectionSection(duration)
	report += d.generateFileSystemSection(duration)
	report += d.generateUDPSection(duration)
	report += d.generateHTTPSection(duration)
	report += d.generateCPUSection(duration)
	report += d.generateTCPStateSection(duration)
	report += d.generateMemorySection(duration)
	report += profiling.GenerateCPUUsageReport(allEvents, duration)
	report += d.generateStackTraceSectionWithContext(ctx)
	report += d.generateSyscallSection(duration)
	report += d.generateApplicationTracing(duration)
	report += tracker.GenerateConnectionCorrelation(allEvents)
	report += d.generateIssuesSection()

	return report
}

func (d *Diagnostician) filterEvents(eventType events.EventType) []*events.Event {
	allEvents := d.GetEvents()
	var filtered []*events.Event
	for _, e := range allEvents {
		if e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (d *Diagnostician) generateApplicationTracing(duration time.Duration) string {
	var report string

	allEvents := d.GetEvents()
	pidActivity := tracker.AnalyzeProcessActivity(allEvents)
	if len(pidActivity) > 0 {
		report += "Process Activity:\n"
		report += fmt.Sprintf("  Active processes: %d\n", len(pidActivity))
		report += "  Top active processes:\n"
		for i, pidInfo := range pidActivity {
			if i >= config.TopProcessesLimit {
				break
			}
			name := pidInfo.Name
			if name == "" {
				name = "unknown"
			}
			report += fmt.Sprintf("    - PID %d (%s): %d events (%.1f%%)\n",
				pidInfo.Pid, name, pidInfo.Count, pidInfo.Percentage)
		}
		report += "\n"
	}

	timeline := profiling.AnalyzeTimeline(allEvents, d.startTime, duration)
	if len(timeline) > 0 {
		report += "Activity Timeline:\n"
		report += fmt.Sprintf("  Activity distribution:\n")
		for _, bucket := range timeline {
			report += fmt.Sprintf("    - %s: %d events (%.1f%%)\n",
				bucket.Period, bucket.Count, bucket.Percentage)
		}
		report += "\n"
	}

	bursts := profiling.DetectBursts(allEvents, d.startTime, duration)
	if len(bursts) > 0 {
		report += fmt.Sprintf("Activity Bursts:\n")
		report += fmt.Sprintf("  Detected %d burst period(s):\n", len(bursts))
		for i, burst := range bursts {
			if i >= config.MaxBurstsDisplay {
				break
			}
			report += fmt.Sprintf("    - %s: %.1f events/sec (%.1fx normal rate)\n",
				burst.Time.Format("15:04:05"), burst.Rate, burst.Multiplier)
		}
		report += "\n"
	}

	connectEvents := d.filterEvents(events.EventConnect)
	if len(connectEvents) > 0 {
		pattern := profiling.AnalyzeConnectionPattern(connectEvents, d.startTime, d.endTime, duration)
		report += fmt.Sprintf("Connection Patterns:\n")
		report += fmt.Sprintf("  Pattern: %s\n", pattern.Pattern)
		var avgRate float64
		if duration.Seconds() > 0 {
			avgRate = float64(len(connectEvents)) / duration.Seconds()
		}
		report += fmt.Sprintf("  Average rate: %.1f connections/sec\n", avgRate)
		if pattern.BurstRate > 0 {
			report += fmt.Sprintf("  Peak rate: %.1f connections/sec\n", pattern.BurstRate)
		}
		if pattern.UniqueTargets > 0 {
			report += fmt.Sprintf("  Unique targets: %d\n", pattern.UniqueTargets)
		}
		report += "\n"
	}

	tcpEvents := append(d.filterEvents(events.EventTCPSend), d.filterEvents(events.EventTCPRecv)...)
	if len(tcpEvents) > 0 {
		ioPattern := profiling.AnalyzeIOPattern(tcpEvents, d.startTime, duration)
		report += fmt.Sprintf("Network I/O Pattern:\n")
		report += fmt.Sprintf("  Send/Receive ratio: %.2f:1\n", ioPattern.SendRecvRatio)
		report += fmt.Sprintf("  Average throughput: %.1f ops/sec\n", ioPattern.AvgThroughput)
		if ioPattern.PeakThroughput > 0 {
			report += fmt.Sprintf("  Peak throughput: %.1f ops/sec\n", ioPattern.PeakThroughput)
		}
		report += "\n"
	}

	return report
}

type stackSummary struct {
	Key        string
	Count      int
	Sample     *events.Event
	FirstFrame string
}

func (d *Diagnostician) generateStackTraceSectionWithContext(ctx context.Context) string {
	var report string
	allEvents := d.GetEvents()
	if len(allEvents) == 0 {
		return ""
	}
	type resolver struct {
		cache map[string]string
	}
	resolve := func(r *resolver, pid uint32, addr uint64) string {
		select {
		case <-ctx.Done():
			return ""
		default:
		}

		if addr == 0 {
			return ""
		}
		if r.cache == nil {
			r.cache = make(map[string]string)
		}
		exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || exePath == "" {
			return fmt.Sprintf("0x%x", addr)
		}
		key := exePath + "|" + fmt.Sprintf("%x", addr)
		if v, ok := r.cache[key]; ok {
			return v
		}
		timeoutCtx, cancel := context.WithTimeout(ctx, config.DefaultAddr2lineTimeout)
		defer cancel()
		cmd := exec.CommandContext(timeoutCtx, "addr2line", "-e", exePath, fmt.Sprintf("%#x", addr))
		out, err := cmd.Output()
		if err != nil {
			v := fmt.Sprintf("%s@0x%x", filepath.Base(exePath), addr)
			r.cache[key] = v
			return v
		}
		line := strings.TrimSpace(string(out))
		if line == "" || line == "??:0" || line == "??:?" {
			line = fmt.Sprintf("%s@0x%x", filepath.Base(exePath), addr)
		} else {
			line = filepath.Base(exePath) + ":" + line
		}
		r.cache[key] = line
		return line
	}
	r := &resolver{cache: make(map[string]string)}
	stackMap := make(map[string]*stackSummary)
	processed := 0
	for _, e := range allEvents {
		if processed >= config.MaxEventsForStacks {
			break
		}
		if e == nil {
			continue
		}
		if len(e.Stack) == 0 {
			continue
		}
		if e.LatencyNS < config.MinLatencyForStackNS && e.Type != events.EventLockContention && e.Type != events.EventDBQuery {
			continue
		}
		processed++
		top := e.Stack[0]
		frame := resolve(r, e.PID, top)
		if frame == "" {
			continue
		}
		key := fmt.Sprintf("%s|%d", frame, e.Type)
		if entry, ok := stackMap[key]; ok {
			entry.Count++
		} else {
			stackMap[key] = &stackSummary{
				Key:        key,
				Count:      1,
				Sample:     e,
				FirstFrame: frame,
			}
		}
	}
	if len(stackMap) == 0 {
		return ""
	}
	var summaries []*stackSummary
	for _, v := range stackMap {
		summaries = append(summaries, v)
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Count > summaries[j].Count
	})
	report += "Stack Traces for Slow Operations:\n"
	limit := config.MaxStackTracesLimit
	if len(summaries) < limit {
		limit = len(summaries)
	}
	for i := 0; i < limit; i++ {
		s := summaries[i]
		e := s.Sample
		if e == nil {
			continue
		}
		report += fmt.Sprintf("  Hot stack %d: %d events, type=%s, target=%s, avg latency=%.2fms\n", i+1, s.Count, e.TypeString(), e.Target, float64(e.LatencyNS)/1e6)
		maxFrames := config.MaxStackFramesLimit
		if len(e.Stack) < maxFrames {
			maxFrames = len(e.Stack)
		}
		for j := 0; j < maxFrames; j++ {
			addr := e.Stack[j]
			frame := resolve(r, e.PID, addr)
			report += fmt.Sprintf("    #%d %s\n", j, frame)
		}
	}
	report += "\n"
	return report
}

func (d *Diagnostician) generateSyscallSection(duration time.Duration) string {
	var report string
	allEvents := d.GetEvents()
	if len(allEvents) == 0 {
		return ""
	}
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
	if len(execEvents) == 0 && len(forkEvents) == 0 && len(openEvents) == 0 && len(closeEvents) == 0 {
		return ""
	}
	report += "Process and Syscall Activity:\n"
	if len(execEvents) > 0 {
		var execRate float64
		if duration.Seconds() > 0 {
			execRate = float64(len(execEvents)) / duration.Seconds()
		}
		report += fmt.Sprintf("  Execve calls: %d (%.1f/sec)\n", len(execEvents), execRate)
	}
	if len(forkEvents) > 0 {
		var forkRate float64
		if duration.Seconds() > 0 {
			forkRate = float64(len(forkEvents)) / duration.Seconds()
		}
		report += fmt.Sprintf("  Fork events: %d (%.1f/sec)\n", len(forkEvents), forkRate)
	}
	if len(openEvents) > 0 || len(closeEvents) > 0 {
		var openRate, closeRate float64
		if duration.Seconds() > 0 {
			openRate = float64(len(openEvents)) / duration.Seconds()
			closeRate = float64(len(closeEvents)) / duration.Seconds()
		}
		report += fmt.Sprintf("  Open calls: %d (%.1f/sec)\n", len(openEvents), openRate)
		report += fmt.Sprintf("  Close calls: %d (%.1f/sec)\n", len(closeEvents), closeRate)
		diff := len(openEvents) - len(closeEvents)
		if diff > 0 {
			report += fmt.Sprintf("  Potential descriptor leak: %d more opens than closes\n", diff)
		}
		fileCounts := make(map[string]int)
		for _, e := range openEvents {
			name := e.Target
			if name == "" || name == "?" || name == "unknown" {
				continue
			}
			fileCounts[name]++
		}
		if len(fileCounts) > 0 {
			type fileInfo struct {
				Name  string
				Count int
			}
			var files []fileInfo
			for name, count := range fileCounts {
				files = append(files, fileInfo{Name: name, Count: count})
			}
			sort.Slice(files, func(i, j int) bool {
				return files[i].Count > files[j].Count
			})
			report += "  Top opened files:\n"
			for i, f := range files {
				if i >= config.TopFilesLimit {
					break
				}
				report += fmt.Sprintf("    - %s (%d opens)\n", f.Name, f.Count)
			}
		}
	}
	report += "\n"
	return report
}

type ExportData struct {
	Summary         map[string]interface{}   `json:"summary"`
	DNS             map[string]interface{}   `json:"dns,omitempty"`
	TCP             map[string]interface{}   `json:"tcp,omitempty"`
	Connections     map[string]interface{}   `json:"connections,omitempty"`
	FileSystem      map[string]interface{}   `json:"filesystem,omitempty"`
	CPU             map[string]interface{}   `json:"cpu,omitempty"`
	ProcessActivity []map[string]interface{} `json:"process_activity,omitempty"`
	PotentialIssues []string                 `json:"potential_issues,omitempty"`
}

func (d *Diagnostician) ExportJSON() ExportData {
	duration := d.endTime.Sub(d.startTime)
	allEvents := d.GetEvents()
	eventsPerSec := float64(len(allEvents)) / duration.Seconds()

	data := ExportData{
		Summary: map[string]interface{}{
			"total_events":      len(allEvents),
			"events_per_second": eventsPerSec,
			"start_time":        d.startTime.Format(time.RFC3339),
			"end_time":          d.endTime.Format(time.RFC3339),
			"duration_seconds":  duration.Seconds(),
		},
	}

	dnsEvents := d.filterEvents(events.EventDNS)
	if len(dnsEvents) > 0 {
		avgLatency, maxLatency, errors, p50, p95, p99, topTargets := analyzer.AnalyzeDNS(dnsEvents)
		data.DNS = map[string]interface{}{
			"total_lookups": len(dnsEvents),
			"rate_per_second": func() float64 {
				if duration.Seconds() > 0 {
					return float64(len(dnsEvents)) / duration.Seconds()
				}
				return 0
			}(),
			"avg_latency_ms": avgLatency,
			"max_latency_ms": maxLatency,
			"p50_ms":         p50,
			"p95_ms":         p95,
			"p99_ms":         p99,
			"errors":         errors,
			"error_rate": func() float64 {
				if len(dnsEvents) > 0 {
					return float64(errors) * 100 / float64(len(dnsEvents))
				}
				return 0
			}(),
			"top_targets": topTargets,
		}
	}

	tcpSendEvents := d.filterEvents(events.EventTCPSend)
	tcpRecvEvents := d.filterEvents(events.EventTCPRecv)
	if len(tcpSendEvents) > 0 || len(tcpRecvEvents) > 0 {
		allTCP := append(tcpSendEvents, tcpRecvEvents...)
		avgRTT, maxRTT, spikes, p50, p95, p99, errors, totalBytes, avgBytes, peakBytes := analyzer.AnalyzeTCP(allTCP, d.rttSpikeThreshold)
		errorRate := float64(0)
		if len(allTCP) > 0 {
			errorRate = float64(errors) * 100 / float64(len(allTCP))
		}
		data.TCP = map[string]interface{}{
			"send_operations":    len(tcpSendEvents),
			"receive_operations": len(tcpRecvEvents),
			"avg_rtt_ms":         avgRTT,
			"max_rtt_ms":         maxRTT,
			"p50_ms":             p50,
			"p95_ms":             p95,
			"p99_ms":             p99,
			"rtt_spikes":         spikes,
			"errors":             errors,
			"error_rate":         errorRate,
			"total_bytes":        totalBytes,
			"avg_bytes":          avgBytes,
			"peak_bytes":         peakBytes,
		}
	}

	connectEvents := d.filterEvents(events.EventConnect)
	if len(connectEvents) > 0 {
		avgLatency, maxLatency, errors, p50, p95, p99, topTargets, errorBreakdown := analyzer.AnalyzeConnections(connectEvents)
		data.Connections = map[string]interface{}{
			"total_connections": len(connectEvents),
			"rate_per_second": func() float64 {
				if duration.Seconds() > 0 {
					return float64(len(connectEvents)) / duration.Seconds()
				}
				return 0
			}(),
			"avg_latency_ms":  avgLatency,
			"max_latency_ms":  maxLatency,
			"p50_ms":          p50,
			"p95_ms":          p95,
			"p99_ms":          p99,
			"failed":          errors,
			"failure_rate":    float64(errors) * 100 / float64(len(connectEvents)),
			"error_breakdown": errorBreakdown,
			"top_targets":     topTargets,
		}
	}

	writeEvents := d.filterEvents(events.EventWrite)
	readEvents := d.filterEvents(events.EventRead)
	fsyncEvents := d.filterEvents(events.EventFsync)
	if len(writeEvents) > 0 || len(readEvents) > 0 || len(fsyncEvents) > 0 {
		allFS := append(append(writeEvents, readEvents...), fsyncEvents...)
		avgLatency, maxLatency, slowOps, p50, p95, p99, totalBytes, avgBytes := analyzer.AnalyzeFS(allFS, d.fsSlowThreshold)
		data.FileSystem = map[string]interface{}{
			"write_operations": len(writeEvents),
			"read_operations":  len(readEvents),
			"fsync_operations": len(fsyncEvents),
			"avg_latency_ms":   avgLatency,
			"max_latency_ms":   maxLatency,
			"p50_ms":           p50,
			"p95_ms":           p95,
			"p99_ms":           p99,
			"slow_operations":  slowOps,
			"total_bytes":      totalBytes,
			"avg_bytes":        avgBytes,
		}
	}

	schedEvents := d.filterEvents(events.EventSchedSwitch)
	if len(schedEvents) > 0 {
		avgBlock, maxBlock, p50, p95, p99 := analyzer.AnalyzeCPU(schedEvents)
		data.CPU = map[string]interface{}{
			"thread_switches":   len(schedEvents),
			"avg_block_time_ms": avgBlock,
			"max_block_time_ms": maxBlock,
			"p50_ms":            p50,
			"p95_ms":            p95,
			"p99_ms":            p99,
		}
	}

	pidActivity := tracker.AnalyzeProcessActivity(allEvents)
	for _, info := range pidActivity {
		data.ProcessActivity = append(data.ProcessActivity, map[string]interface{}{
			"pid":         info.Pid,
			"name":        info.Name,
			"event_count": info.Count,
			"percentage":  info.Percentage,
		})
	}

	issues := detector.DetectIssues(allEvents, d.errorRateThreshold, d.rttSpikeThreshold)
	data.PotentialIssues = issues

	return data
}

func (d *Diagnostician) ExportCSV(w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{"timestamp", "pid", "process_name", "type", "latency_ms", "error", "target"}
	if err := writer.Write(header); err != nil {
		return err
	}

	allEvents := d.GetEvents()
	for _, event := range allEvents {
		if event == nil {
			continue
		}
		record := []string{
			fmt.Sprintf("%d", event.Timestamp),
			fmt.Sprintf("%d", event.PID),
			validation.SanitizeCSVField(event.ProcessName),
			validation.SanitizeCSVField(event.TypeString()),
			fmt.Sprintf("%.2f", float64(event.LatencyNS)/1e6),
			fmt.Sprintf("%d", event.Error),
			validation.SanitizeCSVField(event.Target),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}
