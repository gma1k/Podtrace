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
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
	"github.com/podtrace/podtrace/internal/diagnose/detector"
	"github.com/podtrace/podtrace/internal/diagnose/profiling"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/validation"
)

// Diagnostician collects and analyzes events
type Diagnostician struct {
	events             []*events.Event
	startTime          time.Time
	endTime            time.Time
	errorRateThreshold float64
	rttSpikeThreshold  float64
	fsSlowThreshold    float64
}

func NewDiagnostician() *Diagnostician {
	return &Diagnostician{
		events:             make([]*events.Event, 0),
		startTime:          time.Now(),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}
}

func NewDiagnosticianWithThresholds(errorRate, rttSpike, fsSlow float64) *Diagnostician {
	return &Diagnostician{
		events:             make([]*events.Event, 0),
		startTime:          time.Now(),
		errorRateThreshold: errorRate,
		rttSpikeThreshold:  rttSpike,
		fsSlowThreshold:    fsSlow,
	}
}

func (d *Diagnostician) AddEvent(event *events.Event) {
	d.events = append(d.events, event)
}

func (d *Diagnostician) Finish() {
	d.endTime = time.Now()
}

// Generate the diagnostic report
func (d *Diagnostician) GenerateReport() string {
	if len(d.events) == 0 {
		return "No events collected during the diagnostic period.\n"
	}

	duration := d.endTime.Sub(d.startTime)
	eventsPerSec := float64(len(d.events)) / duration.Seconds()

	var report string
	report += fmt.Sprintf("=== Diagnostic Report (collected over %v) ===\n\n", duration)
	report += fmt.Sprintf("Summary:\n")
	report += fmt.Sprintf("  Total events: %d\n", len(d.events))
	report += fmt.Sprintf("  Events per second: %.1f\n", eventsPerSec)
	report += fmt.Sprintf("  Collection period: %v to %v\n\n", d.startTime.Format("15:04:05"), d.endTime.Format("15:04:05"))

	// DNS statistics
	dnsEvents := d.filterEvents(events.EventDNS)
	if len(dnsEvents) > 0 {

		avgLatency, maxLatency, errors, p50, p95, p99, topTargets := analyzer.AnalyzeDNS(dnsEvents)
		report += fmt.Sprintf("DNS Statistics:\n")
		report += fmt.Sprintf("  Total lookups: %d (%.1f/sec)\n", len(dnsEvents), float64(len(dnsEvents))/duration.Seconds())
		report += fmt.Sprintf("  Average latency: %.2fms\n", avgLatency)
		report += fmt.Sprintf("  Max latency: %.2fms\n", maxLatency)
		report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
		report += fmt.Sprintf("  Errors: %d (%.1f%%)\n", errors, float64(errors)*100/float64(len(dnsEvents)))
		if len(topTargets) > 0 {
			report += fmt.Sprintf("  Top targets:\n")
			for i, target := range topTargets {
				if i >= 5 {
					break
				}
				report += fmt.Sprintf("    - %s (%d lookups)\n", target.Target, target.Count)
			}
		}
		report += "\n"
	}

	tcpSendEvents := d.filterEvents(events.EventTCPSend)
	tcpRecvEvents := d.filterEvents(events.EventTCPRecv)
	if len(tcpSendEvents) > 0 || len(tcpRecvEvents) > 0 {
		report += fmt.Sprintf("TCP Statistics:\n")
		report += fmt.Sprintf("  Send operations: %d (%.1f/sec)\n", len(tcpSendEvents), float64(len(tcpSendEvents))/duration.Seconds())
		report += fmt.Sprintf("  Receive operations: %d (%.1f/sec)\n", len(tcpRecvEvents), float64(len(tcpRecvEvents))/duration.Seconds())

		allTCP := append(tcpSendEvents, tcpRecvEvents...)
		if len(allTCP) > 0 {
			avgRTT, maxRTT, spikes, p50, p95, p99, errors, totalBytes, avgBytes, peakBytes := analyzer.AnalyzeTCP(allTCP, d.rttSpikeThreshold)
			report += fmt.Sprintf("  Average RTT: %.2fms\n", avgRTT)
			report += fmt.Sprintf("  Max RTT: %.2fms\n", maxRTT)
			report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
			report += fmt.Sprintf("  RTT spikes (>100ms): %d\n", spikes)
			report += fmt.Sprintf("  Errors: %d (%.1f%%)\n", errors, float64(errors)*100/float64(len(allTCP)))
			if totalBytes > 0 {
				report += fmt.Sprintf("  Total bytes transferred: %s\n", analyzer.FormatBytes(totalBytes))
				report += fmt.Sprintf("  Average bytes per operation: %s\n", analyzer.FormatBytes(avgBytes))
				report += fmt.Sprintf("  Peak bytes per operation: %s\n", analyzer.FormatBytes(peakBytes))
				report += fmt.Sprintf("  Average throughput: %s/sec\n", analyzer.FormatBytes(uint64(float64(totalBytes)/duration.Seconds())))
			}
		}
		report += "\n"
	}

	// Connection statistics
	connectEvents := d.filterEvents(events.EventConnect)
	if len(connectEvents) > 0 {
		avgLatency, maxLatency, errors, p50, p95, p99, topTargets, errorBreakdown := analyzer.AnalyzeConnections(connectEvents)
		report += fmt.Sprintf("Connection Statistics:\n")
		report += fmt.Sprintf("  Total connections: %d (%.1f/sec)\n", len(connectEvents), float64(len(connectEvents))/duration.Seconds())
		report += fmt.Sprintf("  Average latency: %.2fms\n", avgLatency)
		report += fmt.Sprintf("  Max latency: %.2fms\n", maxLatency)
		report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
		report += fmt.Sprintf("  Failed connections: %d (%.1f%%)\n", errors, float64(errors)*100/float64(len(connectEvents)))
		if len(errorBreakdown) > 0 {
			report += fmt.Sprintf("  Error breakdown:\n")
			for errCode, count := range errorBreakdown {
				report += fmt.Sprintf("    - Error %d: %d occurrences\n", errCode, count)
			}
		}
		if len(topTargets) > 0 {
			report += fmt.Sprintf("  Top connection targets:\n")
			for i, target := range topTargets {
				if i >= 5 {
					break
				}
				report += fmt.Sprintf("    - %s (%d connections)\n", target.Target, target.Count)
			}
		}
		report += "\n"
	}

	writeEvents := d.filterEvents(events.EventWrite)
	readEvents := d.filterEvents(events.EventRead)
	fsyncEvents := d.filterEvents(events.EventFsync)
	if len(writeEvents) > 0 || len(readEvents) > 0 || len(fsyncEvents) > 0 {
		report += fmt.Sprintf("File System Statistics:\n")
		report += fmt.Sprintf("  Write operations: %d (%.1f/sec)\n", len(writeEvents), float64(len(writeEvents))/duration.Seconds())
		report += fmt.Sprintf("  Read operations: %d (%.1f/sec)\n", len(readEvents), float64(len(readEvents))/duration.Seconds())
		report += fmt.Sprintf("  Fsync operations: %d (%.1f/sec)\n", len(fsyncEvents), float64(len(fsyncEvents))/duration.Seconds())

		allFS := append(append(writeEvents, readEvents...), fsyncEvents...)
		if len(allFS) > 0 {
			avgLatency, maxLatency, slowOps, p50, p95, p99, totalBytes, avgBytes := analyzer.AnalyzeFS(allFS, d.fsSlowThreshold)
			report += fmt.Sprintf("  Average latency: %.2fms\n", avgLatency)
			report += fmt.Sprintf("  Max latency: %.2fms\n", maxLatency)
			report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
			thresholdMs := d.fsSlowThreshold
			report += fmt.Sprintf("  Slow operations (>%.1fms): %d\n", thresholdMs, slowOps)
			if totalBytes > 0 {
				report += fmt.Sprintf("  Total bytes transferred: %s\n", analyzer.FormatBytes(totalBytes))
				report += fmt.Sprintf("  Average bytes per operation: %s\n", analyzer.FormatBytes(avgBytes))
				report += fmt.Sprintf("  Average throughput: %s/sec\n", analyzer.FormatBytes(uint64(float64(totalBytes)/duration.Seconds())))
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
				report += fmt.Sprintf("  Top accessed files:\n")
				for i, fc := range fileCounts {
					if i >= 5 {
						break
					}
					report += fmt.Sprintf("    - %s (%d operations)\n", fc.file, fc.count)
				}
			}
		}
		report += "\n"
	}

	udpSendEvents := d.filterEvents(events.EventUDPSend)
	udpRecvEvents := d.filterEvents(events.EventUDPRecv)
	if len(udpSendEvents) > 0 || len(udpRecvEvents) > 0 {
		report += fmt.Sprintf("UDP Statistics:\n")
		report += fmt.Sprintf("  Send operations: %d (%.1f/sec)\n", len(udpSendEvents), float64(len(udpSendEvents))/duration.Seconds())
		report += fmt.Sprintf("  Receive operations: %d (%.1f/sec)\n", len(udpRecvEvents), float64(len(udpRecvEvents))/duration.Seconds())

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
				if e.Bytes > 0 && e.Bytes < 10*1024*1024 {
					totalBytes += e.Bytes
					if e.Bytes > peakBytes {
						peakBytes = e.Bytes
					}
				}
			}
			if len(allUDP) > 0 {
				avgLatency := totalLatency / float64(len(allUDP))
				avgBytes = totalBytes / uint64(len(allUDP))
				sort.Float64s(latencies)
				p50 := analyzer.Percentile(latencies, 50)
				p95 := analyzer.Percentile(latencies, 95)
				p99 := analyzer.Percentile(latencies, 99)
				report += fmt.Sprintf("  Average latency: %.2fms\n", avgLatency)
				report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
				report += fmt.Sprintf("  Errors: %d (%.1f%%)\n", errors, float64(errors)*100/float64(len(allUDP)))
				if totalBytes > 0 {
					report += fmt.Sprintf("  Total bytes transferred: %s\n", analyzer.FormatBytes(totalBytes))
					report += fmt.Sprintf("  Average bytes per operation: %s\n", analyzer.FormatBytes(avgBytes))
					report += fmt.Sprintf("  Peak bytes per operation: %s\n", analyzer.FormatBytes(peakBytes))
					report += fmt.Sprintf("  Average throughput: %s/sec\n", analyzer.FormatBytes(uint64(float64(totalBytes)/duration.Seconds())))
				}
			}
		}
		report += "\n"
	}

	httpReqEvents := d.filterEvents(events.EventHTTPReq)
	httpRespEvents := d.filterEvents(events.EventHTTPResp)
	if len(httpReqEvents) > 0 || len(httpRespEvents) > 0 {
		report += fmt.Sprintf("HTTP Statistics:\n")
		report += fmt.Sprintf("  Requests: %d (%.1f/sec)\n", len(httpReqEvents), float64(len(httpReqEvents))/duration.Seconds())
		report += fmt.Sprintf("  Responses: %d (%.1f/sec)\n", len(httpRespEvents), float64(len(httpRespEvents))/duration.Seconds())

		allHTTP := append(httpReqEvents, httpRespEvents...)
		if len(allHTTP) > 0 {
			var totalBytes, avgBytes uint64
			var totalLatency float64
			var latencies []float64
			for _, e := range allHTTP {
				latencyMs := float64(e.LatencyNS) / 1e6
				latencies = append(latencies, latencyMs)
				totalLatency += latencyMs
				if e.Bytes > 0 && e.Bytes < 10*1024*1024 {
					totalBytes += e.Bytes
				}
			}
			if len(allHTTP) > 0 {
				avgLatency := totalLatency / float64(len(allHTTP))
				avgBytes = totalBytes / uint64(len(allHTTP))
				sort.Float64s(latencies)
				p50 := analyzer.Percentile(latencies, 50)
				p95 := analyzer.Percentile(latencies, 95)
				p99 := analyzer.Percentile(latencies, 99)
				report += fmt.Sprintf("  Average latency: %.2fms\n", avgLatency)
				report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
				if totalBytes > 0 {
					report += fmt.Sprintf("  Total bytes transferred: %s\n", analyzer.FormatBytes(totalBytes))
					report += fmt.Sprintf("  Average bytes per response: %s\n", analyzer.FormatBytes(avgBytes))
					report += fmt.Sprintf("  Average throughput: %s/sec\n", analyzer.FormatBytes(uint64(float64(totalBytes)/duration.Seconds())))
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
						report += fmt.Sprintf("  Top requested URLs:\n")
						for i, uc := range urlCounts {
							if i >= 5 {
								break
							}
							report += fmt.Sprintf("    - %s (%d requests)\n", uc.url, uc.count)
						}
					}
				}
			}
		}
		report += "\n"
	}

	schedEvents := d.filterEvents(events.EventSchedSwitch)
	if len(schedEvents) > 0 {
		avgBlock, maxBlock, p50, p95, p99 := analyzer.AnalyzeCPU(schedEvents)
		report += fmt.Sprintf("CPU Statistics:\n")
		report += fmt.Sprintf("  Thread switches: %d (%.1f/sec)\n", len(schedEvents), float64(len(schedEvents))/duration.Seconds())
		report += fmt.Sprintf("  Average block time: %.2fms\n", avgBlock)
		report += fmt.Sprintf("  Max block time: %.2fms\n", maxBlock)
		report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
		report += "\n"
	}

	tcpStateEvents := d.filterEvents(events.EventTCPState)
	if len(tcpStateEvents) > 0 {
		report += fmt.Sprintf("TCP Connection State Tracking:\n")
		report += fmt.Sprintf("  State changes: %d (%.1f/sec)\n", len(tcpStateEvents), float64(len(tcpStateEvents))/duration.Seconds())
		stateCounts := make(map[string]int)
		for _, e := range tcpStateEvents {
			stateStr := events.TCPStateString(e.TCPState)
			stateCounts[stateStr]++
		}
		if len(stateCounts) > 0 {
			report += fmt.Sprintf("  State distribution:\n")
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
				if i >= 10 {
					break
				}
				report += fmt.Sprintf("    - %s: %d\n", s.state, s.count)
			}
		}
		report += "\n"
	}

	pageFaultEvents := d.filterEvents(events.EventPageFault)
	oomKillEvents := d.filterEvents(events.EventOOMKill)
	if len(pageFaultEvents) > 0 || len(oomKillEvents) > 0 {
		report += fmt.Sprintf("Memory Statistics:\n")
		if len(pageFaultEvents) > 0 {
			report += fmt.Sprintf("  Page faults: %d (%.1f/sec)\n", len(pageFaultEvents), float64(len(pageFaultEvents))/duration.Seconds())
			errorCounts := make(map[int32]int)
			for _, e := range pageFaultEvents {
				errorCounts[e.Error]++
			}
			if len(errorCounts) > 0 {
				report += fmt.Sprintf("  Page fault error codes:\n")
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
				report += fmt.Sprintf("  Killed processes:\n")
				for i, e := range oomKillEvents {
					if i >= 5 {
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
	}

	report += profiling.GenerateCPUUsageReport(d.events, duration)

	report += d.generateStackTraceSection()

	report += d.generateSyscallSection(duration)

	report += d.generateApplicationTracing(duration)

	report += tracker.GenerateConnectionCorrelation(d.events)

	// Issues summary
	issues := detector.DetectIssues(d.events, d.errorRateThreshold, d.rttSpikeThreshold)
	if len(issues) > 0 {
		report += fmt.Sprintf("Potential Issues Detected:\n")
		for _, issue := range issues {
			report += fmt.Sprintf("  %s\n", issue)
		}
		report += "\n"
	}

	return report
}

func (d *Diagnostician) filterEvents(eventType events.EventType) []*events.Event {
	var filtered []*events.Event
	for _, e := range d.events {
		if e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (d *Diagnostician) generateApplicationTracing(duration time.Duration) string {
	var report string

	pidActivity := tracker.AnalyzeProcessActivity(d.events)
	if len(pidActivity) > 0 {
		report += fmt.Sprintf("Process Activity:\n")
		report += fmt.Sprintf("  Active processes: %d\n", len(pidActivity))
		report += fmt.Sprintf("  Top active processes:\n")
		for i, pidInfo := range pidActivity {
			if i >= 5 {
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

	timeline := profiling.AnalyzeTimeline(d.events, d.startTime, duration)
	if len(timeline) > 0 {
		report += fmt.Sprintf("Activity Timeline:\n")
		report += fmt.Sprintf("  Activity distribution:\n")
		for _, bucket := range timeline {
			report += fmt.Sprintf("    - %s: %d events (%.1f%%)\n",
				bucket.Period, bucket.Count, bucket.Percentage)
		}
		report += "\n"
	}

	bursts := profiling.DetectBursts(d.events, d.startTime, duration)
	if len(bursts) > 0 {
		report += fmt.Sprintf("Activity Bursts:\n")
		report += fmt.Sprintf("  Detected %d burst period(s):\n", len(bursts))
		for i, burst := range bursts {
			if i >= 3 {
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
		report += fmt.Sprintf("  Average rate: %.1f connections/sec\n", pattern.AvgRate)
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

func (d *Diagnostician) generateStackTraceSection() string {
	var report string
	if len(d.events) == 0 {
		return ""
	}
	type resolver struct {
		cache map[string]string
	}
	resolve := func(r *resolver, pid uint32, addr uint64) string {
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
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		cmd := exec.CommandContext(ctx, "addr2line", "-e", exePath, fmt.Sprintf("%#x", addr))
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
	const maxEventsForStacks = 10000
	processed := 0
	for _, e := range d.events {
		if processed >= maxEventsForStacks {
			break
		}
		if e == nil {
			continue
		}
		if len(e.Stack) == 0 {
			continue
		}
		if e.LatencyNS < uint64(1000000) && e.Type != events.EventLockContention && e.Type != events.EventDBQuery {
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
	limit := 5
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
		maxFrames := 5
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
	if len(d.events) == 0 {
		return ""
	}
	var execEvents, forkEvents, openEvents, closeEvents []*events.Event
	for _, e := range d.events {
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
		report += fmt.Sprintf("  Execve calls: %d (%.1f/sec)\n", len(execEvents), float64(len(execEvents))/duration.Seconds())
	}
	if len(forkEvents) > 0 {
		report += fmt.Sprintf("  Fork events: %d (%.1f/sec)\n", len(forkEvents), float64(len(forkEvents))/duration.Seconds())
	}
	if len(openEvents) > 0 || len(closeEvents) > 0 {
		report += fmt.Sprintf("  Open calls: %d (%.1f/sec)\n", len(openEvents), float64(len(openEvents))/duration.Seconds())
		report += fmt.Sprintf("  Close calls: %d (%.1f/sec)\n", len(closeEvents), float64(len(closeEvents))/duration.Seconds())
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
				if i >= 5 {
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
	eventsPerSec := float64(len(d.events)) / duration.Seconds()

	data := ExportData{
		Summary: map[string]interface{}{
			"total_events":      len(d.events),
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
			"total_lookups":   len(dnsEvents),
			"rate_per_second": float64(len(dnsEvents)) / duration.Seconds(),
			"avg_latency_ms":  avgLatency,
			"max_latency_ms":  maxLatency,
			"p50_ms":          p50,
			"p95_ms":          p95,
			"p99_ms":          p99,
			"errors":          errors,
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
			"rate_per_second":   float64(len(connectEvents)) / duration.Seconds(),
			"avg_latency_ms":    avgLatency,
			"max_latency_ms":    maxLatency,
			"p50_ms":            p50,
			"p95_ms":            p95,
			"p99_ms":            p99,
			"failed":            errors,
			"failure_rate":      float64(errors) * 100 / float64(len(connectEvents)),
			"error_breakdown":   errorBreakdown,
			"top_targets":       topTargets,
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

	pidActivity := tracker.AnalyzeProcessActivity(d.events)
	for _, info := range pidActivity {
		data.ProcessActivity = append(data.ProcessActivity, map[string]interface{}{
			"pid":         info.Pid,
			"name":        info.Name,
			"event_count": info.Count,
			"percentage":  info.Percentage,
		})
	}

	issues := detector.DetectIssues(d.events, d.errorRateThreshold, d.rttSpikeThreshold)
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

	for _, event := range d.events {
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