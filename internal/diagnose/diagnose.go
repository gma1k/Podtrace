package diagnose

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/validation"
)

// Diagnostician collects and analyzes events
type Diagnostician struct {
	events    []*events.Event
	startTime time.Time
	endTime   time.Time
}

func NewDiagnostician() *Diagnostician {
	return &Diagnostician{
		events:    make([]*events.Event, 0),
		startTime: time.Now(),
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

		avgLatency, maxLatency, errors, p50, p95, p99, topTargets := d.analyzeDNS(dnsEvents)
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
				report += fmt.Sprintf("    - %s (%d lookups)\n", target.target, target.count)
			}
		}
		report += "\n"
	}

	// TCP RTT statistics
	tcpSendEvents := d.filterEvents(events.EventTCPSend)
	tcpRecvEvents := d.filterEvents(events.EventTCPRecv)
	if len(tcpSendEvents) > 0 || len(tcpRecvEvents) > 0 {
		report += fmt.Sprintf("TCP Statistics:\n")
		report += fmt.Sprintf("  Send operations: %d (%.1f/sec)\n", len(tcpSendEvents), float64(len(tcpSendEvents))/duration.Seconds())
		report += fmt.Sprintf("  Receive operations: %d (%.1f/sec)\n", len(tcpRecvEvents), float64(len(tcpRecvEvents))/duration.Seconds())

		allTCP := append(tcpSendEvents, tcpRecvEvents...)
		if len(allTCP) > 0 {
			avgRTT, maxRTT, spikes, p50, p95, p99, errors := d.analyzeTCP(allTCP)
			report += fmt.Sprintf("  Average RTT: %.2fms\n", avgRTT)
			report += fmt.Sprintf("  Max RTT: %.2fms\n", maxRTT)
			report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
			report += fmt.Sprintf("  RTT spikes (>100ms): %d\n", spikes)
			report += fmt.Sprintf("  Errors: %d (%.1f%%)\n", errors, float64(errors)*100/float64(len(allTCP)))
		}
		report += "\n"
	}

	// Connection statistics
	connectEvents := d.filterEvents(events.EventConnect)
	if len(connectEvents) > 0 {
		avgLatency, maxLatency, errors, p50, p95, p99, topTargets, errorBreakdown := d.analyzeConnections(connectEvents)
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
				report += fmt.Sprintf("    - %s (%d connections)\n", target.target, target.count)
			}
		}
		report += "\n"
	}

	// File system statistics
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
			avgLatency, maxLatency, slowOps, p50, p95, p99 := d.analyzeFS(allFS)
			report += fmt.Sprintf("  Average latency: %.2fms\n", avgLatency)
			report += fmt.Sprintf("  Max latency: %.2fms\n", maxLatency)
			report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
			report += fmt.Sprintf("  Slow operations (>10ms): %d\n", slowOps)

			// Top files by operation count
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

	// CPU statistics
	schedEvents := d.filterEvents(events.EventSchedSwitch)
	if len(schedEvents) > 0 {
		avgBlock, maxBlock, p50, p95, p99 := d.analyzeCPU(schedEvents)
		report += fmt.Sprintf("CPU Statistics:\n")
		report += fmt.Sprintf("  Thread switches: %d (%.1f/sec)\n", len(schedEvents), float64(len(schedEvents))/duration.Seconds())
		report += fmt.Sprintf("  Average block time: %.2fms\n", avgBlock)
		report += fmt.Sprintf("  Max block time: %.2fms\n", maxBlock)
		report += fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
		report += "\n"
	}

	// CPU Usage by Process
	report += d.generateCPUUsageReport(duration)

	report += d.generateApplicationTracing(duration)

	// Issues summary
	issues := d.detectIssues()
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

type targetCount struct {
	target string
	count  int
}

func (d *Diagnostician) analyzeDNS(events []*events.Event) (avgLatency, maxLatency float64, errors int, p50, p95, p99 float64, topTargets []targetCount) {
	var totalLatency float64
	var latencies []float64
	maxLatency = 0
	errors = 0
	targetMap := make(map[string]int)

	for _, e := range events {
		latencyMs := float64(e.LatencyNS) / 1e6
		latencies = append(latencies, latencyMs)
		totalLatency += latencyMs
		if latencyMs > maxLatency {
			maxLatency = latencyMs
		}
		if e.Error != 0 {
			errors++
		}
		if e.Target != "" && e.Target != "?" {
			targetMap[e.Target]++
		}
	}

	if len(events) > 0 {
		avgLatency = totalLatency / float64(len(events))
		sort.Float64s(latencies)
		p50 = percentile(latencies, 50)
		p95 = percentile(latencies, 95)
		p99 = percentile(latencies, 99)
	}

	for target, count := range targetMap {
		topTargets = append(topTargets, targetCount{target: target, count: count})
	}
	sort.Slice(topTargets, func(i, j int) bool {
		return topTargets[i].count > topTargets[j].count
	})

	return
}

func (d *Diagnostician) analyzeTCP(events []*events.Event) (avgRTT, maxRTT float64, spikes int, p50, p95, p99 float64, errors int) {
	var totalRTT float64
	var rtts []float64
	maxRTT = 0
	spikes = 0
	errors = 0

	for _, e := range events {
		rttMs := float64(e.LatencyNS) / 1e6
		rtts = append(rtts, rttMs)
		totalRTT += rttMs
		if rttMs > maxRTT {
			maxRTT = rttMs
		}
		if rttMs > 100 {
			spikes++
		}
		if e.Error < 0 && e.Error != -11 {
			errors++
		}
	}

	if len(events) > 0 {
		avgRTT = totalRTT / float64(len(events))
		sort.Float64s(rtts)
		p50 = percentile(rtts, 50)
		p95 = percentile(rtts, 95)
		p99 = percentile(rtts, 99)
	}
	return
}

func (d *Diagnostician) analyzeConnections(events []*events.Event) (avgLatency, maxLatency float64, errors int, p50, p95, p99 float64, topTargets []targetCount, errorBreakdown map[int32]int) {
	var totalLatency float64
	var latencies []float64
	maxLatency = 0
	errors = 0
	targetMap := make(map[string]int)
	errorBreakdown = make(map[int32]int)

	for _, e := range events {
		latencyMs := float64(e.LatencyNS) / 1e6
		latencies = append(latencies, latencyMs)
		totalLatency += latencyMs
		if latencyMs > maxLatency {
			maxLatency = latencyMs
		}
		if e.Error != 0 {
			errors++
			errorBreakdown[e.Error]++
		}
		if e.Target != "" && e.Target != "?" && e.Target != "unknown" && e.Target != "file" {
			targetMap[e.Target]++
		}
	}

	if len(events) > 0 {
		avgLatency = totalLatency / float64(len(events))
		sort.Float64s(latencies)
		p50 = percentile(latencies, 50)
		p95 = percentile(latencies, 95)
		p99 = percentile(latencies, 99)
	}

	for target, count := range targetMap {
		topTargets = append(topTargets, targetCount{target: target, count: count})
	}
	sort.Slice(topTargets, func(i, j int) bool {
		return topTargets[i].count > topTargets[j].count
	})

	return
}

func (d *Diagnostician) analyzeFS(events []*events.Event) (avgLatency, maxLatency float64, slowOps int, p50, p95, p99 float64) {
	var totalLatency float64
	var latencies []float64
	maxLatency = 0
	slowOps = 0

	for _, e := range events {
		latencyMs := float64(e.LatencyNS) / 1e6
		latencies = append(latencies, latencyMs)
		totalLatency += latencyMs
		if latencyMs > maxLatency {
			maxLatency = latencyMs
		}
		if latencyMs > 10 {
			slowOps++
		}
	}

	if len(events) > 0 {
		avgLatency = totalLatency / float64(len(events))
		sort.Float64s(latencies)
		p50 = percentile(latencies, 50)
		p95 = percentile(latencies, 95)
		p99 = percentile(latencies, 99)
	}
	return
}

func (d *Diagnostician) analyzeCPU(events []*events.Event) (avgBlock, maxBlock float64, p50, p95, p99 float64) {
	var totalBlock float64
	var blocks []float64
	maxBlock = 0

	for _, e := range events {
		blockMs := float64(e.LatencyNS) / 1e6
		blocks = append(blocks, blockMs)
		totalBlock += blockMs
		if blockMs > maxBlock {
			maxBlock = blockMs
		}
	}

	if len(events) > 0 {
		avgBlock = totalBlock / float64(len(events))
		sort.Float64s(blocks)
		p50 = percentile(blocks, 50)
		p95 = percentile(blocks, 95)
		p99 = percentile(blocks, 99)
	}
	return
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1) * p / 100)
	return sorted[index]
}

// detectIssues analyzes events and returns a list of potential issues
func (d *Diagnostician) detectIssues() []string {
	var issues []string

	connectEvents := d.filterEvents(events.EventConnect)
	if len(connectEvents) > 0 {
		errors := 0
		for _, e := range connectEvents {
			if e.Error != 0 {
				errors++
			}
		}
		errorRate := float64(errors) / float64(len(connectEvents)) * 100
		if errorRate > 10 {
			issues = append(issues, fmt.Sprintf("High connection failure rate: %.1f%% (%d/%d)", errorRate, errors, len(connectEvents)))
		}
	}

	tcpEvents := append(d.filterEvents(events.EventTCPSend), d.filterEvents(events.EventTCPRecv)...)
	if len(tcpEvents) > 0 {
		spikes := 0
		for _, e := range tcpEvents {
			if float64(e.LatencyNS)/1e6 > 100 {
				spikes++
			}
		}
		spikeRate := float64(spikes) / float64(len(tcpEvents)) * 100
		if spikeRate > 5 {
			issues = append(issues, fmt.Sprintf("High TCP RTT spike rate: %.1f%% (%d/%d)", spikeRate, spikes, len(tcpEvents)))
		}
	}

	return issues
}

func (d *Diagnostician) generateApplicationTracing(duration time.Duration) string {
	var report string

	pidActivity := d.analyzeProcessActivity()
	if len(pidActivity) > 0 {
		report += fmt.Sprintf("Process Activity:\n")
		report += fmt.Sprintf("  Active processes: %d\n", len(pidActivity))
		report += fmt.Sprintf("  Top active processes:\n")
		for i, pidInfo := range pidActivity {
			if i >= 5 {
				break
			}
			name := pidInfo.name
			if name == "" {
				name = "unknown"
			}
			report += fmt.Sprintf("    - PID %d (%s): %d events (%.1f%%)\n",
				pidInfo.pid, name, pidInfo.count, pidInfo.percentage)
		}
		report += "\n"
	}

	timeline := d.analyzeTimeline(duration)
	if len(timeline) > 0 {
		report += fmt.Sprintf("Activity Timeline:\n")
		report += fmt.Sprintf("  Activity distribution:\n")
		for _, bucket := range timeline {
			report += fmt.Sprintf("    - %s: %d events (%.1f%%)\n",
				bucket.period, bucket.count, bucket.percentage)
		}
		report += "\n"
	}

	bursts := d.detectBursts(duration)
	if len(bursts) > 0 {
		report += fmt.Sprintf("Activity Bursts:\n")
		report += fmt.Sprintf("  Detected %d burst period(s):\n", len(bursts))
		for i, burst := range bursts {
			if i >= 3 {
				break
			}
			report += fmt.Sprintf("    - %s: %.1f events/sec (%.1fx normal rate)\n",
				burst.time.Format("15:04:05"), burst.rate, burst.multiplier)
		}
		report += "\n"
	}

	connectEvents := d.filterEvents(events.EventConnect)
	if len(connectEvents) > 0 {
		pattern := d.analyzeConnectionPattern(connectEvents, duration)
		report += fmt.Sprintf("Connection Patterns:\n")
		report += fmt.Sprintf("  Pattern: %s\n", pattern.pattern)
		report += fmt.Sprintf("  Average rate: %.1f connections/sec\n", pattern.avgRate)
		if pattern.burstRate > 0 {
			report += fmt.Sprintf("  Peak rate: %.1f connections/sec\n", pattern.burstRate)
		}
		if pattern.uniqueTargets > 0 {
			report += fmt.Sprintf("  Unique targets: %d\n", pattern.uniqueTargets)
		}
		report += "\n"
	}

	tcpEvents := append(d.filterEvents(events.EventTCPSend), d.filterEvents(events.EventTCPRecv)...)
	if len(tcpEvents) > 0 {
		ioPattern := d.analyzeIOPattern(tcpEvents, duration)
		report += fmt.Sprintf("Network I/O Pattern:\n")
		report += fmt.Sprintf("  Send/Receive ratio: %.2f:1\n", ioPattern.sendRecvRatio)
		report += fmt.Sprintf("  Average throughput: %.1f ops/sec\n", ioPattern.avgThroughput)
		if ioPattern.peakThroughput > 0 {
			report += fmt.Sprintf("  Peak throughput: %.1f ops/sec\n", ioPattern.peakThroughput)
		}
		report += "\n"
	}

	return report
}

type pidInfo struct {
	pid        uint32
	name       string
	count      int
	percentage float64
}

type timelineBucket struct {
	period     string
	count      int
	percentage float64
}

type burstInfo struct {
	time       time.Time
	rate       float64
	multiplier float64
}

type connectionPattern struct {
	pattern       string
	avgRate       float64
	burstRate     float64
	uniqueTargets int
}

type ioPattern struct {
	sendRecvRatio  float64
	avgThroughput  float64
	peakThroughput float64
}

func (d *Diagnostician) analyzeProcessActivity() []pidInfo {
	pidMap := make(map[uint32]int)
	totalEvents := len(d.events)

	for _, e := range d.events {
		pidMap[e.PID]++
	}

	var pidInfos []pidInfo
	for pid, count := range pidMap {
		percentage := float64(count) / float64(totalEvents) * 100
		name := ""
		for _, e := range d.events {
			if e.PID == pid && e.ProcessName != "" {
				name = e.ProcessName
				break
			}
		}
		if name == "" {
			name = getProcessName(pid)
		}
		if name == "" {
			name = "unknown"
		}
		pidInfos = append(pidInfos, pidInfo{
			pid:        pid,
			name:       name,
			count:      count,
			percentage: percentage,
		})
	}

	sort.Slice(pidInfos, func(i, j int) bool {
		return pidInfos[i].count > pidInfos[j].count
	})

	return pidInfos
}

const maxProcessCacheSize = 1000

var processNameCache = make(map[uint32]string)
var processNameCacheMutex = &sync.Mutex{}

func getProcessName(pid uint32) string {
	if !validation.ValidatePID(pid) {
		return ""
	}

	processNameCacheMutex.Lock()
	if name, ok := processNameCache[pid]; ok {
		processNameCacheMutex.Unlock()
		return name
	}
	processNameCacheMutex.Unlock()

	name := ""

	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	if data, err := os.ReadFile(statPath); err == nil {
		statStr := string(data)
		start := strings.Index(statStr, "(")
		end := strings.LastIndex(statStr, ")")
		if start >= 0 && end > start {
			name = statStr[start+1 : end]
		}
	}

	if name == "" {
		commPath := fmt.Sprintf("/proc/%d/comm", pid)
		if data, err := os.ReadFile(commPath); err == nil {
			name = strings.TrimSpace(string(data))
		}
	}

	if name == "" {
		cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
		if cmdline, err := os.ReadFile(cmdlinePath); err == nil {
			parts := strings.Split(string(cmdline), "\x00")
			if len(parts) > 0 && parts[0] != "" {
				name = parts[0]
				if idx := strings.LastIndex(name, "/"); idx >= 0 {
					name = name[idx+1:]
				}
			}
		}
	}

	if name == "" {
		exePath := fmt.Sprintf("/proc/%d/exe", pid)
		if link, err := os.Readlink(exePath); err == nil {
			if idx := strings.LastIndex(link, "/"); idx >= 0 {
				name = link[idx+1:]
			} else {
				name = link
			}
		}
	}

	if name == "" {
		statusPath := fmt.Sprintf("/proc/%d/status", pid)
		if data, err := os.ReadFile(statusPath); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "Name:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						name = parts[1]
						break
					}
				}
			}
		}
	}

	processNameCacheMutex.Lock()
	if len(processNameCache) >= maxProcessCacheSize {
		for k := range processNameCache {
			delete(processNameCache, k)
			break
		}
	}
	processNameCache[pid] = name
	processNameCacheMutex.Unlock()

	return validation.SanitizeProcessName(name)
}

func (d *Diagnostician) analyzeTimeline(duration time.Duration) []timelineBucket {
	if len(d.events) == 0 {
		return nil
	}

	numBuckets := 5
	bucketDuration := duration / time.Duration(numBuckets)
	buckets := make([]int, numBuckets)

	for _, e := range d.events {
		eventTime := time.Unix(0, int64(e.Timestamp))
		elapsed := eventTime.Sub(d.startTime)
		bucketIndex := int(elapsed / bucketDuration)
		if bucketIndex >= numBuckets {
			bucketIndex = numBuckets - 1
		}
		if bucketIndex < 0 {
			bucketIndex = 0
		}
		buckets[bucketIndex]++
	}

	var timeline []timelineBucket
	totalEvents := len(d.events)
	for i, count := range buckets {
		startTime := d.startTime.Add(time.Duration(i) * bucketDuration)
		endTime := d.startTime.Add(time.Duration(i+1) * bucketDuration)
		period := fmt.Sprintf("%s-%s", startTime.Format("15:04:05"), endTime.Format("15:04:05"))
		percentage := float64(count) / float64(totalEvents) * 100
		timeline = append(timeline, timelineBucket{
			period:     period,
			count:      count,
			percentage: percentage,
		})
	}

	return timeline
}

func (d *Diagnostician) detectBursts(duration time.Duration) []burstInfo {
	if len(d.events) < 10 {
		return nil
	}

	avgRate := float64(len(d.events)) / duration.Seconds()
	windowDuration := 1 * time.Second
	numWindows := int(duration / windowDuration)
	if numWindows < 2 {
		return nil
	}

	var bursts []burstInfo
	windowStart := d.startTime

	for i := 0; i < numWindows; i++ {
		windowEnd := windowStart.Add(windowDuration)
		count := 0
		for _, e := range d.events {
			eventTime := time.Unix(0, int64(e.Timestamp))
			if eventTime.After(windowStart) && eventTime.Before(windowEnd) {
				count++
			}
		}
		rate := float64(count) / windowDuration.Seconds()
		if rate > avgRate*2.0 {
			multiplier := rate / avgRate
			bursts = append(bursts, burstInfo{
				time:       windowStart,
				rate:       rate,
				multiplier: multiplier,
			})
		}
		windowStart = windowEnd
	}

	return bursts
}

func (d *Diagnostician) analyzeConnectionPattern(connectEvents []*events.Event, duration time.Duration) connectionPattern {
	if len(connectEvents) == 0 {
		return connectionPattern{}
	}

	avgRate := float64(len(connectEvents)) / duration.Seconds()
	windowDuration := duration / 10
	if windowDuration < 100*time.Millisecond {
		windowDuration = 100 * time.Millisecond
	}

	var windowCounts []int
	windowStart := d.startTime
	for windowStart.Before(d.endTime) {
		windowEnd := windowStart.Add(windowDuration)
		count := 0
		for _, e := range connectEvents {
			eventTime := time.Unix(0, int64(e.Timestamp))
			if eventTime.After(windowStart) && eventTime.Before(windowEnd) {
				count++
			}
		}
		windowCounts = append(windowCounts, count)
		windowStart = windowEnd
	}

	var sum, sumSq float64
	for _, count := range windowCounts {
		sum += float64(count)
		sumSq += float64(count) * float64(count)
	}
	mean := sum / float64(len(windowCounts))
	variance := (sumSq / float64(len(windowCounts))) - (mean * mean)
	stdDev := variance

	pattern := "steady"
	if stdDev > mean*0.5 {
		pattern = "bursty"
	} else if stdDev < mean*0.1 {
		pattern = "steady"
	} else {
		pattern = "sporadic"
	}

	peakRate := 0.0
	for _, count := range windowCounts {
		rate := float64(count) / windowDuration.Seconds()
		if rate > peakRate {
			peakRate = rate
		}
	}

	targetMap := make(map[string]bool)
	for _, e := range connectEvents {
		if e.Target != "" && e.Target != "?" && e.Target != "unknown" && e.Target != "file" {
			targetMap[e.Target] = true
		}
	}

	return connectionPattern{
		pattern:       pattern,
		avgRate:       avgRate,
		burstRate:     peakRate,
		uniqueTargets: len(targetMap),
	}
}

func (d *Diagnostician) analyzeIOPattern(tcpEvents []*events.Event, duration time.Duration) ioPattern {
	sendEvents := d.filterEvents(events.EventTCPSend)
	recvEvents := d.filterEvents(events.EventTCPRecv)

	sendCount := len(sendEvents)
	recvCount := len(recvEvents)

	sendRecvRatio := 1.0
	if recvCount > 0 {
		sendRecvRatio = float64(sendCount) / float64(recvCount)
	}

	avgThroughput := float64(len(tcpEvents)) / duration.Seconds()
	windowDuration := 1 * time.Second
	numWindows := int(duration / windowDuration)
	if numWindows < 1 {
		numWindows = 1
	}

	peakThroughput := 0.0
	windowStart := d.startTime
	for i := 0; i < numWindows; i++ {
		windowEnd := windowStart.Add(windowDuration)
		count := 0
		for _, e := range tcpEvents {
			eventTime := time.Unix(0, int64(e.Timestamp))
			if eventTime.After(windowStart) && eventTime.Before(windowEnd) {
				count++
			}
		}
		rate := float64(count) / windowDuration.Seconds()
		if rate > peakThroughput {
			peakThroughput = rate
		}
		windowStart = windowEnd
	}

	return ioPattern{
		sendRecvRatio:  sendRecvRatio,
		avgThroughput:  avgThroughput,
		peakThroughput: peakThroughput,
	}
}
