package analyzer

import (
	"sort"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

func AnalyzeTCP(events []*events.Event, rttSpikeThreshold float64) (avgRTT, maxRTT float64, spikes int, p50, p95, p99 float64, errors int, totalBytes, avgBytes, peakBytes uint64) {
	var totalRTT float64
	var rtts []float64
	maxRTT = 0
	spikes = 0
	errors = 0
	totalBytes = 0
	peakBytes = 0

	for _, e := range events {
		rttMs := float64(e.LatencyNS) / float64(config.NSPerMS)
		rtts = append(rtts, rttMs)
		totalRTT += rttMs
		if rttMs > maxRTT {
			maxRTT = rttMs
		}
		if rttMs > rttSpikeThreshold {
			spikes++
		}
		if e.Error < 0 && e.Error != -config.EAGAIN {
			errors++
		}
		if e.Bytes > 0 && e.Bytes < config.MaxBytesForBandwidth {
			totalBytes += e.Bytes
			if e.Bytes > peakBytes {
				peakBytes = e.Bytes
			}
		}
	}

	if len(events) > 0 {
		avgRTT = totalRTT / float64(len(events))
		sort.Float64s(rtts)
		p50 = Percentile(rtts, 50)
		p95 = Percentile(rtts, 95)
		p99 = Percentile(rtts, 99)
		if totalBytes > 0 {
			avgBytes = totalBytes / uint64(len(events))
		}
	}
	return
}

func AnalyzeConnections(events []*events.Event) (avgLatency, maxLatency float64, errors int, p50, p95, p99 float64, topTargets []TargetCount, errorBreakdown map[int32]int) {
	var totalLatency float64
	var latencies []float64
	maxLatency = 0
	errors = 0
	targetMap := make(map[string]int)
	errorBreakdown = make(map[int32]int)

	for _, e := range events {
		latencyMs := float64(e.LatencyNS) / float64(config.NSPerMS)
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
		p50 = Percentile(latencies, 50)
		p95 = Percentile(latencies, 95)
		p99 = Percentile(latencies, 99)
	}

	for target, count := range targetMap {
		topTargets = append(topTargets, TargetCount{target, count})
	}
	sort.Slice(topTargets, func(i, j int) bool {
		return topTargets[i].Count > topTargets[j].Count
	})

	return
}
