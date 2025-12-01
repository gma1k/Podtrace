package analyzer

import (
	"sort"
	"github.com/podtrace/podtrace/internal/events"
)

func AnalyzeFS(events []*events.Event, fsSlowThreshold float64) (avgLatency, maxLatency float64, slowOps int, p50, p95, p99 float64, totalBytes, avgBytes uint64) {
	var totalLatency float64
	var latencies []float64
	maxLatency = 0
	slowOps = 0
	totalBytes = 0

	for _, e := range events {
		latencyMs := float64(e.LatencyNS) / 1e6
		latencies = append(latencies, latencyMs)
		totalLatency += latencyMs
		if latencyMs > maxLatency {
			maxLatency = latencyMs
		}
		if latencyMs > fsSlowThreshold {
			slowOps++
		}
		if e.Bytes > 0 && e.Bytes < 10*1024*1024 {
			totalBytes += e.Bytes
		}
	}

	if len(events) > 0 {
		avgLatency = totalLatency / float64(len(events))
		sort.Float64s(latencies)
		p50 = Percentile(latencies, 50)
		p95 = Percentile(latencies, 95)
		p99 = Percentile(latencies, 99)
		if totalBytes > 0 {
			avgBytes = totalBytes / uint64(len(events))
		}
	}
	return
}
