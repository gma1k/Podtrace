package analyzer

import (
	"sort"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func AnalyzeTLS(events []*events.Event) (
	avgLatency, maxLatency float64,
	errors int,
	p50, p95, p99 float64,
	errorBreakdown map[int32]int,
	topTargets []TargetCount,
) {
	var totalLatency float64
	var latencies []float64
	maxLatency = 0
	errors = 0
	errorBreakdown = make(map[int32]int)
	targetMap := make(map[string]int)

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
	sortTargetCounts(topTargets)

	return
}
