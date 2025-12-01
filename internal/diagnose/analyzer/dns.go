package analyzer

import (
	"sort"
	"github.com/podtrace/podtrace/internal/events"
)

func AnalyzeDNS(events []*events.Event) (avgLatency, maxLatency float64, errors int, p50, p95, p99 float64, topTargets []TargetCount) {
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
