package analyzer

import (
	"sort"
	"github.com/podtrace/podtrace/internal/events"
)

func AnalyzeCPU(events []*events.Event) (avgBlock, maxBlock float64, p50, p95, p99 float64) {
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
		p50 = Percentile(blocks, 50)
		p95 = Percentile(blocks, 95)
		p99 = Percentile(blocks, 99)
	}
	return
}
