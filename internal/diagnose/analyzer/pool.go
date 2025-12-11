package analyzer

import (
	"sort"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

type PoolStats struct {
	TotalAcquires   int
	TotalReleases   int
	ExhaustedCount  int
	AvgWaitTime     time.Duration
	MaxWaitTime     time.Duration
	ReuseRate       float64
	PeakConnections int
	AvgConnections  float64
	P50WaitTime     float64
	P95WaitTime     float64
	P99WaitTime     float64
}

func AnalyzePool(acquireEvents, releaseEvents, exhaustedEvents []*events.Event) PoolStats {
	stats := PoolStats{
		TotalAcquires:  len(acquireEvents),
		TotalReleases:  len(releaseEvents),
		ExhaustedCount: len(exhaustedEvents),
	}

	if stats.TotalAcquires > 0 {
		stats.ReuseRate = float64(stats.TotalReleases) / float64(stats.TotalAcquires)
	}

	var waitTimes []float64
	var totalWaitTime time.Duration
	maxWaitTime := time.Duration(0)

	for _, e := range exhaustedEvents {
		waitTime := e.Latency()
		waitTimes = append(waitTimes, float64(waitTime.Nanoseconds())/float64(config.NSPerMS))
		totalWaitTime += waitTime
		if waitTime > maxWaitTime {
			maxWaitTime = waitTime
		}
	}

	if stats.ExhaustedCount > 0 {
		stats.AvgWaitTime = totalWaitTime / time.Duration(stats.ExhaustedCount)
		stats.MaxWaitTime = maxWaitTime

		if len(waitTimes) > 0 {
			sort.Float64s(waitTimes)
			stats.P50WaitTime = Percentile(waitTimes, 50)
			stats.P95WaitTime = Percentile(waitTimes, 95)
			stats.P99WaitTime = Percentile(waitTimes, 99)
		}
	}

	poolTracker := make(map[string]struct {
		current int
		peak    int
	})

	for _, e := range acquireEvents {
		poolID := e.Target
		if poolID == "" {
			poolID = "default"
		}
		pool := poolTracker[poolID]
		pool.current++
		if pool.current > pool.peak {
			pool.peak = pool.current
		}
		poolTracker[poolID] = pool
	}

	for _, e := range releaseEvents {
		poolID := e.Target
		if poolID == "" {
			poolID = "default"
		}
		pool := poolTracker[poolID]
		if pool.current > 0 {
			pool.current--
		}
		poolTracker[poolID] = pool
	}

	totalPeak := 0
	totalCurrent := 0
	for _, pool := range poolTracker {
		if pool.peak > totalPeak {
			totalPeak = pool.peak
		}
		totalCurrent += pool.current
	}

	stats.PeakConnections = totalPeak
	if len(poolTracker) > 0 {
		stats.AvgConnections = float64(totalCurrent) / float64(len(poolTracker))
	}

	return stats
}
