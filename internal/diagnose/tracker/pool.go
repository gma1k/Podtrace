package tracker

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

type PoolInfo struct {
	PoolID         string
	MaxConns       int
	CurrentConns   int
	AcquireCount   int
	ReleaseCount   int
	ExhaustedCount int
	TotalWaitTime  time.Duration
	MaxWaitTime    time.Duration
	LastAcquire    time.Time
	LastRelease    time.Time
	LastExhausted  time.Time
}

type PoolTracker struct {
	mu    sync.RWMutex
	pools map[string]*PoolInfo
}

func NewPoolTracker() *PoolTracker {
	return &PoolTracker{
		pools: make(map[string]*PoolInfo),
	}
}

func (pt *PoolTracker) ProcessEvent(event *events.Event) {
	if event == nil {
		return
	}

	pt.mu.Lock()
	defer pt.mu.Unlock()

	poolID := event.Target
	if poolID == "" {
		poolID = "default"
	}

	pool, exists := pt.pools[poolID]
	if !exists {
		pool = &PoolInfo{
			PoolID: poolID,
		}
		pt.pools[poolID] = pool
	}

	timestamp := event.TimestampTime()

	switch event.Type {
	case events.EventPoolAcquire:
		pool.AcquireCount++
		pool.CurrentConns++
		pool.LastAcquire = timestamp
		if pool.CurrentConns > pool.MaxConns {
			pool.MaxConns = pool.CurrentConns
		}

	case events.EventPoolRelease:
		pool.ReleaseCount++
		if pool.CurrentConns > 0 {
			pool.CurrentConns--
		}
		pool.LastRelease = timestamp

	case events.EventPoolExhausted:
		pool.ExhaustedCount++
		waitTime := event.Latency()
		pool.TotalWaitTime += waitTime
		if waitTime > pool.MaxWaitTime {
			pool.MaxWaitTime = waitTime
		}
		pool.LastExhausted = timestamp
	}
}

func (pt *PoolTracker) GetPoolSummary() []PoolSummary {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	var summaries []PoolSummary
	for _, pool := range pt.pools {
		reuseRate := 0.0
		if pool.AcquireCount > 0 {
			reuseRate = float64(pool.ReleaseCount) / float64(pool.AcquireCount)
		}

		avgWaitTime := time.Duration(0)
		if pool.ExhaustedCount > 0 {
			avgWaitTime = pool.TotalWaitTime / time.Duration(pool.ExhaustedCount)
		}

		summaries = append(summaries, PoolSummary{
			PoolID:         pool.PoolID,
			MaxConns:       pool.MaxConns,
			CurrentConns:   pool.CurrentConns,
			AcquireCount:   pool.AcquireCount,
			ReleaseCount:   pool.ReleaseCount,
			ExhaustedCount: pool.ExhaustedCount,
			ReuseRate:      reuseRate,
			AvgWaitTime:    avgWaitTime,
			MaxWaitTime:    pool.MaxWaitTime,
			LastAcquire:    pool.LastAcquire,
			LastRelease:    pool.LastRelease,
			LastExhausted:  pool.LastExhausted,
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].AcquireCount > summaries[j].AcquireCount
	})

	return summaries
}

type PoolSummary struct {
	PoolID         string
	MaxConns       int
	CurrentConns   int
	AcquireCount   int
	ReleaseCount   int
	ExhaustedCount int
	ReuseRate      float64
	AvgWaitTime    time.Duration
	MaxWaitTime    time.Duration
	LastAcquire    time.Time
	LastRelease    time.Time
	LastExhausted  time.Time
}

func GetPoolSummaryFromEvents(acquireEvents, releaseEvents, exhaustedEvents []*events.Event) []PoolSummary {
	tracker := NewPoolTracker()
	for _, event := range acquireEvents {
		tracker.ProcessEvent(event)
	}
	for _, event := range releaseEvents {
		tracker.ProcessEvent(event)
	}
	for _, event := range exhaustedEvents {
		tracker.ProcessEvent(event)
	}
	return tracker.GetPoolSummary()
}

func GeneratePoolCorrelation(events []*events.Event) string {
	if len(events) == 0 {
		return ""
	}

	tracker := NewPoolTracker()
	for _, event := range events {
		tracker.ProcessEvent(event)
	}

	summaries := tracker.GetPoolSummary()
	if len(summaries) == 0 {
		return ""
	}

	report := "Connection Pool Tracking:\n"
	report += fmt.Sprintf("  Active pools: %d\n", len(summaries))
	report += "  Pool statistics:\n"
	for i, summary := range summaries {
		if i >= config.MaxConnectionTargets {
			break
		}
		report += fmt.Sprintf("    - %s:\n", summary.PoolID)
		report += fmt.Sprintf("        Acquires: %d, Releases: %d\n", summary.AcquireCount, summary.ReleaseCount)
		report += fmt.Sprintf("        Reuse rate: %.2f%%\n", summary.ReuseRate*100)
		report += fmt.Sprintf("        Current connections: %d (peak: %d)\n", summary.CurrentConns, summary.MaxConns)

		healthStatus := determinePoolHealthFromSummary(summary)
		report += fmt.Sprintf("        Status: %s\n", healthStatus)

		if summary.ExhaustedCount > 0 {
			report += fmt.Sprintf("        Exhaustion events: %d\n", summary.ExhaustedCount)
			report += fmt.Sprintf("        Avg wait time: %.2fms\n", float64(summary.AvgWaitTime.Nanoseconds())/float64(config.NSPerMS))
			report += fmt.Sprintf("        Max wait time: %.2fms\n", float64(summary.MaxWaitTime.Nanoseconds())/float64(config.NSPerMS))
		}
		if !summary.LastAcquire.IsZero() {
			report += fmt.Sprintf("        Last acquire: %s\n", summary.LastAcquire.Format("15:04:05.000"))
		}
	}
	report += "\n"
	return report
}

func determinePoolHealthFromSummary(summary PoolSummary) string {
	if summary.ExhaustedCount > 0 {
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
