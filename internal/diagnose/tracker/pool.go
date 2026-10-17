package tracker

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/sanitize"
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
		releaseRatio := 0.0
		if pool.AcquireCount > 0 {
			releaseRatio = float64(pool.ReleaseCount) / float64(pool.AcquireCount)
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
			ReleaseRatio:   releaseRatio,
			AvgWaitTime:    avgWaitTime,
			MaxWaitTime:    pool.MaxWaitTime,
			LastAcquire:    pool.LastAcquire,
			LastRelease:    pool.LastRelease,
			LastExhausted:  pool.LastExhausted,
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].AcquireCount != summaries[j].AcquireCount {
			return summaries[i].AcquireCount > summaries[j].AcquireCount
		}
		return summaries[i].PoolID < summaries[j].PoolID
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
	ReleaseRatio   float64
	AvgWaitTime    time.Duration
	MaxWaitTime    time.Duration
	LastAcquire    time.Time
	LastRelease    time.Time
	LastExhausted  time.Time
}

func GetPoolSummaryFromEvents(acquireEvents, releaseEvents, exhaustedEvents []*events.Event) []PoolSummary {
	merged := make([]*events.Event, 0, len(acquireEvents)+len(releaseEvents)+len(exhaustedEvents))
	merged = append(merged, acquireEvents...)
	merged = append(merged, releaseEvents...)
	merged = append(merged, exhaustedEvents...)
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i] == nil || merged[j] == nil {
			return merged[j] != nil
		}
		return merged[i].Timestamp < merged[j].Timestamp
	})

	tracker := NewPoolTracker()
	for _, event := range merged {
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
		report += fmt.Sprintf("    - %s:\n", sanitize.Terminal(summary.PoolID))
		report += fmt.Sprintf("        Acquires: %d, Releases: %d\n", summary.AcquireCount, summary.ReleaseCount)
		report += fmt.Sprintf("        Release ratio: %.2f%% (releases/acquires)\n", summary.ReleaseRatio*100)
		report += fmt.Sprintf("        Current connections: %d (peak: %d)\n", summary.CurrentConns, summary.MaxConns)

		healthStatus := determinePoolHealthFromSummary(summary)
		report += fmt.Sprintf("        Status: %s\n", healthStatus)

		if summary.ExhaustedCount > 0 {
			report += fmt.Sprintf("        Exhaustion events: %d\n", summary.ExhaustedCount)
			// Named as in the diagnose report: the client-library probe
			// timestamps a connection on acquire and never refreshes it, so
			// this is the connection's age when a query ran, not queue time.
			report += fmt.Sprintf("        Avg connection age at query: %.2fms\n", float64(summary.AvgWaitTime.Nanoseconds())/float64(config.NSPerMS))
			report += fmt.Sprintf("        Max connection age at query: %.2fms\n", float64(summary.MaxWaitTime.Nanoseconds())/float64(config.NSPerMS))
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
		if summary.AcquireCount == 0 {
			return "CRITICAL - Pool exhausted with no successful acquisitions"
		}
		exhaustionRate := float64(summary.ExhaustedCount) / float64(summary.AcquireCount)
		if exhaustionRate > 0.1 {
			return "CRITICAL - High pool exhaustion rate (>10%)"
		} else if exhaustionRate > 0.05 {
			return "WARNING - Moderate pool exhaustion rate (>5%)"
		}
	}

	if summary.AcquireCount > 0 && summary.ReleaseRatio < 0.5 {
		return "WARNING - Under half of acquired connections released (<50%, possible leak)"
	}

	if summary.MaxWaitTime > 1000*time.Millisecond {
		return "WARNING - High wait times detected"
	}

	return "OK - Pool operating normally"
}
