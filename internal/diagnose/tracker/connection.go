package tracker

import (
	"fmt"
	"sort"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

type ConnectionInfo struct {
	Target       string
	ConnectTime  time.Time
	SendCount    int
	RecvCount    int
	TotalLatency time.Duration
	LastActivity time.Time
}

type ConnectionTracker struct {
	connections map[string]*ConnectionInfo
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string]*ConnectionInfo),
	}
}

func (ct *ConnectionTracker) ProcessEvent(event *events.Event) {
	if event == nil {
		return
	}

	switch event.Type {
	case events.EventConnect:
		if event.Error == 0 && event.Target != "" {
			conn := &ConnectionInfo{
				Target:       event.Target,
				ConnectTime:  event.TimestampTime(),
				LastActivity: event.TimestampTime(),
			}
			ct.connections[event.Target] = conn
		}

	case events.EventTCPSend, events.EventTCPRecv:
		if event.Target != "" {
			if conn, exists := ct.connections[event.Target]; exists {
				if event.Type == events.EventTCPSend {
					conn.SendCount++
				} else {
					conn.RecvCount++
				}
				conn.TotalLatency += event.Latency()
				conn.LastActivity = event.TimestampTime()
			} else {
				conn := &ConnectionInfo{
					Target:       event.Target,
					ConnectTime:  event.TimestampTime(),
					LastActivity: event.TimestampTime(),
				}
				if event.Type == events.EventTCPSend {
					conn.SendCount = 1
				} else {
					conn.RecvCount = 1
				}
				conn.TotalLatency = event.Latency()
				ct.connections[event.Target] = conn
			}
		}
	}
}

func (ct *ConnectionTracker) GetConnectionSummary() []ConnectionSummary {
	var summaries []ConnectionSummary
	for target, conn := range ct.connections {
		avgLatency := time.Duration(0)
		totalOps := conn.SendCount + conn.RecvCount
		if totalOps > 0 {
			avgLatency = conn.TotalLatency / time.Duration(totalOps)
		}
		summaries = append(summaries, ConnectionSummary{
			Target:       target,
			ConnectTime:  conn.ConnectTime,
			SendCount:    conn.SendCount,
			RecvCount:    conn.RecvCount,
			TotalOps:     totalOps,
			AvgLatency:   avgLatency,
			LastActivity: conn.LastActivity,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].TotalOps > summaries[j].TotalOps
	})
	return summaries
}

type ConnectionSummary struct {
	Target       string
	ConnectTime  time.Time
	SendCount    int
	RecvCount    int
	TotalOps     int
	AvgLatency   time.Duration
	LastActivity time.Time
}

func GenerateConnectionCorrelation(events []*events.Event) string {
	tracker := NewConnectionTracker()
	for _, event := range events {
		tracker.ProcessEvent(event)
	}

	summaries := tracker.GetConnectionSummary()
	if len(summaries) == 0 {
		return ""
	}

	report := "Connection Correlation:\n"
	report += fmt.Sprintf("  Active connections: %d\n", len(summaries))
	report += "  Top connections by activity:\n"
	for i, summary := range summaries {
		if i >= config.MaxConnectionTargets {
			break
		}
		report += fmt.Sprintf("    - %s:\n", summary.Target)
		report += fmt.Sprintf("        Connect: %s\n", summary.ConnectTime.Format("15:04:05"))
		report += fmt.Sprintf("        Operations: %d send, %d recv (total: %d)\n", summary.SendCount, summary.RecvCount, summary.TotalOps)
		report += fmt.Sprintf("        Avg latency: %.2fms\n", float64(summary.AvgLatency.Nanoseconds())/1e6)
		report += fmt.Sprintf("        Last activity: %s\n", summary.LastActivity.Format("15:04:05.000"))
	}
	report += "\n"
	return report
}
