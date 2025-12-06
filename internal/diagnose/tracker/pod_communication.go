package tracker

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

type PodCommunication struct {
	SourcePod      string
	TargetPod      string
	TargetService  string
	Namespace      string
	ConnectionCount int
	TotalBytes     uint64
	TotalLatency   time.Duration
	ErrorCount     int
	LastSeen       time.Time
	FirstSeen      time.Time
}

type PodCommunicationTracker struct {
	mu             sync.RWMutex
	communications map[string]*PodCommunication
	sourcePod      string
	sourceNamespace string
}

func NewPodCommunicationTracker(sourcePod, sourceNamespace string) *PodCommunicationTracker {
	return &PodCommunicationTracker{
		communications:  make(map[string]*PodCommunication),
		sourcePod:       sourcePod,
		sourceNamespace: sourceNamespace,
	}
}

func (pct *PodCommunicationTracker) ProcessEvent(event *events.Event, k8sContext interface{}) {
	if event == nil {
		return
	}

	if !isNetworkEvent(event.Type) {
		return
	}

	var targetPod, targetService, targetNamespace string

	if ctx, ok := k8sContext.(map[string]interface{}); ok {
		if pod, ok := ctx["target_pod"].(string); ok {
			targetPod = pod
		}
		if svc, ok := ctx["target_service"].(string); ok {
			targetService = svc
		}
		if ns, ok := ctx["target_namespace"].(string); ok {
			targetNamespace = ns
		}
	}

	if targetPod == "" && targetService == "" {
		return
	}

	key := pct.getKey(targetPod, targetService, targetNamespace)
	timestamp := event.TimestampTime()

	pct.mu.Lock()
	defer pct.mu.Unlock()

	comm, exists := pct.communications[key]
	if !exists {
		comm = &PodCommunication{
			SourcePod:      pct.sourcePod,
			TargetPod:      targetPod,
			TargetService:  targetService,
			Namespace:      targetNamespace,
			FirstSeen:      timestamp,
			LastSeen:       timestamp,
		}
		pct.communications[key] = comm
	}

	comm.LastSeen = timestamp
	comm.ConnectionCount++

	if event.Bytes > 0 {
		comm.TotalBytes += event.Bytes
	}

	if event.LatencyNS > 0 {
		comm.TotalLatency += event.Latency()
	}

	if event.Error != 0 {
		comm.ErrorCount++
	}
}

func (pct *PodCommunicationTracker) getKey(targetPod, targetService, namespace string) string {
	if targetService != "" {
		return fmt.Sprintf("%s->%s/%s", pct.sourcePod, targetService, namespace)
	}
	if targetPod != "" {
		return fmt.Sprintf("%s->%s/%s", pct.sourcePod, targetPod, namespace)
	}
	return ""
}

func (pct *PodCommunicationTracker) GetSummary() []PodCommunicationSummary {
	pct.mu.RLock()
	defer pct.mu.RUnlock()

	var summaries []PodCommunicationSummary
	for _, comm := range pct.communications {
		avgLatency := time.Duration(0)
		if comm.ConnectionCount > 0 {
			avgLatency = comm.TotalLatency / time.Duration(comm.ConnectionCount)
		}

		target := comm.TargetService
		if target == "" {
			target = comm.TargetPod
		}

		summaries = append(summaries, PodCommunicationSummary{
			Target:          target,
			Namespace:       comm.Namespace,
			ConnectionCount: comm.ConnectionCount,
			TotalBytes:      comm.TotalBytes,
			AvgLatency:      avgLatency,
			ErrorCount:      comm.ErrorCount,
			LastSeen:        comm.LastSeen,
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].ConnectionCount > summaries[j].ConnectionCount
	})

	return summaries
}

type PodCommunicationSummary struct {
	Target          string
	Namespace       string
	ConnectionCount int
	TotalBytes      uint64
	AvgLatency      time.Duration
	ErrorCount      int
	LastSeen        time.Time
}

func isNetworkEvent(eventType events.EventType) bool {
	return eventType == events.EventConnect ||
		eventType == events.EventTCPSend ||
		eventType == events.EventTCPRecv ||
		eventType == events.EventUDPSend ||
		eventType == events.EventUDPRecv
}

func GeneratePodCommunicationReport(summaries []PodCommunicationSummary) string {
	if len(summaries) == 0 {
		return ""
	}

	report := "Pod-to-Pod Communication:\n"
	report += fmt.Sprintf("  Total pod/service pairs: %d\n", len(summaries))
	report += "  Top communications:\n"

	maxDisplay := config.MaxConnectionTargets
	if len(summaries) < maxDisplay {
		maxDisplay = len(summaries)
	}

	for i := 0; i < maxDisplay; i++ {
		summary := summaries[i]
		report += fmt.Sprintf("    - %s (namespace: %s):\n", summary.Target, summary.Namespace)
		report += fmt.Sprintf("        Connections: %d\n", summary.ConnectionCount)
		if summary.TotalBytes > 0 {
			report += fmt.Sprintf("        Total bytes: %s\n", formatBytes(summary.TotalBytes))
		}
		if summary.AvgLatency > 0 {
			report += fmt.Sprintf("        Avg latency: %.2fms\n", float64(summary.AvgLatency.Nanoseconds())/float64(config.NSPerMS))
		}
		if summary.ErrorCount > 0 {
			report += fmt.Sprintf("        Errors: %d\n", summary.ErrorCount)
		}
		report += fmt.Sprintf("        Last seen: %s\n", summary.LastSeen.Format("15:04:05.000"))
	}

	report += "\n"
	return report
}

func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

