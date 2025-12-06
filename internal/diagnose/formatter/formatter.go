package formatter

import (
	"fmt"
	"sort"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
)

func SectionHeader(title string) string {
	return fmt.Sprintf("%s Statistics:\n", title)
}

func TotalWithRate(label string, count int, rate float64) string {
	return fmt.Sprintf("  Total %s: %d (%.1f/sec)\n", label, count, rate)
}

func LatencyMetrics(avgLatency, maxLatency float64) string {
	return fmt.Sprintf("  Average latency: %.2fms\n  Max latency: %.2fms\n", avgLatency, maxLatency)
}

func Percentiles(p50, p95, p99 float64) string {
	return fmt.Sprintf("  Percentiles: P50=%.2fms, P95=%.2fms, P99=%.2fms\n", p50, p95, p99)
}

func ErrorRate(errors, total int) string {
	if total == 0 {
		return fmt.Sprintf("  Errors: %d (0.0%%)\n", errors)
	}
	return fmt.Sprintf("  Errors: %d (%.1f%%)\n", errors, float64(errors)*float64(config.Percent100)/float64(total))
}

func TopTargets(targets []analyzer.TargetCount, limit int, headerLabel, countLabel string) string {
	if len(targets) == 0 {
		return ""
	}
	var result string
	result += fmt.Sprintf("  Top %s:\n", headerLabel)
	for i, target := range targets {
		if i >= limit {
			break
		}
		result += fmt.Sprintf("    - %s (%d %s)\n", target.Target, target.Count, countLabel)
	}
	return result
}

func BytesSection(totalBytes, avgBytes uint64, throughput uint64) string {
	if totalBytes == 0 {
		return ""
	}
	var result string
	result += fmt.Sprintf("  Total bytes transferred: %s\n", analyzer.FormatBytes(totalBytes))
	result += fmt.Sprintf("  Average bytes per operation: %s\n", analyzer.FormatBytes(avgBytes))
	if throughput > 0 {
		result += fmt.Sprintf("  Average throughput: %s/sec\n", analyzer.FormatBytes(throughput))
	}
	return result
}

func Rate(count int, duration float64) string {
	if duration > 0 {
		return fmt.Sprintf(" (%.1f/sec)", float64(count)/duration)
	}
	return ""
}

func TopItems(items map[string]int, limit int, headerLabel, itemLabel string) string {
	if len(items) == 0 {
		return ""
	}
	type itemCount struct {
		name  string
		count int
	}
	var itemCounts []itemCount
	for name, count := range items {
		itemCounts = append(itemCounts, itemCount{name: name, count: count})
	}
	sort.Slice(itemCounts, func(i, j int) bool {
		return itemCounts[i].count > itemCounts[j].count
	})
	var result string
	result += fmt.Sprintf("  Top %s:\n", headerLabel)
	for i, ic := range itemCounts {
		if i >= limit {
			break
		}
		result += fmt.Sprintf("    - %s (%d %s)\n", ic.name, ic.count, itemLabel)
	}
	return result
}

