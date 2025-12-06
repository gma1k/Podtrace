package export

import (
	"encoding/csv"
	"fmt"
	"io"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
	"github.com/podtrace/podtrace/internal/diagnose/detector"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/validation"
)

type ExportData struct {
	Summary         map[string]interface{}   `json:"summary"`
	DNS             map[string]interface{}   `json:"dns,omitempty"`
	TCP             map[string]interface{}   `json:"tcp,omitempty"`
	Connections     map[string]interface{}   `json:"connections,omitempty"`
	FileSystem      map[string]interface{}   `json:"filesystem,omitempty"`
	CPU             map[string]interface{}   `json:"cpu,omitempty"`
	ProcessActivity []map[string]interface{} `json:"process_activity,omitempty"`
	PotentialIssues []string                 `json:"potential_issues,omitempty"`
}

type Diagnostician interface {
	GetEvents() []*events.Event
	FilterEvents(eventType events.EventType) []*events.Event
	CalculateRate(count int, duration time.Duration) float64
	StartTime() time.Time
	EndTime() time.Time
	ErrorRateThreshold() float64
	RTTSpikeThreshold() float64
	FSSlowThreshold() float64
}

func calculateRate(count int, duration time.Duration) float64 {
	if duration.Seconds() > 0 {
		return float64(count) / duration.Seconds()
	}
	return 0
}

func ExportJSON(d Diagnostician) ExportData {
	duration := d.EndTime().Sub(d.StartTime())
	allEvents := d.GetEvents()
	eventsPerSec := calculateRate(len(allEvents), duration)

	data := ExportData{
		Summary: map[string]interface{}{
			"total_events":      len(allEvents),
			"events_per_second": eventsPerSec,
			"start_time":        d.StartTime().Format(time.RFC3339),
			"end_time":          d.EndTime().Format(time.RFC3339),
			"duration_seconds":  duration.Seconds(),
		},
	}

	dnsEvents := d.FilterEvents(events.EventDNS)
	if len(dnsEvents) > 0 {
		avgLatency, maxLatency, errors, p50, p95, p99, topTargets := analyzer.AnalyzeDNS(dnsEvents)
		data.DNS = buildDNSExportData(dnsEvents, duration, avgLatency, maxLatency, errors, p50, p95, p99, topTargets)
	}

	tcpSendEvents := d.FilterEvents(events.EventTCPSend)
	tcpRecvEvents := d.FilterEvents(events.EventTCPRecv)
	if len(tcpSendEvents) > 0 || len(tcpRecvEvents) > 0 {
		allTCP := append(tcpSendEvents, tcpRecvEvents...)
		avgRTT, maxRTT, spikes, p50, p95, p99, errors, totalBytes, avgBytes, peakBytes := analyzer.AnalyzeTCP(allTCP, d.RTTSpikeThreshold())
		data.TCP = buildTCPExportData(tcpSendEvents, tcpRecvEvents, allTCP, duration, avgRTT, maxRTT, spikes, p50, p95, p99, errors, totalBytes, avgBytes, peakBytes)
	}

	connectEvents := d.FilterEvents(events.EventConnect)
	if len(connectEvents) > 0 {
		avgLatency, maxLatency, errors, p50, p95, p99, topTargets, errorBreakdown := analyzer.AnalyzeConnections(connectEvents)
		data.Connections = buildConnectionExportData(connectEvents, duration, avgLatency, maxLatency, errors, p50, p95, p99, topTargets, errorBreakdown)
	}

	writeEvents := d.FilterEvents(events.EventWrite)
	readEvents := d.FilterEvents(events.EventRead)
	fsyncEvents := d.FilterEvents(events.EventFsync)
	if len(writeEvents) > 0 || len(readEvents) > 0 || len(fsyncEvents) > 0 {
		allFS := append(append(writeEvents, readEvents...), fsyncEvents...)
		avgLatency, maxLatency, slowOps, p50, p95, p99, totalBytes, avgBytes := analyzer.AnalyzeFS(allFS, d.FSSlowThreshold())
		data.FileSystem = buildFSExportData(writeEvents, readEvents, fsyncEvents, avgLatency, maxLatency, slowOps, p50, p95, p99, totalBytes, avgBytes)
	}

	schedEvents := d.FilterEvents(events.EventSchedSwitch)
	if len(schedEvents) > 0 {
		avgBlock, maxBlock, p50, p95, p99 := analyzer.AnalyzeCPU(schedEvents)
		data.CPU = buildCPUExportData(schedEvents, avgBlock, maxBlock, p50, p95, p99)
	}

	pidActivity := tracker.AnalyzeProcessActivity(allEvents)
	for _, info := range pidActivity {
		data.ProcessActivity = append(data.ProcessActivity, map[string]interface{}{
			"pid":         info.Pid,
			"name":        info.Name,
			"event_count": info.Count,
			"percentage":  info.Percentage,
		})
	}

	issues := detector.DetectIssues(allEvents, d.ErrorRateThreshold(), d.RTTSpikeThreshold())
	data.PotentialIssues = issues

	return data
}

func buildDNSExportData(dnsEvents []*events.Event, duration time.Duration, avgLatency, maxLatency float64, errors int, p50, p95, p99 float64, topTargets []analyzer.TargetCount) map[string]interface{} {
	return map[string]interface{}{
		"total_lookups": len(dnsEvents),
		"rate_per_second": calculateRate(len(dnsEvents), duration),
		"avg_latency_ms": avgLatency,
		"max_latency_ms": maxLatency,
		"p50_ms":         p50,
		"p95_ms":         p95,
		"p99_ms":         p99,
		"errors":         errors,
		"error_rate": func() float64 {
			if len(dnsEvents) > 0 {
				return float64(errors) * float64(config.Percent100) / float64(len(dnsEvents))
			}
			return 0
		}(),
		"top_targets": topTargets,
	}
}

func buildTCPExportData(tcpSendEvents, tcpRecvEvents, allTCP []*events.Event, duration time.Duration, avgRTT, maxRTT float64, spikes int, p50, p95, p99 float64, errors int, totalBytes, avgBytes, peakBytes uint64) map[string]interface{} {
	errorRate := float64(0)
	if len(allTCP) > 0 {
		errorRate = float64(errors) * float64(config.Percent100) / float64(len(allTCP))
	}
	return map[string]interface{}{
		"send_operations":    len(tcpSendEvents),
		"receive_operations": len(tcpRecvEvents),
		"avg_rtt_ms":         avgRTT,
		"max_rtt_ms":         maxRTT,
		"p50_ms":             p50,
		"p95_ms":             p95,
		"p99_ms":             p99,
		"rtt_spikes":         spikes,
		"errors":             errors,
		"error_rate":         errorRate,
		"total_bytes":        totalBytes,
		"avg_bytes":          avgBytes,
		"peak_bytes":         peakBytes,
	}
}

func buildConnectionExportData(connectEvents []*events.Event, duration time.Duration, avgLatency, maxLatency float64, errors int, p50, p95, p99 float64, topTargets []analyzer.TargetCount, errorBreakdown map[int32]int) map[string]interface{} {
	return map[string]interface{}{
		"total_connections": len(connectEvents),
		"rate_per_second":    calculateRate(len(connectEvents), duration),
		"avg_latency_ms":     avgLatency,
		"max_latency_ms":     maxLatency,
		"p50_ms":             p50,
		"p95_ms":             p95,
		"p99_ms":             p99,
		"failed":             errors,
		"failure_rate":       float64(errors) * float64(config.Percent100) / float64(len(connectEvents)),
		"error_breakdown":    errorBreakdown,
		"top_targets":        topTargets,
	}
}

func buildFSExportData(writeEvents, readEvents, fsyncEvents []*events.Event, avgLatency, maxLatency float64, slowOps int, p50, p95, p99 float64, totalBytes, avgBytes uint64) map[string]interface{} {
	return map[string]interface{}{
		"write_operations": len(writeEvents),
		"read_operations":  len(readEvents),
		"fsync_operations": len(fsyncEvents),
		"avg_latency_ms":   avgLatency,
		"max_latency_ms":   maxLatency,
		"p50_ms":           p50,
		"p95_ms":           p95,
		"p99_ms":           p99,
		"slow_operations":  slowOps,
		"total_bytes":      totalBytes,
		"avg_bytes":        avgBytes,
	}
}

func buildCPUExportData(schedEvents []*events.Event, avgBlock, maxBlock, p50, p95, p99 float64) map[string]interface{} {
	return map[string]interface{}{
		"thread_switches":   len(schedEvents),
		"avg_block_time_ms": avgBlock,
		"max_block_time_ms": maxBlock,
		"p50_ms":            p50,
		"p95_ms":            p95,
		"p99_ms":            p99,
	}
}

func ExportCSV(d Diagnostician, w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{"timestamp", "pid", "process_name", "type", "latency_ms", "error", "target"}
	if err := writer.Write(header); err != nil {
		return err
	}

	allEvents := d.GetEvents()
	for _, event := range allEvents {
		if event == nil {
			continue
		}
		record := []string{
			fmt.Sprintf("%d", event.Timestamp),
			fmt.Sprintf("%d", event.PID),
			validation.SanitizeCSVField(event.ProcessName),
			validation.SanitizeCSVField(event.TypeString()),
			fmt.Sprintf("%.2f", float64(event.LatencyNS)/float64(config.NSPerMS)),
			fmt.Sprintf("%d", event.Error),
			validation.SanitizeCSVField(event.Target),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

