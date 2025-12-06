package diagnose

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/export"
	"github.com/podtrace/podtrace/internal/diagnose/profiling"
	"github.com/podtrace/podtrace/internal/diagnose/report"
	"github.com/podtrace/podtrace/internal/diagnose/stacktrace"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
)

func (d *Diagnostician) ExportJSON() ExportData {
	return export.ExportJSON(d)
}

func (d *Diagnostician) ExportCSV(w io.Writer) error {
	return export.ExportCSV(d, w)
}

type ExportData = export.ExportData

type Diagnostician struct {
	mu                 sync.RWMutex
	events             []*events.Event
	startTime          time.Time
	endTime            time.Time
	errorRateThreshold float64
	rttSpikeThreshold  float64
	fsSlowThreshold    float64
	maxEvents          int
	eventCount         int
	droppedEvents      int
}

func NewDiagnostician() *Diagnostician {
	return &Diagnostician{
		events:             make([]*events.Event, 0),
		startTime:          time.Now(),
		errorRateThreshold: config.DefaultErrorRateThreshold,
		rttSpikeThreshold:  config.DefaultRTTThreshold,
		fsSlowThreshold:    config.DefaultFSSlowThreshold,
		maxEvents:          config.MaxEvents,
	}
}

func NewDiagnosticianWithThresholds(errorRate, rttSpike, fsSlow float64) *Diagnostician {
	return &Diagnostician{
		events:             make([]*events.Event, 0),
		startTime:          time.Now(),
		errorRateThreshold: errorRate,
		rttSpikeThreshold:  rttSpike,
		fsSlowThreshold:    fsSlow,
		maxEvents:          config.MaxEvents,
	}
}

func (d *Diagnostician) AddEvent(event *events.Event) {
	if event == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.eventCount++
	if len(d.events) >= d.maxEvents {
		if shouldSampleEvent(event, d.eventCount) {
			d.events = append(d.events, event)
		} else {
			d.droppedEvents++
		}
		if d.droppedEvents%config.DroppedEventsLogRate == 0 {
			logger.Warn("Event limit reached, sampling events",
				zap.Int("max_events", d.maxEvents),
				zap.Int("dropped", d.droppedEvents))
		}
		return
	}

	d.events = append(d.events, event)
}

func (d *Diagnostician) GetEvents() []*events.Event {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]*events.Event, len(d.events))
	copy(result, d.events)
	return result
}

func (d *Diagnostician) Finish() {
	d.endTime = time.Now()
}

func (d *Diagnostician) CalculateRate(count int, duration time.Duration) float64 {
	if duration.Seconds() > 0 {
		return float64(count) / duration.Seconds()
	}
	return 0
}

func (d *Diagnostician) FilterEvents(eventType events.EventType) []*events.Event {
	allEvents := d.GetEvents()
	var filtered []*events.Event
	for _, e := range allEvents {
		if e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (d *Diagnostician) StartTime() time.Time {
	return d.startTime
}

func (d *Diagnostician) EndTime() time.Time {
	return d.endTime
}

func (d *Diagnostician) ErrorRateThreshold() float64 {
	return d.errorRateThreshold
}

func (d *Diagnostician) RTTSpikeThreshold() float64 {
	return d.rttSpikeThreshold
}

func (d *Diagnostician) FSSlowThreshold() float64 {
	return d.fsSlowThreshold
}

func (d *Diagnostician) GenerateReport() string {
	return d.GenerateReportWithContext(context.Background())
}

func (d *Diagnostician) GenerateReportWithContext(ctx context.Context) string {
	allEvents := d.GetEvents()
	if len(allEvents) == 0 {
		return "No events collected during the diagnostic period.\n"
	}

	select {
	case <-ctx.Done():
		return fmt.Sprintf("Report generation cancelled: %v\n", ctx.Err())
	default:
	}

	duration := d.endTime.Sub(d.startTime)
	var result string

	result += report.GenerateSummarySection(d, duration)
	result += report.GenerateDNSSection(d, duration)
	result += report.GenerateTCPSection(d, duration)
	result += report.GenerateConnectionSection(d, duration)
	result += report.GenerateFileSystemSection(d, duration)
	result += report.GenerateUDPSection(d, duration)
	result += report.GenerateHTTPSection(d, duration)
	result += report.GenerateCPUSection(d, duration)
	result += report.GenerateTCPStateSection(d, duration)
	result += report.GenerateMemorySection(d, duration)
	result += profiling.GenerateCPUUsageReport(allEvents, duration)
	result += stacktrace.GenerateStackTraceSectionWithContext(d, ctx)
	result += report.GenerateSyscallSection(d, duration)
	result += report.GenerateApplicationTracing(d, duration)
	result += tracker.GenerateConnectionCorrelation(allEvents)
	result += report.GenerateIssuesSection(d)

	return result
}
