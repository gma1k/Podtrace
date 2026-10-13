package diagnose

import (
	"context"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/analysis/criticalpath"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/analyzer"
	"github.com/gma1k/podtrace/internal/diagnose/correlator"
	"github.com/gma1k/podtrace/internal/diagnose/export"
	"github.com/gma1k/podtrace/internal/diagnose/profiling"
	"github.com/gma1k/podtrace/internal/diagnose/report"
	"github.com/gma1k/podtrace/internal/diagnose/stacktrace"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/logger"
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
	enrichedEvents     []map[string]interface{}
	startTime          time.Time
	endTime            time.Time
	errorRateThreshold float64
	rttSpikeThreshold  float64
	fsSlowThreshold    float64
	maxEvents          int
	eventCount         int
	droppedEvents      int
	evHead             int
	wrapped            bool
	podCommTracker     *tracker.PodCommunicationTracker
	errorCorrelator    *correlator.ErrorCorrelator
	criticalPath       *criticalpath.Collector
	fsKernelRows       []kernelagg.Row
	processCPUNS       map[uint32]uint64
	sourcePod          string
	sourceNamespace    string
}

func NewDiagnostician() *Diagnostician {
	return &Diagnostician{
		events:             make([]*events.Event, 0),
		enrichedEvents:     make([]map[string]interface{}, 0),
		startTime:          time.Now(),
		errorRateThreshold: config.DefaultErrorRateThreshold,
		rttSpikeThreshold:  config.DefaultRTTThreshold,
		fsSlowThreshold:    config.DefaultFSSlowThreshold,
		maxEvents:          config.MaxEvents,
		errorCorrelator:    correlator.NewErrorCorrelator(30 * time.Second),
		criticalPath:       criticalpath.New(),
	}
}

func NewDiagnosticianWithThresholds(errorRate, rttSpike, fsSlow float64) *Diagnostician {
	return &Diagnostician{
		events:             make([]*events.Event, 0),
		enrichedEvents:     make([]map[string]interface{}, 0),
		startTime:          time.Now(),
		errorRateThreshold: errorRate,
		rttSpikeThreshold:  rttSpike,
		fsSlowThreshold:    fsSlow,
		maxEvents:          config.MaxEvents,
		errorCorrelator:    correlator.NewErrorCorrelator(30 * time.Second),
		criticalPath:       criticalpath.New(),
	}
}

func NewDiagnosticianWithK8s(sourcePod, sourceNamespace string) *Diagnostician {
	d := NewDiagnostician()
	d.sourcePod = sourcePod
	d.sourceNamespace = sourceNamespace
	d.podCommTracker = tracker.NewPodCommunicationTracker(sourcePod, sourceNamespace)
	return d
}

func NewDiagnosticianWithK8sAndThresholds(sourcePod, sourceNamespace string, errorRate, rttSpike, fsSlow float64) *Diagnostician {
	d := NewDiagnosticianWithThresholds(errorRate, rttSpike, fsSlow)
	d.sourcePod = sourcePod
	d.sourceNamespace = sourceNamespace
	d.podCommTracker = tracker.NewPodCommunicationTracker(sourcePod, sourceNamespace)
	return d
}

func (d *Diagnostician) AddEvent(event *events.Event) {
	d.AddEventWithContext(event, nil)
}

func (d *Diagnostician) AddEventWithContext(event *events.Event, k8sContext map[string]interface{}) {
	if event == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.eventCount++

	if d.podCommTracker != nil && k8sContext != nil {
		d.podCommTracker.ProcessEvent(event, k8sContext)
	}
	if d.errorCorrelator != nil {
		d.errorCorrelator.AddEvent(event, k8sContext)
	}
	d.criticalPath.Feed(event)

	if len(d.events) < d.maxEvents {
		d.events = append(d.events, event)
		d.enrichedEvents = append(d.enrichedEvents, k8sContext)
		return
	}

	if !shouldSampleEvent(event, d.eventCount) {
		d.droppedEvents++
		if d.droppedEvents == 1 || d.droppedEvents%config.DroppedEventsLogRate == 0 {
			logger.Warn("Event buffer at capacity; sampling and evicting oldest events",
				zap.Int("max_events", d.maxEvents),
				zap.Int("dropped", d.droppedEvents))
		}
		return
	}
	d.events[d.evHead] = event
	d.enrichedEvents[d.evHead] = k8sContext
	d.evHead = (d.evHead + 1) % d.maxEvents
	d.wrapped = true
}

func (d *Diagnostician) GetEvents() []*events.Event {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]*events.Event, len(d.events))
	if !d.wrapped {
		copy(result, d.events)
	} else {
		n := copy(result, d.events[d.evHead:])
		copy(result[n:], d.events[:d.evHead])
	}
	return result
}

// AddFastFilesystemOps keeps the kernel's counts of the filesystem
// operations too fast to become events.
func (d *Diagnostician) AddFastFilesystemOps(rows []kernelagg.Row) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fsKernelRows = append(d.fsKernelRows, rows...)
}

// AddProcessCPU keeps the kernel's on-CPU nanoseconds per process ID.
func (d *Diagnostician) AddProcessCPU(times map[uint32]uint64) {
	if len(times) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.processCPUNS == nil {
		d.processCPUNS = make(map[uint32]uint64, len(times))
	}
	for pid, ns := range times {
		d.processCPUNS[pid] += ns
	}
}

// ProcessCPU returns a copy of what AddProcessCPU kept, so a per-pod
// diagnostician can be given it.
func (d *Diagnostician) ProcessCPU() map[uint32]uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.processCPUNS) == 0 {
		return nil
	}
	out := make(map[uint32]uint64, len(d.processCPUNS))
	for pid, ns := range d.processCPUNS {
		out[pid] = ns
	}
	return out
}

// FastFilesystemRows returns the rows AddFastFilesystemOps kept, so a per-pod
// diagnostician can be given them.
func (d *Diagnostician) FastFilesystemRows() []kernelagg.Row {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]kernelagg.Row(nil), d.fsKernelRows...)
}

// FastFilesystemOps sums the kernel's counts for the cgroups this
// diagnostician's events came from, so each pod's report counts its own.
func (d *Diagnostician) FastFilesystemOps() analyzer.FSKernelCounts {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.fsKernelRows) == 0 {
		return nil
	}
	own := make(map[uint64]struct{})
	for _, e := range d.events {
		if e != nil && e.CgroupID != 0 {
			own[e.CgroupID] = struct{}{}
		}
	}
	out := analyzer.FSKernelCounts{}
	for _, r := range d.fsKernelRows {
		if _, ok := own[r.Key.CgroupID]; !ok {
			continue
		}
		typ := events.EventType(r.Key.EventType)
		switch typ {
		case events.EventRead, events.EventWrite, events.EventFsync:
		default:
			continue
		}
		c := out[typ]
		c.Count += r.Value.Count
		c.SumNS += r.Value.SumNS
		c.Bytes += r.Value.Bytes
		if c.Buckets == nil {
			c.Buckets = map[float64]uint64{}
		}
		c.Buckets[kernelBucketUpperMs(r.Key.Bucket)] += r.Value.Count
		out[typ] = c
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// kernelBucketUpperMs is a kernel latency bucket's upper bound in
// milliseconds.
func kernelBucketUpperMs(bucket uint16) float64 {
	return math.Exp2(float64(kernelagg.NativeIndex(bucket))/float64(uint(1)<<kernelagg.Schema)) * 1000
}

// CriticalPath returns where the requests served during collection spent
// their time.
func (d *Diagnostician) CriticalPath() criticalpath.Summary {
	return d.criticalPath.Summary()
}

func (d *Diagnostician) Finish() {
	d.endTime = time.Now()
}

// EventContexts returns the per-event enrichment contexts, index-aligned with
// GetEvents().
func (d *Diagnostician) EventContexts() []map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]map[string]interface{}, len(d.enrichedEvents))
	if !d.wrapped {
		copy(result, d.enrichedEvents)
	} else {
		n := copy(result, d.enrichedEvents[d.evHead:])
		copy(result[n:], d.enrichedEvents[:d.evHead])
	}
	return result
}

// SetTimeWindow overrides the observation window.
func (d *Diagnostician) SetTimeWindow(start, end time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.startTime = start
	d.endTime = end
}

func (d *Diagnostician) CalculateRate(count int, duration time.Duration) float64 {
	if duration.Seconds() > 0 {
		return float64(count) / duration.Seconds()
	}
	return 0
}

// FilterEvents returns the events of a given type.
func (d *Diagnostician) FilterEvents(eventType events.EventType) []*events.Event {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var filtered []*events.Event
	match := func(e *events.Event) {
		if e != nil && e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	if !d.wrapped {
		for _, e := range d.events {
			match(e)
		}
		return filtered
	}
	for _, e := range d.events[d.evHead:] {
		match(e)
	}
	for _, e := range d.events[:d.evHead] {
		match(e)
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
	ctx, cancel := context.WithTimeout(context.Background(), config.ReportGenerationTimeout)
	defer cancel()
	return d.GenerateReportWithContext(ctx)
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
	result += report.GenerateSecuritySection(d)
	result += report.GenerateCgroupScopeSection(d)
	result += report.GenerateDNSSection(d, duration)
	result += report.GenerateTCPSection(d, duration)
	result += report.GenerateTLSSection(d, duration)
	result += report.GenerateConnectionSection(d, duration)
	result += report.GenerateFileSystemSection(d, duration)
	result += report.GenerateUDPSection(d, duration)
	result += report.GenerateHTTPSection(d, duration)
	result += report.GenerateHTTP3Section(d, duration)
	result += report.GenerateCPUSection(d, duration)
	result += report.GenerateTCPStateSection(d, duration)
	result += report.GenerateMemorySection(d, duration)
	result += report.GenerateResourceSection(d)
	result += report.GeneratePoolSection(d, duration)
	result += profiling.GenerateProcessCPUReport(allEvents, duration, d.ProcessCPU())
	result += stacktrace.GenerateStackTraceSectionWithContext(d, ctx)
	result += report.GenerateSyscallSection(d, duration)
	result += report.GenerateApplicationTracing(d, duration)
	result += tracker.GenerateConnectionCorrelation(allEvents)

	if d.podCommTracker != nil {
		summaries := d.podCommTracker.GetSummary()
		result += tracker.GeneratePodCommunicationReport(summaries)
	}

	if d.errorCorrelator != nil {
		result += d.errorCorrelator.GetErrorSummary()
	}

	result += report.GenerateIssuesSection(d)

	return result
}
