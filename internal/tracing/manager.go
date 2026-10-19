package tracing

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/tracing/exporter"
	"github.com/gma1k/podtrace/internal/tracing/extractor"
	"github.com/gma1k/podtrace/internal/tracing/graph"
)

type Manager struct {
	enabled         bool
	extractor       *extractor.HTTPExtractor
	traceTracker    *tracker.TraceTracker
	otlpExporter    *exporter.OTLPExporter
	jaegerExporter  *exporter.JaegerExporter
	splunkExporter  *exporter.SplunkExporter
	datadogExporter *exporter.DataDogExporter
	zipkinExporter  *exporter.ZipkinExporter
	graphBuilder    *graph.GraphBuilder
	exportInterval  time.Duration
	cleanupInterval time.Duration
	synthesize      bool
	corr            *correlationCache
	stopCh          chan struct{}
	stopOnce        sync.Once
	wg              sync.WaitGroup

	exportMu sync.Mutex
	statsMu  sync.Mutex
	stats    map[string]*ExporterStatus
}

// ExporterStatus is the delivery record of one exporter over the
// manager's lifetime: how many export batches it delivered, how many
// failed, and the last failure (URLs redacted).
type ExporterStatus struct {
	Exporter         string
	SucceededBatches int64
	FailedBatches    int64
	LastError        string
}

func NewManager() (*Manager, error) {
	if !config.TracingEnabled {
		return &Manager{enabled: false}, nil
	}

	extractor := extractor.NewHTTPExtractor()
	traceTracker := tracker.NewTraceTracker()
	graphBuilder := graph.NewGraphBuilder()

	var otlpExporter *exporter.OTLPExporter
	var jaegerExporter *exporter.JaegerExporter
	var splunkExporter *exporter.SplunkExporter
	var datadogExporter *exporter.DataDogExporter
	var zipkinExporter *exporter.ZipkinExporter
	var err error

	if config.OTLPEndpoint != "" {
		otlpExporter, err = exporter.NewOTLPExporter(config.OTLPEndpoint, config.TracingSampleRate)
		if err != nil {
			logger.Warn("Failed to create OTLP exporter", zap.Error(err))
		}
	}

	if config.JaegerEndpoint != "" {
		jaegerExporter, err = exporter.NewJaegerExporter(config.JaegerEndpoint, config.TracingSampleRate)
		if err != nil {
			logger.Warn("Failed to create Jaeger exporter", zap.Error(err))
		}
	}

	if config.SplunkEndpoint != "" {
		splunkExporter, err = exporter.NewSplunkExporter(config.SplunkEndpoint, config.SplunkToken, config.TracingSampleRate)
		if err != nil {
			logger.Warn("Failed to create Splunk exporter", zap.Error(err))
		}
	}

	if config.DataDogEndpoint != "" {
		datadogExporter, err = exporter.NewDataDogExporter(config.DataDogEndpoint, config.DataDogAPIKey, config.TracingSampleRate)
		if err != nil {
			logger.Warn("Failed to create DataDog exporter", zap.Error(err))
		}
	}

	if config.ZipkinEndpoint != "" {
		zipkinExporter, err = exporter.NewZipkinExporter(config.ZipkinEndpoint, config.TracingSampleRate)
		if err != nil {
			logger.Warn("Failed to create Zipkin exporter", zap.Error(err))
		}
	}

	return &Manager{
		enabled:         true,
		extractor:       extractor,
		traceTracker:    traceTracker,
		otlpExporter:    otlpExporter,
		jaegerExporter:  jaegerExporter,
		splunkExporter:  splunkExporter,
		datadogExporter: datadogExporter,
		zipkinExporter:  zipkinExporter,
		graphBuilder:    graphBuilder,
		exportInterval:  5 * time.Second,
		cleanupInterval: 1 * time.Minute,
		synthesize:      config.SynthesizeSpans,
		corr:            newCorrelationCache(config.MaxTraceContextCacheSize),
		stopCh:          make(chan struct{}),
	}, nil
}

func (m *Manager) ProcessEvent(event *events.Event, k8sContext interface{}) {
	if !m.enabled || event == nil {
		return
	}

	haveContext := false
	if event.Details != "" {
		if tc := m.extractor.ExtractFromRawHeaders(event.Details); tc != nil && tc.HasRemoteParent() {
			event.TraceID = tc.TraceID
			event.ParentSpanID = tc.ParentSpanID
			event.TraceFlags = tc.Flags
			event.TraceState = tc.State
			haveContext = true
		}
	}

	if m.assignSpanIdentity(event, haveContext) {
		m.traceTracker.ProcessEvent(event, k8sContext)
	}
}

// assignSpanIdentity gives the event a stable per-request span id and, for the
// response event (which carries no headers), joins it to the request's trace.
func (m *Manager) assignSpanIdentity(event *events.Event, haveContext bool) bool {
	if haveContext {
		if isCorrelatableL7(event) {
			key := correlationKey(event)
			event.SpanID = deriveSpanID(key)
			m.corr.store(key, correlationEntry{
				traceID:      event.TraceID,
				parentSpanID: event.ParentSpanID,
				spanID:       event.SpanID,
				flags:        event.TraceFlags,
				state:        event.TraceState,
			})
		} else {
			event.SpanID = deriveSpanID(event.TraceID + event.ParentSpanID)
		}
		return true
	}

	if isCorrelatableL7(event) {
		key := correlationKey(event)
		if e, ok := m.corr.loadDelete(key); ok {
			event.TraceID = e.traceID
			event.ParentSpanID = e.parentSpanID
			event.SpanID = e.spanID
			event.TraceFlags = e.flags
			event.TraceState = e.state
			return true
		}
		if m.synthesize {
			event.TraceID = deriveTraceID(key)
			event.SpanID = deriveSpanID(key)
			return true
		}
		return false
	}

	return event.TraceID != ""
}

func (m *Manager) Start(ctx context.Context) error {
	if !m.enabled {
		return nil
	}

	m.wg.Add(2)
	go m.exportLoop(ctx)
	go m.cleanupLoop(ctx)

	return nil
}

func (m *Manager) exportLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.exportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.exportTraces(false)
		}
	}
}

func (m *Manager) cleanupLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.traceTracker.CleanupOldTraces(10 * time.Minute)
			m.corr.sweep(2 * time.Minute)
		}
	}
}

// exporterTarget pairs one configured exporter with the metadata its
// failure alert needs.
type exporterTarget struct {
	name            string
	endpoint        string
	export          func([]*tracker.Trace) error
	recommendations []string
	suppressAlert   bool
}

func (m *Manager) exporterTargets() []exporterTarget {
	var out []exporterTarget
	if m.otlpExporter != nil {
		out = append(out, exporterTarget{
			name: "otlp", endpoint: config.OTLPEndpoint, export: m.otlpExporter.ExportTraces,
			recommendations: []string{"Check OTLP endpoint connectivity", "Verify endpoint configuration", "Check network connectivity"},
		})
	}
	if m.jaegerExporter != nil {
		out = append(out, exporterTarget{
			name: "jaeger", endpoint: config.JaegerEndpoint, export: m.jaegerExporter.ExportTraces,
			recommendations: []string{"Check Jaeger endpoint connectivity", "Verify endpoint configuration", "Check network connectivity"},
		})
	}
	if m.splunkExporter != nil {
		out = append(out, exporterTarget{
			name: "splunk", endpoint: config.SplunkEndpoint, export: m.splunkExporter.ExportTraces,
			recommendations: []string{"Check Splunk endpoint connectivity", "Verify Splunk token", "Check network connectivity"},
			// Avoid an alert feedback loop when alerts themselves are
			// delivered through Splunk.
			suppressAlert: config.AlertSplunkEnabled,
		})
	}
	if m.datadogExporter != nil {
		out = append(out, exporterTarget{
			name: "datadog", endpoint: config.DataDogEndpoint, export: m.datadogExporter.ExportTraces,
			recommendations: []string{"Check DataDog agent endpoint connectivity", "Verify DD-API-KEY if using direct ingest", "Check network connectivity"},
		})
	}
	if m.zipkinExporter != nil {
		out = append(out, exporterTarget{
			name: "zipkin", endpoint: config.ZipkinEndpoint, export: m.zipkinExporter.ExportTraces,
			recommendations: []string{"Check Zipkin endpoint connectivity", "Verify endpoint configuration", "Check network connectivity"},
		})
	}
	return out
}

// exportTraces hands each span to every exporter exactly once: the tracker
// snapshot advances a per-trace watermark, so a tick no longer re-sends every
// accumulated trace (which duplicated spans in all backends on every 5s
// interval). force (shutdown) flushes spans of traces that are still
// settling.
func (m *Manager) exportTraces(force bool) {
	m.exportMu.Lock()
	defer m.exportMu.Unlock()
	for _, target := range m.exporterTargets() {
		traces := m.traceTracker.SnapshotForExport(m.exportInterval, force, target.name)
		if len(traces) == 0 {
			continue
		}
		err := target.export(traces)
		m.recordExport(target.name, err)
		if err != nil {
			m.reportExporterFailure(target, err)
		}
		// Advance only this exporter's watermark, and only past the traces
		// it must not be offered again.
		if done := settledTraces(traces, err); len(done) > 0 {
			m.traceTracker.CommitExport(done, target.name)
		}
	}
}

// settledTraces returns the traces of a batch that must not be re-offered:
// all of them on success, none on a whole-batch failure, and on a partial
// failure every trace except those the exporter asks to retry.
func settledTraces(traces []*tracker.Trace, err error) []*tracker.Trace {
	if err == nil {
		return traces
	}
	var partial *exporter.PartialExportError
	if !errors.As(err, &partial) {
		return nil
	}
	done := make([]*tracker.Trace, 0, len(traces))
	for _, t := range traces {
		if !partial.Retry(t.TraceID) {
			done = append(done, t)
		}
	}
	return done
}

// reportExporterFailure logs and (unless suppressed) raises an alert for a
// failed export.
func (m *Manager) reportExporterFailure(target exporterTarget, err error) {
	safeErr := alerting.RedactURLsInText(err.Error())
	logger.Warn("Failed to export traces", zap.String("exporter", target.name), zap.String("error", safeErr))
	if target.suppressAlert {
		return
	}
	manager := alerting.GetGlobalManager()
	if manager == nil {
		return
	}
	manager.SendAlert(&alerting.Alert{
		Severity:  alerting.SeverityWarning,
		Title:     fmt.Sprintf("%s Exporter Failure", strings.ToUpper(target.name[:1])+target.name[1:]),
		Message:   fmt.Sprintf("Failed to export traces to %s: %s", target.name, safeErr),
		Timestamp: time.Now(),
		Source:    "exporter",
		Context: map[string]interface{}{
			"exporter": target.name,
			"endpoint": alerting.RedactURLForLog(target.endpoint),
			"error":    safeErr,
		},
		Recommendations: target.recommendations,
	})
}

// recordExport tallies one export batch for the exporter's status.
func (m *Manager) recordExport(name string, err error) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	if m.stats == nil {
		m.stats = map[string]*ExporterStatus{}
	}
	st, ok := m.stats[name]
	if !ok {
		st = &ExporterStatus{Exporter: name}
		m.stats[name] = st
	}
	if err == nil {
		st.SucceededBatches++
		return
	}
	st.FailedBatches++
	st.LastError = alerting.RedactURLsInText(err.Error())
}

// Flush exports every pending span now, including spans of traces that are
// still settling, without stopping the manager. A bounded run (a session
// Job) calls it before reading ExportStatus so the status covers the final
// batch too.
func (m *Manager) Flush() {
	if !m.enabled {
		return
	}
	m.exportTraces(true)
}

// ExportStatus returns the delivery record of every exporter that has
// attempted at least one batch, sorted by exporter name.
func (m *Manager) ExportStatus() []ExporterStatus {
	if !m.enabled {
		return nil
	}
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	out := make([]ExporterStatus, 0, len(m.stats))
	for _, st := range m.stats {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Exporter < out[j].Exporter })
	return out
}

func (m *Manager) GetRequestFlowGraph() *graph.RequestFlowGraph {
	if !m.enabled {
		return nil
	}

	traces := m.traceTracker.SnapshotAll()
	return m.graphBuilder.BuildFromTraces(traces)
}

func (m *Manager) GetTraceCount() int {
	if !m.enabled {
		return 0
	}
	return m.traceTracker.GetTraceCount()
}

func (m *Manager) Shutdown(ctx context.Context) error {
	if !m.enabled {
		return nil
	}

	m.stopOnce.Do(func() { close(m.stopCh) })

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.wg.Wait()
		// Final flush: force-export spans of traces still settling.
		m.exportTraces(true)
		m.shutdownExporters(ctx)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		logger.Warn("Tracing shutdown exceeded its deadline; abandoning in-flight export", zap.Error(ctx.Err()))
	}
	return nil
}

// shutdownExporters closes every configured exporter, logging but not
// propagating individual failures.
func (m *Manager) shutdownExporters(ctx context.Context) {
	if m.otlpExporter != nil {
		if err := m.otlpExporter.Shutdown(ctx); err != nil {
			logger.Warn("Failed to shutdown OTLP exporter", zap.Error(err))
		}
	}
	if m.jaegerExporter != nil {
		if err := m.jaegerExporter.Shutdown(ctx); err != nil {
			logger.Warn("Failed to shutdown Jaeger exporter", zap.Error(err))
		}
	}
	if m.splunkExporter != nil {
		if err := m.splunkExporter.Shutdown(ctx); err != nil {
			logger.Warn("Failed to shutdown Splunk exporter", zap.Error(err))
		}
	}
	if m.datadogExporter != nil {
		if err := m.datadogExporter.Shutdown(ctx); err != nil {
			logger.Warn("Failed to shutdown DataDog exporter", zap.Error(err))
		}
	}
	if m.zipkinExporter != nil {
		if err := m.zipkinExporter.Shutdown(ctx); err != nil {
			logger.Warn("Failed to shutdown Zipkin exporter", zap.Error(err))
		}
	}
}
