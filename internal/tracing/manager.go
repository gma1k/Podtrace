package tracing

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/tracing/exporter"
	"github.com/podtrace/podtrace/internal/tracing/extractor"
	"github.com/podtrace/podtrace/internal/tracing/graph"
)

type Manager struct {
	enabled         bool
	extractor       *extractor.HTTPExtractor
	traceTracker    *tracker.TraceTracker
	otlpExporter    *exporter.OTLPExporter
	jaegerExporter  *exporter.JaegerExporter
	splunkExporter  *exporter.SplunkExporter
	graphBuilder    *graph.GraphBuilder
	exportInterval  time.Duration
	cleanupInterval time.Duration
	stopCh          chan struct{}
	wg              sync.WaitGroup
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

	return &Manager{
		enabled:         true,
		extractor:       extractor,
		traceTracker:    traceTracker,
		otlpExporter:    otlpExporter,
		jaegerExporter:  jaegerExporter,
		splunkExporter:  splunkExporter,
		graphBuilder:    graphBuilder,
		exportInterval:  5 * time.Second,
		cleanupInterval: 1 * time.Minute,
		stopCh:          make(chan struct{}),
	}, nil
}

func (m *Manager) ProcessEvent(event *events.Event, k8sContext interface{}) {
	if !m.enabled || event == nil {
		return
	}

	if event.Details != "" {
		traceCtx := m.extractor.ExtractFromRawHeaders(event.Details)
		if traceCtx != nil && traceCtx.IsValid() {
			event.TraceID = traceCtx.TraceID
			event.SpanID = traceCtx.SpanID
			event.ParentSpanID = traceCtx.ParentSpanID
			event.TraceFlags = traceCtx.Flags
			event.TraceState = traceCtx.State
		}
	}

	if event.TraceID != "" {
		m.traceTracker.ProcessEvent(event, k8sContext)
	}
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
			m.exportTraces()
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
		}
	}
}

func (m *Manager) exportTraces() {
	traces := m.traceTracker.GetAllTraces()
	if len(traces) == 0 {
		return
	}

	if m.otlpExporter != nil {
		if err := m.otlpExporter.ExportTraces(traces); err != nil {
			logger.Warn("Failed to export traces to OTLP", zap.Error(err))
		}
	}

	if m.jaegerExporter != nil {
		if err := m.jaegerExporter.ExportTraces(traces); err != nil {
			logger.Warn("Failed to export traces to Jaeger", zap.Error(err))
		}
	}

	if m.splunkExporter != nil {
		if err := m.splunkExporter.ExportTraces(traces); err != nil {
			logger.Warn("Failed to export traces to Splunk", zap.Error(err))
		}
	}
}

func (m *Manager) GetRequestFlowGraph() *graph.RequestFlowGraph {
	if !m.enabled {
		return nil
	}

	traces := m.traceTracker.GetAllTraces()
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

	close(m.stopCh)
	m.wg.Wait()

	m.exportTraces()

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

	return nil
}
