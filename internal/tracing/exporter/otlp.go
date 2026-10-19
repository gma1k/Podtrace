package exporter

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
)

type OTLPExporter struct {
	exporter   sdktrace.SpanExporter
	resource   *resource.Resource
	endpoint   string
	enabled    bool
	sampleRate float64
}

// otlpTracesPath is the OTLP/HTTP trace ingest path every collector serves.
const otlpTracesPath = "/v1/traces"

func isLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// normalizeOTLPHTTPEndpoint returns a full URL for WithEndpointURL and whether to use WithInsecure (HTTP).
func normalizeOTLPHTTPEndpoint(endpoint string) (endpointURL string, useInsecure bool, err error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		raw = config.DefaultOTLPEndpoint
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("parse OTLP endpoint: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		u, err = url.Parse("http://" + raw)
		if err != nil {
			return "", false, fmt.Errorf("parse OTLP endpoint: %w", err)
		}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false, fmt.Errorf("otlp endpoint scheme must be http or https")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = otlpTracesPath
	}
	host := u.Hostname()
	if u.Scheme == "http" {
		if isLoopbackHost(host) || config.OTLPAllowInsecureNonLoopback() {
			return u.String(), true, nil
		}
		return "", false, fmt.Errorf("otlp: refusing cleartext http to %q; use https:// or set PODTRACE_OTLP_INSECURE=1", host)
	}
	return u.String(), false, nil
}

func NewOTLPExporter(endpoint string, sampleRate float64) (*OTLPExporter, error) {
	endpointURL, useInsecure, err := normalizeOTLPHTTPEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	httpClient, err := otlpHTTPClient(config.TracingExporterTimeout, useInsecure)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(endpointURL),
		otlptracehttp.WithHTTPClient(httpClient),
		otlptracehttp.WithTimeout(config.TracingExporterTimeout),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}),
	}
	if useInsecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(config.OTLPHeaders) > 0 {
		headers := make(map[string]string, len(config.OTLPHeaders))
		for k, v := range config.OTLPHeaders {
			headers[k] = v
		}
		opts = append(opts, otlptracehttp.WithHeaders(headers))
	}
	otlpExporter, err := newOTLPClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	res, err := newResource(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("Podtrace"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	return &OTLPExporter{
		exporter:   otlpExporter,
		resource:   res,
		endpoint:   endpointURL,
		enabled:    true,
		sampleRate: sampleRate,
	}, nil
}

func (e *OTLPExporter) ExportTraces(traces []*tracker.Trace) error {
	if !e.enabled || len(traces) == 0 {
		return nil
	}

	ctx := context.Background()
	var outcome exportOutcome
	var snapshots []sdktrace.ReadOnlySpan
	var shipped []string
	for _, t := range traces {
		if !e.shouldSample(t) {
			continue
		}

		contributed := false
		for _, span := range t.Spans {
			snapshot, err := e.spanSnapshot(span)
			if err != nil {
				outcome.record(permanent(fmt.Errorf("trace %s span %s: %w", t.TraceID, span.SpanID, err)))
				continue
			}
			snapshots = append(snapshots, snapshot)
			contributed = true
		}
		if contributed {
			shipped = append(shipped, t.TraceID)
		}
	}

	if len(snapshots) > 0 {
		if err := e.exporter.ExportSpans(ctx, snapshots); err != nil {
			outcome.record(fmt.Errorf("export %d spans: %w", len(snapshots), err), shipped...)
		}
	}

	return outcome.err()
}

func (e *OTLPExporter) shouldSample(t *tracker.Trace) bool {
	return sampleTrace(t.TraceID, e.sampleRate)
}

// spanSnapshot converts a tracker span into a ReadOnlySpan that carries the
// ORIGINAL trace, span, and parent IDs. The previous implementation replayed
// spans through the SDK tracer, which mints a fresh span ID for every span
// and demotes the original ID to its parent — every OTLP backend then showed
// a broken parent/child structure with phantom intermediate spans.
func (e *OTLPExporter) spanSnapshot(span *tracker.Span) (sdktrace.ReadOnlySpan, error) {
	span.UpdateDuration()

	traceID, err := trace.TraceIDFromHex(span.TraceID)
	if err != nil {
		return nil, fmt.Errorf("invalid trace ID: %w", err)
	}

	spanID, err := trace.SpanIDFromHex(span.SpanID)
	if err != nil {
		return nil, fmt.Errorf("invalid span ID: %w", err)
	}

	stub := tracetest.SpanStub{
		Name: span.Operation,
		SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     spanID,
			TraceFlags: trace.FlagsSampled,
		}),
		StartTime: span.StartTime,
		EndTime:   span.StartTime.Add(span.Duration),
		Resource:  e.resource,
		InstrumentationScope: instrumentation.Scope{
			Name: "Podtrace",
		},
	}

	if span.ParentSpanID != "" {
		parentID, err := trace.SpanIDFromHex(span.ParentSpanID)
		if err != nil {
			return nil, fmt.Errorf("invalid parent span ID: %w", err)
		}
		stub.Parent = trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     parentID,
			TraceFlags: trace.FlagsSampled,
		})
	}

	attrs := make([]attribute.KeyValue, 0, len(span.Attributes))
	for k, v := range span.Attributes {
		attrs = append(attrs, attribute.String(k, v))
	}
	stub.Attributes = attrs

	if span.Error {
		stub.Status = sdktrace.Status{Code: codes.Error}
	}

	for _, event := range span.Events {
		attrs := []attribute.KeyValue{
			attribute.String("target", event.Target),
			attribute.Int64("latency_ns", safeconv.Uint64ToInt64(event.LatencyNS)),
		}
		if event.Type == events.EventDNS {
			attrs = append(attrs,
				attribute.String("dns.question.name", event.Target),
				attribute.Int("dns.question.type", int(event.TCPState)),
				attribute.Int("dns.response.code", int(event.Error)),
			)
			if event.Details != "" {
				attrs = append(attrs, attribute.String("dns.resolved", event.Details))
				attrs = append(attrs, attribute.Int("dns.answer.count",
					strings.Count(event.Details, ",")+1))
			}
			if s := event.DNSServerAddr(); s != "" {
				attrs = append(attrs, attribute.String("dns.server", s))
			}
			if event.DNSTransport == 1 {
				attrs = append(attrs, attribute.String("dns.transport", "tcp"))
			}
		}
		if event.Type == events.EventHTTPReq || event.Type == events.EventHTTPResp {
			attrs = append(attrs,
				attribute.String("http.scheme", event.HTTPScheme()),
				attribute.String("podtrace.http.transport", event.HTTPProtoLabel()),
			)
		}
		stub.Events = append(stub.Events, sdktrace.Event{
			Name:       event.TypeString(),
			Time:       event.TimestampTime(),
			Attributes: attrs,
		})
	}

	return stub.Snapshot(), nil
}

func (e *OTLPExporter) Shutdown(ctx context.Context) error {
	if e.exporter != nil {
		return e.exporter.Shutdown(ctx)
	}
	return nil
}
