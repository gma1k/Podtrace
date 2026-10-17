package agent

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/netguard"
	"github.com/gma1k/podtrace/pkg/tracer"
)

var newTraceExporter = otlptrace.New

// newOTLPEventExporter builds a tracer.Exporter that ships per-event
// spans over OTLP HTTP.
func newOTLPEventExporter(cr CRKey, b *BundlePayload, opts ...sdkOption) (tracer.Exporter, error) {
	spanExporter, err := newOTLPSpanExporter(b)
	if err != nil {
		return nil, err
	}
	exporter, err := newSDKEventExporter("otlp", cr, b, spanExporter, opts...)
	if err != nil {
		return nil, err
	}
	return attachMetricPusher(exporter, cr, b, opts...)
}

// attachMetricPusher turns on the second signal when the bundle asks for
// it, binding the pusher's lifetime to the exporter's.
func attachMetricPusher(exporter tracer.Exporter, cr CRKey, b *BundlePayload, opts ...sdkOption) (tracer.Exporter, error) {
	dest, wanted := destinationFromBundle(b)
	if !wanted {
		return exporter, nil
	}
	var cfg sdkOptions
	for _, opt := range opts {
		opt(&cfg)
	}
	sdkExporter, ok := exporter.(*sdkEventExporter)
	if !ok || cfg.pushers == nil {
		return exporter, nil
	}

	release, err := cfg.pushers.acquire(dest, metricNamespaceScope(cr.Namespace, b.TargetNamespaces))
	sdkExporter.releaseMetrics = release
	if err != nil {
		return exporter, fmt.Errorf("start OTLP metric export: %w", err)
	}
	return exporter, nil
}

// newOTLPSpanExporter wires an otlptrace HTTP client from a bundle.
// Shared by every OTLP-speaking backend (OTLP, Jaeger, DataDog, Splunk).
func newOTLPSpanExporter(b *BundlePayload) (*otlptrace.Exporter, error) {
	if b.Endpoint == "" {
		return nil, fmt.Errorf("bundle missing endpoint")
	}

	endpoint, err := normalizeOTLPEndpoint(b.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("bundle endpoint: %w", err)
	}

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint.host),
		otlptracehttp.WithHTTPClient(netguard.HardenedClient(config.TracingExporterTimeout)),
	}
	if endpoint.path != "" && endpoint.path != "/" {
		opts = append(opts, otlptracehttp.WithURLPath(endpoint.path))
	}
	insecure := b.Insecure
	if endpoint.insecure != nil {
		insecure = *endpoint.insecure
	}
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(b.Headers) > 0 || len(b.SecretHeaders) > 0 || b.HeaderName != "" {
		headers := map[string]string{}
		for k, v := range b.Headers {
			headers[k] = v
		}
		for k, v := range b.SecretHeaders {
			headers[k] = v
		}
		if b.HeaderName != "" && len(b.Credential) > 0 {
			headers[b.HeaderName] = string(b.Credential)
		}
		opts = append(opts, otlptracehttp.WithHeaders(headers))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := otlptracehttp.NewClient(opts...)
	spanExporter, err := newTraceExporter(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("create OTLP span exporter: %w", err)
	}
	return spanExporter, nil
}

// otlpEndpoint is the decomposed OTLP endpoint: otlptracehttp wants the
// host:port, the URL path, and TLS-vs-plaintext as separate options.
type otlpEndpoint struct {
	host     string
	path     string
	insecure *bool
}

// normalizeOTLPEndpoint decomposes the endpoint into host / path / scheme.
// Accepts "collector:4318", "http://collector:4318" and
// "https://collector:4318/v1/traces".
func normalizeOTLPEndpoint(raw string) (otlpEndpoint, error) {
	if raw == "" {
		return otlpEndpoint{}, fmt.Errorf("empty endpoint")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return otlpEndpoint{}, err
		}
		ep := otlpEndpoint{host: u.Host, path: u.Path}
		switch u.Scheme {
		case "http":
			t := true
			ep.insecure = &t
		case "https":
			f := false
			ep.insecure = &f
		}
		return ep, nil
	}
	return otlpEndpoint{host: raw}, nil
}

// eventSpanName picks a human-readable span name from the event.
func eventSpanName(ev *events.Event) string {
	base := eventTypeString(ev.Type)
	if ev.Target != "" {
		return base + " " + ev.Target
	}
	return base
}

func eventTypeString(t events.EventType) string {
	if s, ok := eventTypeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("event_%d", uint32(t))
}

// eventTypeNames maps the small set of EventType values we care about
// for span-name readability.
var eventTypeNames = map[events.EventType]string{
	events.EventDNS:            "dns",
	events.EventConnect:        "net.connect",
	events.EventConnectResult:  "net.connect.result",
	events.EventTCPSend:        "net.tcp.send",
	events.EventTCPRecv:        "net.tcp.recv",
	events.EventUDPSend:        "net.udp.send",
	events.EventUDPRecv:        "net.udp.recv",
	events.EventTCPState:       "net.tcp.state",
	events.EventTCPRetrans:     "net.tcp.retransmit",
	events.EventNetDevError:    "net.dev.error",
	events.EventWrite:          "fs.write",
	events.EventRead:           "fs.read",
	events.EventOpen:           "fs.open",
	events.EventClose:          "fs.close",
	events.EventFsync:          "fs.fsync",
	events.EventUnlink:         "fs.unlink",
	events.EventRename:         "fs.rename",
	events.EventSchedSwitch:    "cpu.sched",
	events.EventLockContention: "cpu.lock",
	events.EventPageFault:      "mem.pagefault",
	events.EventOOMKill:        "mem.oomkill",
	events.EventExec:           "proc.exec",
	events.EventFork:           "proc.fork",
	events.EventHTTPReq:        "http.req",
	events.EventHTTPResp:       "http.resp",
	events.EventHTTP3:          "http3.conn",
	events.EventDBQuery:        "db.query",
}
