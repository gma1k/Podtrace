package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/netguard"
	"github.com/gma1k/podtrace/internal/workloadmetrics"
)

// The continuous metrics plane as a second OTLP signal.
const (
	defaultMetricPushInterval = 60 * time.Second

	minMetricPushInterval = 10 * time.Second
	maxMetricPushInterval = 10 * time.Minute

	metricPushTimeout = 8 * time.Second
)

// metricProducer is the read side of the continuous metrics plane. Its
// method set matches sdkmetric.Producer, so a value of this type is
// accepted directly where the SDK wants a Producer.
type metricProducer interface {
	Produce(context.Context) ([]metricdata.ScopeMetrics, error)
}

var _ sdkmetric.Producer = metricProducer(nil)

// metricPusherPool hands out reference-counted pushers keyed by
// destination.
type metricPusherPool struct {
	mu       sync.Mutex
	byKey    map[string]*pooledMetricPusher
	producer metricProducer
	nodeName string

	newReader func(destination, sdkmetric.Producer) (sdkmetric.Reader, error)
}

type pooledMetricPusher struct {
	provider *sdkmetric.MeterProvider
	refs     int

	scopeMu    sync.Mutex
	namespaces map[string]int
}

func (e *pooledMetricPusher) addNamespaces(namespaces []string) {
	e.scopeMu.Lock()
	defer e.scopeMu.Unlock()
	for _, ns := range namespaces {
		e.namespaces[ns]++
	}
}

func (e *pooledMetricPusher) removeNamespaces(namespaces []string) {
	e.scopeMu.Lock()
	defer e.scopeMu.Unlock()
	for _, ns := range namespaces {
		if e.namespaces[ns] <= 1 {
			delete(e.namespaces, ns)
			continue
		}
		e.namespaces[ns]--
	}
}

func (e *pooledMetricPusher) allows(namespace string) bool {
	e.scopeMu.Lock()
	defer e.scopeMu.Unlock()
	return e.namespaces[namespace] > 0
}

// metricNamespaceScope is the set of namespaces whose series one CR may
// push. It mirrors inNamespaceScope: a nil allowlist means the CR's own
// namespace, a non-nil one means exactly that list, and an empty list
// means nothing.
func metricNamespaceScope(crNamespace string, targetNamespaces []string) []string {
	if targetNamespaces == nil {
		if crNamespace == "" {
			return nil
		}
		return []string{crNamespace}
	}
	seen := make(map[string]struct{}, len(targetNamespaces))
	out := make([]string, 0, len(targetNamespaces))
	for _, ns := range targetNamespaces {
		if ns == "" {
			continue
		}
		if _, dup := seen[ns]; dup {
			continue
		}
		seen[ns] = struct{}{}
		out = append(out, ns)
	}
	return out
}

// destination is everything that decides where and how metrics are sent.
// Two exporters agree on a pusher exactly when these agree.
type destination struct {
	endpoint string
	insecure bool
	headers  map[string]string
	interval time.Duration
}

func newMetricPusherPool(producer metricProducer, nodeName string) *metricPusherPool {
	return &metricPusherPool{
		byKey:     map[string]*pooledMetricPusher{},
		producer:  producer,
		nodeName:  nodeName,
		newReader: newOTLPMetricReader,
	}
}

// acquire returns a release function for the pusher serving dest, starting
// one if this is the first caller, and adds namespaces to what that pusher
// may send. release takes them away again.
//
// The returned release is always safe to call, exactly once, including
// when acquire failed.
func (p *metricPusherPool) acquire(dest destination, namespaces []string) (func(context.Context) error, error) {
	if p == nil || p.producer == nil {
		return noopRelease, nil
	}

	key := dest.key()

	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.byKey[key]; ok {
		existing.refs++
		existing.addNamespaces(namespaces)
		return p.releaseFor(key, namespaces), nil
	}

	entry := &pooledMetricPusher{refs: 1, namespaces: map[string]int{}}
	entry.addNamespaces(namespaces)
	reader, err := p.newReader(dest, workloadmetrics.NewNamespaceScopedProducer(p.producer, entry.allows))
	if err != nil {
		return noopRelease, err
	}
	entry.provider = sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(p.resource()),
	)
	p.byKey[key] = entry
	return p.releaseFor(key, namespaces), nil
}

// resource describes the producer of these metrics, which is this agent
// on this node.
//
// Workload identity travels as data-point attributes rather than here,
// because a Resource belongs to the provider and one provider serves every
// workload on the node. That is also what a Collector's Prometheus
// receiver does with a scrape, so the two paths agree.
func (p *metricPusherPool) resource() *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.ServiceName("podtrace"),
		semconv.TelemetrySDKName("podtrace"),
	}
	if p.nodeName != "" {
		attrs = append(attrs, semconv.K8SNodeName(p.nodeName))
	}
	return resource.NewSchemaless(attrs...)
}

func (p *metricPusherPool) releaseFor(key string, namespaces []string) func(context.Context) error {
	var once sync.Once
	return func(ctx context.Context) error {
		var err error
		once.Do(func() {
			p.mu.Lock()
			entry, ok := p.byKey[key]
			if !ok {
				p.mu.Unlock()
				return
			}
			entry.refs--
			if entry.refs > 0 {
				entry.removeNamespaces(namespaces)
				p.mu.Unlock()
				return
			}
			delete(p.byKey, key)
			p.mu.Unlock()

			flushCtx, cancel := context.WithTimeout(ctx, metricPushTimeout)
			defer cancel()
			_ = entry.provider.ForceFlush(flushCtx)
			err = entry.provider.Shutdown(ctx)
		})
		return err
	}
}

// size reports how many pushers are live. Tests only.
func (p *metricPusherPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byKey)
}

func noopRelease(context.Context) error { return nil }

// newOTLPMetricReader builds the periodic reader that pushes the external
// producer's metrics over OTLP HTTP.
func newOTLPMetricReader(dest destination, producer sdkmetric.Producer) (sdkmetric.Reader, error) {
	if dest.endpoint == "" {
		return nil, fmt.Errorf("bundle missing endpoint")
	}
	endpoint, err := normalizeOTLPEndpoint(dest.endpoint)
	if err != nil {
		return nil, fmt.Errorf("bundle endpoint: %w", err)
	}

	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(endpoint.host),
		otlpmetrichttp.WithHTTPClient(netguard.HardenedClient(config.TracingExporterTimeout)),
	}
	if path := metricsPath(endpoint.path); path != "" {
		opts = append(opts, otlpmetrichttp.WithURLPath(path))
	}
	insecure := dest.insecure
	if endpoint.insecure != nil {
		insecure = *endpoint.insecure
	}
	if insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if len(dest.headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(dest.headers))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP metric exporter: %w", err)
	}
	return sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithInterval(dest.interval),
		sdkmetric.WithTimeout(metricPushTimeout),
		sdkmetric.WithProducer(producer),
	), nil
}

// metricsPath maps a trace endpoint path onto the metrics signal.
func metricsPath(tracePath string) string {
	switch strings.TrimSuffix(tracePath, "/") {
	case "", "/v1/traces":
		return ""
	default:
		return tracePath
	}
}

// key is a stable identity for a destination.
func (d destination) key() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "endpoint=%s\ninsecure=%t\ninterval=%d\n", d.endpoint, d.insecure, d.interval)
	writeSortedHeaders(h, d.headers)
	return hex.EncodeToString(h.Sum(nil))
}

func writeSortedHeaders(w io.Writer, headers map[string]string) {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		_, _ = fmt.Fprintf(w, "header=%s=%s\n", name, headers[name])
	}
}

// destinationFromBundle reads the metric destination out of an exporter
// bundle, reporting false when the bundle does not ask for metrics.
func destinationFromBundle(b *BundlePayload) (destination, bool) {
	if b == nil || !b.Metrics {
		return destination{}, false
	}
	return destination{
		endpoint: b.Endpoint,
		insecure: b.Insecure,
		headers:  bundleHeaders(b),
		interval: clampPushInterval(b.MetricsInterval),
	}, true
}

// clampPushInterval keeps the push period inside a range where it is
// useful: below the floor the cost outruns what a cumulative counter can
// reveal, above the ceiling a dashboard reads the gap as an outage.
func clampPushInterval(requested time.Duration) time.Duration {
	switch {
	case requested <= 0:
		return defaultMetricPushInterval
	case requested < minMetricPushInterval:
		return minMetricPushInterval
	case requested > maxMetricPushInterval:
		return maxMetricPushInterval
	default:
		return requested
	}
}

// bundleHeaders flattens the bundle's three header sources the same way
// the span exporter does, so both signals authenticate identically.
func bundleHeaders(b *BundlePayload) map[string]string {
	if len(b.Headers) == 0 && len(b.SecretHeaders) == 0 && b.HeaderName == "" {
		return nil
	}
	headers := make(map[string]string, len(b.Headers)+len(b.SecretHeaders)+1)
	for k, v := range b.Headers {
		headers[k] = v
	}
	for k, v := range b.SecretHeaders {
		headers[k] = v
	}
	if b.HeaderName != "" && len(b.Credential) > 0 {
		headers[b.HeaderName] = string(b.Credential)
	}
	return headers
}
