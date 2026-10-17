package agent

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"

	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

type otlpMetricReceiver struct {
	server *httptest.Server

	mu       sync.Mutex
	paths    []string
	requests []*collectormetrics.ExportMetricsServiceRequest
	arrived  chan struct{}
	once     sync.Once
}

func newOTLPMetricReceiver(t *testing.T) *otlpMetricReceiver {
	t.Helper()
	receiver := &otlpMetricReceiver{arrived: make(chan struct{})}
	receiver.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := readPossiblyGzipped(r)
		if err != nil {
			t.Errorf("read body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var request collectormetrics.ExportMetricsServiceRequest
		if err := proto.Unmarshal(body, &request); err != nil {
			t.Errorf("unmarshal OTLP request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		receiver.mu.Lock()
		receiver.paths = append(receiver.paths, r.URL.Path)
		receiver.requests = append(receiver.requests, &request)
		receiver.mu.Unlock()
		receiver.once.Do(func() { close(receiver.arrived) })

		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{})
	}))
	t.Cleanup(receiver.server.Close)
	return receiver
}

func readPossiblyGzipped(r *http.Request) ([]byte, error) {
	if r.Header.Get("Content-Encoding") != "gzip" {
		return io.ReadAll(r.Body)
	}
	reader, err := gzip.NewReader(r.Body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}

func (r *otlpMetricReceiver) waitForPush(t *testing.T) *collectormetrics.ExportMetricsServiceRequest {
	t.Helper()
	select {
	case <-r.arrived:
	case <-time.After(20 * time.Second):
		t.Fatal("no OTLP metric push arrived")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests[0]
}

func (r *otlpMetricReceiver) firstPath() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.paths) == 0 {
		return ""
	}
	return r.paths[0]
}

type wireProducer struct{}

func (wireProducer) Produce(context.Context) ([]metricdata.ScopeMetrics, error) {
	now := time.Now()
	return []metricdata.ScopeMetrics{{
		Metrics: []metricdata.Metrics{
			{
				Name: "podtrace_workload_l7_requests_total",
				Unit: "",
				Data: metricdata.Sum[float64]{
					DataPoints: []metricdata.DataPoint[float64]{{
						Attributes: attribute.NewSet(attribute.String("namespace", "ns")),
						StartTime:  now.Add(-time.Minute),
						Time:       now,
						Value:      42,
					}},
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
				},
			},
			{
				Name: "http.server.request.duration",
				Unit: "s",
				Data: metricdata.Histogram[float64]{
					DataPoints: []metricdata.HistogramDataPoint[float64]{{
						Attributes:   attribute.NewSet(attribute.String("k8s.namespace.name", "ns")),
						StartTime:    now.Add(-time.Minute),
						Time:         now,
						Count:        3,
						Sum:          0.6,
						Bounds:       []float64{0.1, 1},
						BucketCounts: []uint64{1, 2, 0},
					}},
					Temporality: metricdata.CumulativeTemporality,
				},
			},
		},
	}}, nil
}

func TestMetricsActuallyReachAnOTLPReceiver(t *testing.T) {
	receiver := newOTLPMetricReceiver(t)

	pool := newMetricPusherPool(wireProducer{}, "node-a")
	dest, wanted := destinationFromBundle(&BundlePayload{
		Type:            bundle.TypeOTLP,
		Endpoint:        receiver.server.URL,
		Metrics:         true,
		MetricsInterval: minMetricPushInterval,
		Headers:         map[string]string{"x-tenant": "team-a"},
	})
	if !wanted {
		t.Fatal("destinationFromBundle refused a metrics bundle")
	}

	release, err := pool.acquire(dest, []string{"ns"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	t.Cleanup(func() { _ = release(context.Background()) })

	// The first push happens on release's flush rather than after a full
	// interval, so the test does not wait out the clamped minimum.
	if err := release(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}

	request := receiver.waitForPush(t)

	if got := receiver.firstPath(); got != "/v1/metrics" {
		t.Errorf("pushed to %q, want /v1/metrics; the metrics signal has its own path and a "+
			"trace receiver rejects metrics", got)
	}

	if len(request.GetResourceMetrics()) != 1 {
		t.Fatalf("got %d resource metrics, want 1", len(request.GetResourceMetrics()))
	}
	resourceAttrs := map[string]string{}
	for _, kv := range request.GetResourceMetrics()[0].GetResource().GetAttributes() {
		resourceAttrs[kv.GetKey()] = kv.GetValue().GetStringValue()
	}
	if resourceAttrs["service.name"] != "podtrace" {
		t.Errorf("resource service.name = %q, want podtrace", resourceAttrs["service.name"])
	}
	if resourceAttrs["k8s.node.name"] != "node-a" {
		t.Errorf("resource k8s.node.name = %q, want node-a", resourceAttrs["k8s.node.name"])
	}

	byName := map[string]*metricspb.Metric{}
	for _, scope := range request.GetResourceMetrics()[0].GetScopeMetrics() {
		for _, m := range scope.GetMetrics() {
			byName[m.GetName()] = m
		}
	}

	counter := byName["podtrace_workload_l7_requests_total"]
	if counter == nil {
		t.Fatalf("counter did not reach the receiver; got %v", metricNames(byName))
	}
	sum := counter.GetSum()
	if sum == nil {
		t.Fatalf("counter arrived as %T, want a Sum", counter.GetData())
	}
	if sum.GetAggregationTemporality() != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE {
		t.Errorf("temporality on the wire = %v, want cumulative; the underlying Prometheus "+
			"counters are cumulative and a delta claim would make a backend double-count",
			sum.GetAggregationTemporality())
	}
	if !sum.GetIsMonotonic() {
		t.Error("is_monotonic false on the wire for a _total counter")
	}
	if got := sum.GetDataPoints()[0].GetAsDouble(); got != 42 {
		t.Errorf("counter value on the wire = %v, want 42", got)
	}

	histogram := byName["http.server.request.duration"]
	if histogram == nil {
		t.Fatalf("the convention family did not reach the receiver; got %v", metricNames(byName))
	}
	if histogram.GetUnit() != "s" {
		t.Errorf("unit on the wire = %q, want s", histogram.GetUnit())
	}
	point := histogram.GetHistogram().GetDataPoints()[0]
	if point.GetCount() != 3 || point.GetSum() != 0.6 {
		t.Errorf("histogram point = count %d sum %v, want 3 / 0.6", point.GetCount(), point.GetSum())
	}
	if len(point.GetBucketCounts()) != len(point.GetExplicitBounds())+1 {
		t.Errorf("wire has %d bucket counts for %d bounds, want one more count than bounds",
			len(point.GetBucketCounts()), len(point.GetExplicitBounds()))
	}
}

func metricNames(byName map[string]*metricspb.Metric) []string {
	out := make([]string, 0, len(byName))
	for name := range byName {
		out = append(out, name)
	}
	return out
}

func TestAnExplicitTracePathIsRewrittenForMetrics(t *testing.T) {
	receiver := newOTLPMetricReceiver(t)

	parsed, err := url.Parse(receiver.server.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	traceStyleEndpoint := parsed.Scheme + "://" + parsed.Host + "/v1/traces"

	reader, err := newOTLPMetricReader(destination{
		endpoint: traceStyleEndpoint,
		interval: minMetricPushInterval,
	}, wireProducer{})
	if err != nil {
		t.Fatalf("newOTLPMetricReader: %v", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	if err := provider.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	receiver.waitForPush(t)
	if got := receiver.firstPath(); got != "/v1/metrics" {
		t.Errorf("pushed to %q, want /v1/metrics; an endpoint written for traces must not be "+
			"reused verbatim", got)
	}
}

func TestPushCarriesTheBundleHeaders(t *testing.T) {
	var seen http.Header
	var once sync.Once
	arrived := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		once.Do(func() { close(arrived) })
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	dest, _ := destinationFromBundle(&BundlePayload{
		Type:            bundle.TypeOTLP,
		Endpoint:        server.URL,
		Metrics:         true,
		MetricsInterval: minMetricPushInterval,
		HeaderName:      "authorization",
		Credential:      []byte("Bearer secret"),
	})
	reader, err := newOTLPMetricReader(dest, wireProducer{})
	if err != nil {
		t.Fatalf("newOTLPMetricReader: %v", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	if err := provider.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	select {
	case <-arrived:
	case <-time.After(20 * time.Second):
		t.Fatal("no push arrived")
	}

	if got := seen.Get("Authorization"); !strings.Contains(got, "Bearer secret") {
		t.Errorf("Authorization header = %q, want the bundle credential; both signals share an "+
			"endpoint and must authenticate identically", got)
	}
}

func TestAMissingEndpointIsRefusedBeforeAnySocket(t *testing.T) {
	if _, err := newOTLPMetricReader(destination{interval: time.Minute}, wireProducer{}); err == nil {
		t.Error("an empty endpoint was accepted")
	}
	if _, err := newOTLPMetricReader(destination{
		endpoint: "http://[::1", interval: time.Minute,
	}, wireProducer{}); err == nil {
		t.Error("an unparseable endpoint was accepted")
	}
}

func TestACustomEndpointPathIsUsedVerbatim(t *testing.T) {
	var seen string
	var once sync.Once
	arrived := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		once.Do(func() { close(arrived) })
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	reader, err := newOTLPMetricReader(destination{
		endpoint: server.URL + "/ingest/otlp",
		interval: minMetricPushInterval,
	}, wireProducer{})
	if err != nil {
		t.Fatalf("newOTLPMetricReader: %v", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	if err := provider.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	select {
	case <-arrived:
	case <-time.After(20 * time.Second):
		t.Fatal("no push arrived")
	}
	if seen != "/ingest/otlp" {
		t.Errorf("pushed to %q, want /ingest/otlp; a path that is not the trace default is a "+
			"deliberate choice and must be honoured", seen)
	}
}
