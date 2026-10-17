package agent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/gma1k/podtrace/pkg/exporter/bundle"
	"github.com/gma1k/podtrace/pkg/tracer"
)

type fakeProducer struct {
	calls atomic.Int32
}

func (f *fakeProducer) Produce(context.Context) ([]metricdata.ScopeMetrics, error) {
	f.calls.Add(1)
	return []metricdata.ScopeMetrics{{
		Metrics: []metricdata.Metrics{{
			Name: "podtrace_workload_l7_requests_total",
			Data: metricdata.Sum[float64]{
				DataPoints: []metricdata.DataPoint[float64]{{
					Attributes: attribute.NewSet(attribute.String("namespace", "ns")),
					Value:      1,
				}},
				Temporality: metricdata.CumulativeTemporality,
				IsMonotonic: true,
			},
		}},
	}}, nil
}

type recordingReader struct {
	sdkmetric.Reader
	mu    sync.Mutex
	calls []string
}

func (r *recordingReader) ForceFlush(context.Context) error {
	r.mu.Lock()
	r.calls = append(r.calls, "flush")
	r.mu.Unlock()
	return nil
}

func (r *recordingReader) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	r.calls = append(r.calls, "shutdown")
	r.mu.Unlock()
	return r.Reader.Shutdown(ctx)
}

func (r *recordingReader) sequence() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

type poolProbe struct {
	pool    *metricPusherPool
	built   atomic.Int32
	readers []*recordingReader
	mu      sync.Mutex
	fail    error
}

func newPoolProbe(t *testing.T, producer metricProducer) *poolProbe {
	t.Helper()
	probe := &poolProbe{}
	probe.pool = newMetricPusherPool(producer, "node-a")
	probe.pool.newReader = func(_ destination, p sdkmetric.Producer) (sdkmetric.Reader, error) {
		probe.built.Add(1)
		if probe.fail != nil {
			return nil, probe.fail
		}
		reader := &recordingReader{Reader: sdkmetric.NewManualReader(sdkmetric.WithProducer(p))}
		probe.mu.Lock()
		probe.readers = append(probe.readers, reader)
		probe.mu.Unlock()
		return reader, nil
	}
	return probe
}

func testDestination(endpoint string) destination {
	return destination{endpoint: endpoint, insecure: true, interval: time.Minute}
}

func TestOneCollectorGetsOnePusherHoweverManyCRsPointAtIt(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})

	releaseA, err := probe.pool.acquire(testDestination("collector:4318"), []string{"ns"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	releaseB, err := probe.pool.acquire(testDestination("collector:4318"), []string{"ns"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	if got := probe.built.Load(); got != 1 {
		t.Errorf("built %d readers, want 1; the metric stream is node-wide, so a second CR "+
			"pointing at the same collector must share it rather than send the same counters "+
			"again", got)
	}
	if got := probe.pool.size(); got != 1 {
		t.Errorf("pool holds %d pushers, want 1", got)
	}

	if err := releaseA(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := probe.pool.size(); got != 1 {
		t.Errorf("pool holds %d pushers after one release, want 1; the other CR is still using "+
			"it", got)
	}
	if err := releaseB(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := probe.pool.size(); got != 0 {
		t.Errorf("pool holds %d pushers after the last release, want 0", got)
	}
}

func TestDifferentCollectorsGetTheirOwnPusher(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})

	if _, err := probe.pool.acquire(testDestination("a:4318"), []string{"ns"}); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := probe.pool.acquire(testDestination("b:4318"), []string{"ns"}); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	if got := probe.pool.size(); got != 2 {
		t.Errorf("pool holds %d pushers, want 2; two collectors is fan-out, not sharing", got)
	}
}

func TestDestinationIdentityCoversEverythingThatChangesDelivery(t *testing.T) {
	base := destination{
		endpoint: "collector:4318",
		insecure: false,
		headers:  map[string]string{"authorization": "Bearer one"},
		interval: time.Minute,
	}

	variants := map[string]destination{
		"endpoint": {endpoint: "other:4318", insecure: base.insecure, headers: base.headers, interval: base.interval},
		"insecure": {endpoint: base.endpoint, insecure: true, headers: base.headers, interval: base.interval},
		"header":   {endpoint: base.endpoint, insecure: base.insecure, headers: map[string]string{"authorization": "Bearer two"}, interval: base.interval},
		"interval": {endpoint: base.endpoint, insecure: base.insecure, headers: base.headers, interval: 30 * time.Second},
	}
	for name, variant := range variants {
		if variant.key() == base.key() {
			t.Errorf("changing the %s did not change the destination key, so two exporters with "+
				"different delivery would silently share one pusher", name)
		}
	}

	same := destination{
		endpoint: base.endpoint,
		insecure: base.insecure,
		headers:  map[string]string{"authorization": "Bearer one"},
		interval: base.interval,
	}
	if same.key() != base.key() {
		t.Error("two identical destinations produced different keys, so they would not share")
	}
}

func TestHeaderOrderDoesNotChangeTheDestinationKey(t *testing.T) {
	first := destination{endpoint: "c:4318", headers: map[string]string{"a": "1", "b": "2"}}
	second := destination{endpoint: "c:4318", headers: map[string]string{"b": "2", "a": "1"}}
	if first.key() != second.key() {
		t.Error("map iteration order leaked into the key, so sharing would be nondeterministic")
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})

	release, err := probe.pool.acquire(testDestination("collector:4318"), []string{"ns"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	shared, err := probe.pool.acquire(testDestination("collector:4318"), []string{"ns"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := release(context.Background()); err != nil {
			t.Fatalf("release %d: %v", i, err)
		}
	}
	if got := probe.pool.size(); got != 1 {
		t.Errorf("pool holds %d pushers, want 1; three calls to one release must decrement the "+
			"reference once, or the pusher dies while another CR is still using it", got)
	}
	if err := shared(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := probe.pool.size(); got != 0 {
		t.Errorf("pool holds %d pushers, want 0", got)
	}
}

func TestReleaseAfterTheEntryIsGoneIsSafe(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})
	release, err := probe.pool.acquire(testDestination("collector:4318"), []string{"ns"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := release(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
	other, err := probe.pool.acquire(testDestination("collector:4318"), []string{"ns"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := other(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := probe.pool.size(); got != 0 {
		t.Errorf("pool holds %d pushers, want 0", got)
	}
}

func TestReleaseFlushesBeforeShuttingDown(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})

	release, err := probe.pool.acquire(testDestination("collector:4318"), []string{"ns"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := release(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}

	probe.mu.Lock()
	reader := probe.readers[0]
	probe.mu.Unlock()

	got := reader.sequence()
	if len(got) != 2 || got[0] != "flush" || got[1] != "shutdown" {
		t.Errorf("reader saw %v, want flush then shutdown; counters accumulated since the last "+
			"push would be dropped when a CR is deleted", got)
	}
}

func TestAReaderFailureDoesNotLeaveAHalfRegisteredPusher(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})
	probe.fail = errors.New("no route to collector")

	release, err := probe.pool.acquire(testDestination("collector:4318"), []string{"ns"})
	if err == nil {
		t.Fatal("acquire hid the reader failure")
	}
	if got := probe.pool.size(); got != 0 {
		t.Errorf("pool holds %d pushers after a failed build, want 0", got)
	}
	if release == nil {
		t.Fatal("acquire returned a nil release on failure; every caller calls it unconditionally")
	}
	if err := release(context.Background()); err != nil {
		t.Errorf("release after a failed acquire returned %v, want nil", err)
	}
}

func TestNoProducerMeansNoPusher(t *testing.T) {
	pool := newMetricPusherPool(nil, "node-a")
	built := false
	pool.newReader = func(destination, sdkmetric.Producer) (sdkmetric.Reader, error) {
		built = true
		return sdkmetric.NewManualReader(), nil
	}

	release, err := pool.acquire(testDestination("collector:4318"), []string{"ns"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if built {
		t.Error("a pusher started with the metrics plane disabled; there is nothing to send")
	}
	if err := release(context.Background()); err != nil {
		t.Errorf("release: %v", err)
	}
}

func TestNilPoolIsInert(t *testing.T) {
	var pool *metricPusherPool
	release, err := pool.acquire(testDestination("collector:4318"), []string{"ns"})
	if err != nil {
		t.Fatalf("acquire on a nil pool: %v", err)
	}
	if err := release(context.Background()); err != nil {
		t.Errorf("release: %v", err)
	}
}

func TestConcurrentAcquireAndReleaseIsSafe(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				release, err := probe.pool.acquire(testDestination("collector:4318"), []string{"ns"})
				if err != nil {
					t.Errorf("acquire: %v", err)
					return
				}
				_ = release(context.Background())
			}
		}()
	}
	wg.Wait()

	if got := probe.pool.size(); got != 0 {
		t.Errorf("pool holds %d pushers after every reference was released, want 0", got)
	}
}

func TestTheProducerReachesTheReader(t *testing.T) {
	producer := &fakeProducer{}
	probe := newPoolProbe(t, producer)

	if _, err := probe.pool.acquire(testDestination("collector:4318"), []string{"ns"}); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	probe.mu.Lock()
	reader := probe.readers[0]
	probe.mu.Unlock()

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var found bool
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == "podtrace_workload_l7_requests_total" {
				found = true
			}
		}
	}
	if !found {
		t.Error("the workload surface did not reach the reader; the external producer is not " +
			"registered and the push would carry nothing")
	}
}

func TestTheResourceNamesPodtraceAndTheNode(t *testing.T) {
	pool := newMetricPusherPool(&fakeProducer{}, "node-a")
	attrs := map[string]string{}
	for _, kv := range pool.resource().Attributes() {
		attrs[string(kv.Key)] = kv.Value.String()
	}

	if attrs["service.name"] != "podtrace" {
		t.Errorf("service.name = %q, want podtrace; the resource describes the producer of "+
			"these metrics, and workload identity travels as data-point attributes because one "+
			"provider serves every workload on the node", attrs["service.name"])
	}
	if attrs["k8s.node.name"] != "node-a" {
		t.Errorf("k8s.node.name = %q, want node-a", attrs["k8s.node.name"])
	}

	bare := newMetricPusherPool(&fakeProducer{}, "")
	for _, kv := range bare.resource().Attributes() {
		if string(kv.Key) == "k8s.node.name" {
			t.Error("an empty node name was stamped as an attribute")
		}
	}
}

func TestBundleWithoutMetricsAsksForNoDestination(t *testing.T) {
	for name, payload := range map[string]*BundlePayload{
		"nil":      nil,
		"disabled": {Type: bundle.TypeOTLP, Endpoint: "collector:4318"},
	} {
		if _, wanted := destinationFromBundle(payload); wanted {
			t.Errorf("%s bundle asked for a metric destination", name)
		}
	}
}

func TestBundleMetricsDestinationCarriesEveryHeaderSource(t *testing.T) {
	dest, wanted := destinationFromBundle(&BundlePayload{
		Type:          bundle.TypeOTLP,
		Endpoint:      "collector:4318",
		Insecure:      true,
		Metrics:       true,
		Headers:       map[string]string{"x-literal": "one"},
		SecretHeaders: map[string]string{"x-secret": "two"},
		HeaderName:    "authorization",
		Credential:    []byte("Bearer three"),
	})
	if !wanted {
		t.Fatal("a bundle with metrics enabled produced no destination")
	}
	if dest.endpoint != "collector:4318" || !dest.insecure {
		t.Errorf("destination = %+v, want the bundle's endpoint and insecure flag", dest)
	}
	for key, want := range map[string]string{
		"x-literal":     "one",
		"x-secret":      "two",
		"authorization": "Bearer three",
	} {
		if dest.headers[key] != want {
			t.Errorf("header %q = %q, want %q; both signals share an endpoint and must "+
				"authenticate identically", key, dest.headers[key], want)
		}
	}
}

func TestBundleWithNoHeadersProducesNoHeaderMap(t *testing.T) {
	dest, _ := destinationFromBundle(&BundlePayload{
		Type: bundle.TypeOTLP, Endpoint: "collector:4318", Metrics: true,
	})
	if dest.headers != nil {
		t.Errorf("headers = %v, want nil", dest.headers)
	}
}

func TestACredentialWithoutAHeaderNameIsNotSmuggledIn(t *testing.T) {
	dest, _ := destinationFromBundle(&BundlePayload{
		Type: bundle.TypeOTLP, Endpoint: "collector:4318", Metrics: true,
		Headers:    map[string]string{"x-literal": "one"},
		Credential: []byte("Bearer three"),
	})
	if len(dest.headers) != 1 {
		t.Errorf("headers = %v, want only the literal one; a credential with no header name "+
			"has nowhere to go", dest.headers)
	}
}

func TestPushIntervalIsClampedToAUsefulRange(t *testing.T) {
	cases := map[time.Duration]time.Duration{
		0:                     defaultMetricPushInterval,
		-time.Second:          defaultMetricPushInterval,
		time.Second:           minMetricPushInterval,
		30 * time.Second:      30 * time.Second,
		time.Hour:             maxMetricPushInterval,
		maxMetricPushInterval: maxMetricPushInterval,
		minMetricPushInterval: minMetricPushInterval,
	}
	for requested, want := range cases {
		if got := clampPushInterval(requested); got != want {
			t.Errorf("clampPushInterval(%v) = %v, want %v", requested, got, want)
		}
	}
}

func TestPushTimeoutStaysUnderTheShortestInterval(t *testing.T) {
	if metricPushTimeout >= minMetricPushInterval {
		t.Errorf("push timeout %v is not shorter than the minimum interval %v; a slow collector "+
			"would make pushes overlap", metricPushTimeout, minMetricPushInterval)
	}
}

func TestTraceEndpointPathIsNotReusedForMetrics(t *testing.T) {
	cases := map[string]string{
		"":             "",
		"/":            "",
		"/v1/traces":   "",
		"/v1/traces/":  "",
		"/custom/otlp": "/custom/otlp",
	}
	for path, want := range cases {
		if got := metricsPath(path); got != want {
			t.Errorf("metricsPath(%q) = %q, want %q; posting metrics to a trace receiver path "+
				"is rejected, and an empty result leaves the exporter's own /v1/metrics default",
				path, got, want)
		}
	}
}

func TestOTLPExporterStartsAndStopsTheMetricPusher(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})
	payload := &BundlePayload{
		Type: bundle.TypeOTLP, Endpoint: "http://collector:4318", Insecure: true, Metrics: true,
	}

	exporter, err := newOTLPEventExporter(CRKey{Namespace: "ns", Name: "cr"}, payload,
		withMetricPushers(probe.pool))
	if err != nil {
		t.Fatalf("newOTLPEventExporter: %v", err)
	}
	if got := probe.pool.size(); got != 1 {
		t.Fatalf("pool holds %d pushers, want 1", got)
	}

	if err := exporter.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := probe.pool.size(); got != 0 {
		t.Errorf("pool holds %d pushers after Close, want 0; a leaked pusher keeps pushing for "+
			"a CR that no longer exists", got)
	}
}

func TestOTLPExporterWithoutMetricsStartsNoPusher(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})
	payload := &BundlePayload{Type: bundle.TypeOTLP, Endpoint: "http://collector:4318", Insecure: true}

	exporter, err := newOTLPEventExporter(CRKey{Namespace: "ns", Name: "cr"}, payload,
		withMetricPushers(probe.pool))
	if err != nil {
		t.Fatalf("newOTLPEventExporter: %v", err)
	}
	if got := probe.pool.size(); got != 0 {
		t.Errorf("pool holds %d pushers for a bundle that never asked for metrics", got)
	}
	if err := exporter.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestAMetricPushFailureStillYieldsAWorkingSpanExporter(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})
	probe.fail = errors.New("metrics receiver unreachable")

	exporter, err := attachMetricPusher(
		mustSDKExporter(t),
		CRKey{Namespace: "ns", Name: "cr"},
		&BundlePayload{Type: bundle.TypeOTLP, Endpoint: "http://collector:4318", Metrics: true},
		withMetricPushers(probe.pool),
	)
	if err == nil {
		t.Error("the metric-push failure was hidden; the caller classifies and reports it")
	}
	if exporter == nil {
		t.Fatal("no exporter returned; spans are the primary signal and an unreachable metrics " +
			"receiver must not take tracing down with it")
	}
	if err := exporter.Close(context.Background()); err != nil {
		t.Errorf("Close after a failed metric attach: %v", err)
	}
}

func TestAttachIsANoOpWithoutAPool(t *testing.T) {
	exporter := mustSDKExporter(t)
	got, err := attachMetricPusher(exporter, CRKey{Namespace: "ns", Name: "cr"},
		&BundlePayload{Type: bundle.TypeOTLP, Endpoint: "http://collector:4318", Metrics: true})
	if err != nil {
		t.Fatalf("attachMetricPusher: %v", err)
	}
	if got != exporter {
		t.Error("attachMetricPusher replaced the exporter when there was no pool to attach to")
	}
}

func mustSDKExporter(t *testing.T) tracer.Exporter {
	t.Helper()
	exporter, err := newSDKEventExporter("otlp", CRKey{Namespace: "ns", Name: "cr"},
		&BundlePayload{Type: bundle.TypeOTLP, Endpoint: "http://collector:4318"},
		&noopSpanExporter{})
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}
	return exporter
}

func TestReleasingAKeyThePoolNeverHeldIsSafe(t *testing.T) {
	probe := newPoolProbe(t, &fakeProducer{})
	if err := probe.pool.releaseFor("a-key-never-acquired", []string{"ns"})(context.Background()); err != nil {
		t.Errorf("releasing an unknown key returned %v, want nil", err)
	}
	if got := probe.pool.size(); got != 0 {
		t.Errorf("pool holds %d pushers, want 0", got)
	}
}
