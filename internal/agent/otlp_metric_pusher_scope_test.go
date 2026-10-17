package agent

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

type tenantProducer struct{}

func (tenantProducer) Produce(context.Context) ([]metricdata.ScopeMetrics, error) {
	point := func(kv ...attribute.KeyValue) metricdata.DataPoint[float64] {
		return metricdata.DataPoint[float64]{Attributes: attribute.NewSet(kv...), Value: 1}
	}
	return []metricdata.ScopeMetrics{{
		Metrics: []metricdata.Metrics{
			{
				Name: "podtrace_workload_l7_requests_total",
				Data: metricdata.Sum[float64]{
					DataPoints: []metricdata.DataPoint[float64]{
						point(attribute.String("namespace", "a")),
						point(attribute.String("namespace", "b")),
						point(attribute.String("namespace", "c")),
					},
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
				},
			},
			{
				Name: "podtrace_workload_metrics_events_total",
				Data: metricdata.Sum[float64]{
					DataPoints:  []metricdata.DataPoint[float64]{point(attribute.String("outcome", "recorded"))},
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
				},
			},
		},
	}}, nil
}

func pushedNamespaces(t *testing.T, probe *poolProbe, index int) []string {
	t.Helper()
	probe.mu.Lock()
	reader := probe.readers[index]
	probe.mu.Unlock()

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	out := []string{}
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			sum, ok := m.Data.(metricdata.Sum[float64])
			if !ok {
				t.Fatalf("%s arrived as %T", m.Name, m.Data)
			}
			for _, p := range sum.DataPoints {
				ns, _ := p.Attributes.Value("namespace")
				out = append(out, ns.AsString())
			}
		}
	}
	sort.Strings(out)
	return out
}

func metricsBundle(targetNamespaces []string) *BundlePayload {
	return &BundlePayload{
		Type:             bundle.TypeOTLP,
		Endpoint:         "http://collector:4318",
		Insecure:         true,
		Metrics:          true,
		TargetNamespaces: targetNamespaces,
	}
}

func TestATenantNeverReceivesAnotherNamespacesSeries(t *testing.T) {
	probe := newPoolProbe(t, tenantProducer{})

	exporter, err := newOTLPEventExporter(CRKey{Namespace: "a", Name: "cr"}, metricsBundle(nil),
		withMetricPushers(probe.pool))
	if err != nil {
		t.Fatalf("newOTLPEventExporter: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Close(context.Background()) })

	if got, want := pushedNamespaces(t, probe, 0), []string{"a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("tenant in namespace a received series from %v, want %v", got, want)
	}
}

func TestCRsSharingACollectorGetTheUnionOfTheirNamespaces(t *testing.T) {
	probe := newPoolProbe(t, tenantProducer{})

	releaseA, err := probe.pool.acquire(testDestination("collector:4318"), []string{"a"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	releaseB, err := probe.pool.acquire(testDestination("collector:4318"), []string{"b"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if got := probe.built.Load(); got != 1 {
		t.Fatalf("built %d pushers for one collector, want 1", got)
	}
	if got, want := pushedNamespaces(t, probe, 0), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("shared pusher sent %v, want %v", got, want)
	}

	if err := releaseB(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got, want := pushedNamespaces(t, probe, 0), []string{"a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("after releasing b the pusher sent %v, want %v", got, want)
	}
	if err := releaseA(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
}

func TestANamespaceSharedByTwoCRsSurvivesOneRelease(t *testing.T) {
	probe := newPoolProbe(t, tenantProducer{})

	first, err := probe.pool.acquire(testDestination("collector:4318"), []string{"a"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	second, err := probe.pool.acquire(testDestination("collector:4318"), []string{"a", "b"})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	t.Cleanup(func() { _ = second(context.Background()) })

	if err := first(context.Background()); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got, want := pushedNamespaces(t, probe, 0), []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("after one of two CRs scoped to a left, the pusher sent %v, want %v", got, want)
	}
}

func TestAnEmptyTargetAllowlistPushesNothing(t *testing.T) {
	probe := newPoolProbe(t, tenantProducer{})

	exporter, err := newOTLPEventExporter(CRKey{Namespace: "a", Name: "cr"}, metricsBundle([]string{}),
		withMetricPushers(probe.pool))
	if err != nil {
		t.Fatalf("newOTLPEventExporter: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Close(context.Background()) })

	if got := pushedNamespaces(t, probe, 0); len(got) != 0 {
		t.Errorf("a selector that matched no namespaces pushed %v, want nothing", got)
	}
}

func TestConsentedTargetNamespacesReplaceTheCRNamespace(t *testing.T) {
	probe := newPoolProbe(t, tenantProducer{})

	exporter, err := newOTLPEventExporter(CRKey{Namespace: "a", Name: "cr"}, metricsBundle([]string{"b", "c"}),
		withMetricPushers(probe.pool))
	if err != nil {
		t.Fatalf("newOTLPEventExporter: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Close(context.Background()) })

	if got, want := pushedNamespaces(t, probe, 0), []string{"b", "c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("pushed %v, want exactly the consented targets %v", got, want)
	}
}

func TestMetricNamespaceScopeMirrorsTheMatcher(t *testing.T) {
	cases := []struct {
		name    string
		crNs    string
		targets []string
		want    []string
	}{
		{name: "nil allowlist falls back to the CR namespace", crNs: "a", targets: nil, want: []string{"a"}},
		{name: "empty allowlist matches nothing", crNs: "a", targets: []string{}, want: []string{}},
		{name: "allowlist replaces the CR namespace", crNs: "a", targets: []string{"b"}, want: []string{"b"}},
		{name: "duplicates and blanks are dropped", crNs: "a", targets: []string{"b", "", "b", "c"}, want: []string{"b", "c"}},
		{name: "no CR namespace and no allowlist is nothing", crNs: "", targets: nil, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := metricNamespaceScope(tc.crNs, tc.targets); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("metricNamespaceScope(%q, %v) = %v, want %v", tc.crNs, tc.targets, got, tc.want)
			}
		})
	}
}
