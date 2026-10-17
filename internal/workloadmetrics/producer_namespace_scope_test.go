package workloadmetrics

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func allowOnly(namespaces ...string) func(string) bool {
	set := map[string]bool{}
	for _, ns := range namespaces {
		set[ns] = true
	}
	return func(ns string) bool { return set[ns] }
}

func attrs(kv ...string) attribute.Set {
	out := make([]attribute.KeyValue, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, attribute.String(kv[i], kv[i+1]))
	}
	return attribute.NewSet(out...)
}

func floatPoint(set attribute.Set) metricdata.DataPoint[float64] {
	return metricdata.DataPoint[float64]{Attributes: set, Time: time.Unix(1, 0), Value: 1}
}

func intPoint(set attribute.Set) metricdata.DataPoint[int64] {
	return metricdata.DataPoint[int64]{Attributes: set, Time: time.Unix(1, 0), Value: 1}
}

func mixedTenantScopes() []metricdata.ScopeMetrics {
	return []metricdata.ScopeMetrics{{
		Metrics: []metricdata.Metrics{
			{
				Name: "podtrace_workload_l7_requests_total",
				Data: metricdata.Sum[float64]{
					DataPoints: []metricdata.DataPoint[float64]{
						floatPoint(attrs("namespace", "a", "workload", "web")),
						floatPoint(attrs("namespace", "b", "workload", "web")),
						floatPoint(attrs("namespace", "c", "workload", "web")),
					},
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
				},
			},
			{
				Name: "http.server.request.duration",
				Data: metricdata.Histogram[float64]{
					DataPoints: []metricdata.HistogramDataPoint[float64]{
						{Attributes: attrs("k8s.namespace.name", "a"), Count: 1},
						{Attributes: attrs("k8s.namespace.name", "b"), Count: 1},
					},
					Temporality: metricdata.CumulativeTemporality,
				},
			},
			{
				Name: "podtrace_workload_edge_requests_total",
				Data: metricdata.Sum[float64]{
					DataPoints: []metricdata.DataPoint[float64]{
						floatPoint(attrs("namespace", "b", "target_namespace", "a", "workload", "spy")),
						floatPoint(attrs("namespace", "a", "target_namespace", "c", "workload", "web")),
					},
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
				},
			},
			{
				Name: "podtrace_workload_metrics_events_total",
				Data: metricdata.Sum[float64]{
					DataPoints:  []metricdata.DataPoint[float64]{floatPoint(attrs("outcome", "recorded"))},
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
				},
			},
			{
				Name: "podtrace_workload_metrics_series_active",
				Data: metricdata.Gauge[float64]{
					DataPoints: []metricdata.DataPoint[float64]{floatPoint(*attribute.EmptySet())},
				},
			},
			{
				Name: "podtrace_workload_only_b",
				Data: metricdata.Gauge[float64]{
					DataPoints: []metricdata.DataPoint[float64]{floatPoint(attrs("namespace", "b"))},
				},
			},
		},
	}}
}

type pointSummary struct {
	metric    string
	namespace string
	target    string
}

func summarise(t *testing.T, scopes []metricdata.ScopeMetrics) []pointSummary {
	t.Helper()
	var out []pointSummary
	add := func(name string, set attribute.Set) {
		ns, ok := set.Value("namespace")
		if !ok {
			ns, _ = set.Value("k8s.namespace.name")
		}
		target, _ := set.Value("target_namespace")
		out = append(out, pointSummary{metric: name, namespace: ns.AsString(), target: target.AsString()})
	}
	for _, scope := range scopes {
		for _, m := range scope.Metrics {
			switch d := m.Data.(type) {
			case metricdata.Sum[float64]:
				for _, p := range d.DataPoints {
					add(m.Name, p.Attributes)
				}
			case metricdata.Sum[int64]:
				for _, p := range d.DataPoints {
					add(m.Name, p.Attributes)
				}
			case metricdata.Gauge[float64]:
				for _, p := range d.DataPoints {
					add(m.Name, p.Attributes)
				}
			case metricdata.Gauge[int64]:
				for _, p := range d.DataPoints {
					add(m.Name, p.Attributes)
				}
			case metricdata.Histogram[float64]:
				for _, p := range d.DataPoints {
					add(m.Name, p.Attributes)
				}
			case metricdata.Histogram[int64]:
				for _, p := range d.DataPoints {
					add(m.Name, p.Attributes)
				}
			case metricdata.ExponentialHistogram[float64]:
				for _, p := range d.DataPoints {
					add(m.Name, p.Attributes)
				}
			case metricdata.ExponentialHistogram[int64]:
				for _, p := range d.DataPoints {
					add(m.Name, p.Attributes)
				}
			default:
				t.Fatalf("%s has unexpected aggregation %T", m.Name, d)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].metric != out[j].metric {
			return out[i].metric < out[j].metric
		}
		return out[i].namespace+out[i].target < out[j].namespace+out[j].target
	})
	return out
}

func TestFilterNamespacesKeepsOnlyTheAllowedTenant(t *testing.T) {
	got := summarise(t, FilterNamespaces(mixedTenantScopes(), allowOnly("a")))
	want := []pointSummary{
		{metric: "http.server.request.duration", namespace: "a"},
		{metric: "podtrace_workload_edge_requests_total", namespace: "a", target: "c"},
		{metric: "podtrace_workload_l7_requests_total", namespace: "a"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("point %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestFilterNamespacesJudgesAnEdgeByItsSourceNamespace(t *testing.T) {
	for _, p := range summarise(t, FilterNamespaces(mixedTenantScopes(), allowOnly("a"))) {
		if p.metric == "podtrace_workload_edge_requests_total" && p.namespace != "a" {
			t.Errorf("edge from namespace %q into %q reached tenant a", p.namespace, p.target)
		}
	}
}

func TestFilterNamespacesDropsNodeWideSelfObservability(t *testing.T) {
	scopes := FilterNamespaces(mixedTenantScopes(), allowOnly("a", "b", "c"))
	for _, scope := range scopes {
		for _, m := range scope.Metrics {
			if m.Name == "podtrace_workload_metrics_events_total" || m.Name == "podtrace_workload_metrics_series_active" {
				t.Errorf("node-wide series %s was pushed", m.Name)
			}
		}
	}
}

func TestFilterNamespacesRemovesMetricsAndScopesLeftEmpty(t *testing.T) {
	scopes := FilterNamespaces(mixedTenantScopes(), allowOnly("a"))
	for _, scope := range scopes {
		for _, m := range scope.Metrics {
			if m.Name == "podtrace_workload_only_b" {
				t.Error("a metric with no allowed points was kept")
			}
		}
	}
	if got := FilterNamespaces(mixedTenantScopes(), allowOnly()); got != nil {
		t.Errorf("empty scope returned %+v, want nil", got)
	}
	if got := FilterNamespaces(mixedTenantScopes(), allowOnly("unknown")); got != nil {
		t.Errorf("unrelated scope returned %+v, want nil", got)
	}
	if got := FilterNamespaces(mixedTenantScopes(), nil); got != nil {
		t.Errorf("nil predicate returned %+v, want nil", got)
	}
}

func TestFilterNamespacesDoesNotModifyItsInput(t *testing.T) {
	input := mixedTenantScopes()
	before := summarise(t, input)
	_ = FilterNamespaces(input, allowOnly("a"))
	after := summarise(t, input)
	if len(before) != len(after) {
		t.Errorf("input shrank from %d to %d points", len(before), len(after))
	}
}

func TestFilterNamespacesCoversEveryAggregation(t *testing.T) {
	a, b := attrs("namespace", "a"), attrs("namespace", "b")
	scopes := []metricdata.ScopeMetrics{{Metrics: []metricdata.Metrics{
		{Name: "sum_float", Data: metricdata.Sum[float64]{DataPoints: []metricdata.DataPoint[float64]{floatPoint(a), floatPoint(b)}}},
		{Name: "sum_int", Data: metricdata.Sum[int64]{DataPoints: []metricdata.DataPoint[int64]{intPoint(a), intPoint(b)}}},
		{Name: "gauge_float", Data: metricdata.Gauge[float64]{DataPoints: []metricdata.DataPoint[float64]{floatPoint(a), floatPoint(b)}}},
		{Name: "gauge_int", Data: metricdata.Gauge[int64]{DataPoints: []metricdata.DataPoint[int64]{intPoint(a), intPoint(b)}}},
		{Name: "histogram_float", Data: metricdata.Histogram[float64]{DataPoints: []metricdata.HistogramDataPoint[float64]{{Attributes: a}, {Attributes: b}}}},
		{Name: "histogram_int", Data: metricdata.Histogram[int64]{DataPoints: []metricdata.HistogramDataPoint[int64]{{Attributes: a}, {Attributes: b}}}},
		{Name: "exponential_float", Data: metricdata.ExponentialHistogram[float64]{DataPoints: []metricdata.ExponentialHistogramDataPoint[float64]{{Attributes: a}, {Attributes: b}}}},
		{Name: "exponential_int", Data: metricdata.ExponentialHistogram[int64]{DataPoints: []metricdata.ExponentialHistogramDataPoint[int64]{{Attributes: a}, {Attributes: b}}}},
		{Name: "summary", Data: metricdata.Summary{DataPoints: []metricdata.SummaryDataPoint{{Attributes: a}}}},
	}}}

	got := summarise(t, FilterNamespaces(scopes, allowOnly("a")))
	if len(got) != 8 {
		t.Fatalf("got %d points, want one per supported aggregation: %+v", len(got), got)
	}
	for _, p := range got {
		if p.namespace != "a" {
			t.Errorf("%s kept a point from namespace %q", p.metric, p.namespace)
		}
	}
}

func TestNamespaceScopedProducerOverTheRealSinkCarriesOnlyTheScopedTenant(t *testing.T) {
	sink, err := New(prometheus.NewRegistry(), Options{SemanticConventions: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	batch := surfaceExercisingBatch()
	for _, e := range surfaceExercisingBatch() {
		other := *e
		meta := *e.K8s
		meta.Namespace = "bank"
		meta.PodUID = "uid-2"
		other.K8s = &meta
		batch = append(batch, &other)
	}
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	unscoped, err := NewProducer(sink).Produce(context.Background())
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	seen := map[string]bool{}
	for _, p := range summarise(t, unscoped) {
		seen[p.namespace] = true
	}
	if !seen["shop"] || !seen["bank"] || !seen[""] {
		t.Fatalf("fixture does not exercise both tenants and node-wide series: %v", seen)
	}

	scoped, err := NewNamespaceScopedProducer(NewProducer(sink), allowOnly("shop")).Produce(context.Background())
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	points := summarise(t, scoped)
	if len(points) == 0 {
		t.Fatal("the scoped tenant received nothing for its own namespace")
	}
	var semconvSeen bool
	for _, p := range points {
		if p.namespace != "shop" {
			t.Errorf("%s point from namespace %q reached tenant shop", p.metric, p.namespace)
		}
		if p.metric == "http.server.request.duration" {
			semconvSeen = true
		}
	}
	if !semconvSeen {
		t.Error("the convention family keyed by k8s.namespace.name was dropped for its own tenant")
	}
}

func TestNamespaceScopedProducerWithoutAnInnerProducerIsInert(t *testing.T) {
	got, err := NewNamespaceScopedProducer(nil, allowOnly("a")).Produce(context.Background())
	if err != nil || got != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", got, err)
	}
	var nilProducer *NamespaceScopedProducer
	if got, err := nilProducer.Produce(context.Background()); err != nil || got != nil {
		t.Errorf("nil receiver got (%v, %v), want (nil, nil)", got, err)
	}
}

type failingSDKProducer struct{}

func (failingSDKProducer) Produce(context.Context) ([]metricdata.ScopeMetrics, error) {
	return nil, errors.New("gather failed")
}

func TestNamespaceScopedProducerSurfacesTheInnerError(t *testing.T) {
	p := NewNamespaceScopedProducer(failingSDKProducer{}, func(string) bool { return true })
	scopes, err := p.Produce(context.Background())
	if err == nil || scopes != nil {
		t.Errorf("Produce = %v, %v; want the inner error and no data", scopes, err)
	}
}
