package workloadmetrics

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Producer republishes the workload surface as OTLP metrics.
type Producer struct {
	gatherer gatherer
	scope    instrumentation.Scope
	start    time.Time
	now      func() time.Time
}

// gatherer is the read side of a Prometheus registry.
type gatherer interface {
	Gather() ([]*dto.MetricFamily, error)
}

// NewProducer builds a Producer over a Prometheus gatherer. Pass the Sink
// itself to publish exactly the workload surface.
func NewProducer(g gatherer) *Producer {
	return &Producer{
		gatherer: g,
		scope: instrumentation.Scope{
			Name: producerScopeName,
		},
		start: time.Now(),
		now:   time.Now,
	}
}

const producerScopeName = "podtrace.io/workloadmetrics"

// Produce converts the current Prometheus surface into OTLP metric data.
func (p *Producer) Produce(context.Context) ([]metricdata.ScopeMetrics, error) {
	if p == nil || p.gatherer == nil {
		return nil, nil
	}
	families, err := p.gatherer.Gather()
	if err != nil {
		return nil, fmt.Errorf("gather workload metrics: %w", err)
	}
	if len(families) == 0 {
		return nil, nil
	}

	now := p.now()
	out := make([]metricdata.Metrics, 0, len(families))
	for _, family := range families {
		if converted, ok := p.convertFamily(family, now); ok {
			out = append(out, converted)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return []metricdata.ScopeMetrics{{Scope: p.scope, Metrics: out}}, nil
}

func (p *Producer) convertFamily(family *dto.MetricFamily, now time.Time) (metricdata.Metrics, bool) {
	if family == nil || len(family.GetMetric()) == 0 {
		return metricdata.Metrics{}, false
	}
	name, unit := otlpIdentityFor(family.GetName())
	out := metricdata.Metrics{
		Name:        name,
		Description: family.GetHelp(),
		Unit:        unit,
	}

	switch family.GetType() {
	case dto.MetricType_COUNTER:
		out.Data = p.counterData(family, now)
	case dto.MetricType_GAUGE:
		out.Data = p.gaugeData(family, now)
	case dto.MetricType_HISTOGRAM:
		data, ok := p.histogramData(family, now)
		if !ok {
			return metricdata.Metrics{}, false
		}
		out.Data = data
	default:
		return metricdata.Metrics{}, false
	}
	return out, true
}

func (p *Producer) counterData(family *dto.MetricFamily, now time.Time) metricdata.Sum[float64] {
	points := make([]metricdata.DataPoint[float64], 0, len(family.GetMetric()))
	for _, m := range family.GetMetric() {
		counter := m.GetCounter()
		if counter == nil {
			continue
		}
		points = append(points, metricdata.DataPoint[float64]{
			Attributes: p.attributes(family.GetName(), m),
			StartTime:  p.startTime(counter.GetCreatedTimestamp().AsTime()),
			Time:       now,
			Value:      counter.GetValue(),
		})
	}
	return metricdata.Sum[float64]{
		DataPoints:  points,
		Temporality: metricdata.CumulativeTemporality,
		IsMonotonic: true,
	}
}

func (p *Producer) gaugeData(family *dto.MetricFamily, now time.Time) metricdata.Gauge[float64] {
	points := make([]metricdata.DataPoint[float64], 0, len(family.GetMetric()))
	for _, m := range family.GetMetric() {
		gauge := m.GetGauge()
		if gauge == nil {
			continue
		}
		points = append(points, metricdata.DataPoint[float64]{
			Attributes: p.attributes(family.GetName(), m),
			Time:       now,
			Value:      gauge.GetValue(),
		})
	}
	return metricdata.Gauge[float64]{DataPoints: points}
}

// histogramData converts a histogram family, choosing the exponential
// representation when the family carries native-histogram spans.
func (p *Producer) histogramData(family *dto.MetricFamily, now time.Time) (metricdata.Aggregation, bool) {
	metrics := family.GetMetric()
	if isNativeHistogram(metrics[0].GetHistogram()) {
		points := make([]metricdata.ExponentialHistogramDataPoint[float64], 0, len(metrics))
		for _, m := range metrics {
			point, ok := p.exponentialPoint(family.GetName(), m, now)
			if !ok {
				return nil, false
			}
			points = append(points, point)
		}
		return metricdata.ExponentialHistogram[float64]{
			DataPoints:  points,
			Temporality: metricdata.CumulativeTemporality,
		}, true
	}

	points := make([]metricdata.HistogramDataPoint[float64], 0, len(metrics))
	for _, m := range metrics {
		histogram := m.GetHistogram()
		if histogram == nil {
			continue
		}
		points = append(points, p.classicPoint(family.GetName(), m, histogram, now))
	}
	return metricdata.Histogram[float64]{
		DataPoints:  points,
		Temporality: metricdata.CumulativeTemporality,
	}, true
}

// classicPoint differences Prometheus' cumulative buckets into the
// per-bucket counts OTLP expects.
func (p *Producer) classicPoint(
	familyName string,
	m *dto.Metric,
	histogram *dto.Histogram,
	now time.Time,
) metricdata.HistogramDataPoint[float64] {
	buckets := make([]*dto.Bucket, 0, len(histogram.GetBucket()))
	for _, b := range histogram.GetBucket() {
		if math.IsInf(b.GetUpperBound(), 1) {
			continue
		}
		buckets = append(buckets, b)
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].GetUpperBound() < buckets[j].GetUpperBound()
	})

	bounds := make([]float64, 0, len(buckets))
	counts := make([]uint64, 0, len(buckets)+1)
	var previous uint64
	for _, b := range buckets {
		cumulative := bucketCount(b)
		bounds = append(bounds, b.GetUpperBound())
		counts = append(counts, saturatingSub(cumulative, previous))
		previous = cumulative
	}
	total := histogramCount(histogram)
	// The overflow bucket: everything above the last finite bound.
	counts = append(counts, saturatingSub(total, previous))

	return metricdata.HistogramDataPoint[float64]{
		Attributes:   p.attributes(familyName, m),
		StartTime:    p.startTime(histogram.GetCreatedTimestamp().AsTime()),
		Time:         now,
		Count:        total,
		Bounds:       bounds,
		BucketCounts: counts,
		Sum:          histogram.GetSampleSum(),
	}
}

// exponentialPoint converts a native histogram.
func (p *Producer) exponentialPoint(
	familyName string,
	m *dto.Metric,
	now time.Time,
) (metricdata.ExponentialHistogramDataPoint[float64], bool) {
	histogram := m.GetHistogram()
	scale := histogram.GetSchema()
	if scale < minExponentialScale || scale > maxExponentialScale {
		return metricdata.ExponentialHistogramDataPoint[float64]{}, false
	}

	positive, ok := exponentialBucket(histogram.GetPositiveSpan(), histogram.GetPositiveDelta(), histogram.GetPositiveCount())
	if !ok {
		return metricdata.ExponentialHistogramDataPoint[float64]{}, false
	}
	negative, ok := exponentialBucket(histogram.GetNegativeSpan(), histogram.GetNegativeDelta(), histogram.GetNegativeCount())
	if !ok {
		return metricdata.ExponentialHistogramDataPoint[float64]{}, false
	}

	return metricdata.ExponentialHistogramDataPoint[float64]{
		Attributes:     p.attributes(familyName, m),
		StartTime:      p.startTime(histogram.GetCreatedTimestamp().AsTime()),
		Time:           now,
		Count:          histogramCount(histogram),
		Sum:            histogram.GetSampleSum(),
		Scale:          scale,
		ZeroCount:      zeroCount(histogram),
		ZeroThreshold:  histogram.GetZeroThreshold(),
		PositiveBucket: positive,
		NegativeBucket: negative,
	}, true
}

// OTLP exponential histograms are defined for base 2^(2^-scale); the
// Prometheus schemas that describe the same layout are -4 through 8.
const (
	minExponentialScale = -4
	maxExponentialScale = 8
)

// exponentialBucket decodes one side of a native histogram into a
// contiguous OTLP bucket run.
func exponentialBucket(spans []*dto.BucketSpan, deltas []int64, absolute []float64) (metricdata.ExponentialBucket, bool) {
	if len(spans) == 0 {
		return metricdata.ExponentialBucket{}, true
	}

	indexed, ok := decodeSpans(spans, deltas, absolute)
	if !ok {
		return metricdata.ExponentialBucket{}, false
	}
	if len(indexed) == 0 {
		return metricdata.ExponentialBucket{}, true
	}

	lowest, highest := indexed[0].index, indexed[len(indexed)-1].index
	counts := make([]uint64, int(highest-lowest)+1)
	for _, b := range indexed {
		counts[b.index-lowest] = b.count
	}
	return metricdata.ExponentialBucket{
		// A Prometheus index i covers (base^(i-1), base^i], an OTLP index
		// j covers (base^j, base^(j+1)]. Hence the minus one.
		Offset: lowest - 1,
		Counts: counts,
	}, true
}

type indexedBucket struct {
	index int32
	count uint64
}

// decodeSpans walks Prometheus' span encoding into absolute bucket
// indices.
func decodeSpans(spans []*dto.BucketSpan, deltas []int64, absolute []float64) ([]indexedBucket, bool) {
	buckets := len(deltas)
	if buckets == 0 {
		buckets = len(absolute)
	}

	out := make([]indexedBucket, 0, buckets)
	var index int32
	var running int64
	var consumed int
	for i, span := range spans {
		if span == nil {
			return nil, false
		}
		if i == 0 {
			index = span.GetOffset()
		} else {
			index += span.GetOffset()
		}
		for j := uint32(0); j < span.GetLength(); j++ {
			if consumed >= buckets {
				return nil, false
			}
			var count uint64
			if len(deltas) > 0 {
				running += deltas[consumed]
				if running < 0 {
					return nil, false
				}
				count = uint64(running)
			} else {
				value := absolute[consumed]
				if value < 0 || math.IsNaN(value) {
					return nil, false
				}
				count = floatToCount(value)
			}
			out = append(out, indexedBucket{index: index, count: count})
			consumed++
			index++
		}
	}
	if consumed != buckets {
		return nil, false
	}
	return out, true
}

// isNativeHistogram reports whether a histogram carries the sparse
// exponential representation rather than fixed buckets.
func isNativeHistogram(h *dto.Histogram) bool {
	if h == nil {
		return false
	}
	if len(h.GetPositiveSpan()) > 0 || len(h.GetNegativeSpan()) > 0 {
		return true
	}
	return len(h.GetBucket()) == 0 && h.Schema != nil
}

// startTime prefers the created timestamp client_golang reports, falling
// back to when this Producer was built.
func (p *Producer) startTime(created time.Time) time.Time {
	if created.IsZero() || created.Unix() <= 0 {
		return p.start
	}
	return created
}

// attributes renders a metric's label pairs as OTLP attributes, using the
// convention's own dotted keys for the semantic-convention families.
func (p *Producer) attributes(familyName string, m *dto.Metric) attribute.Set {
	pairs := m.GetLabel()
	if len(pairs) == 0 {
		return *attribute.EmptySet()
	}
	semconvFamily := isSemconvFamily(familyName)
	attrs := make([]attribute.KeyValue, 0, len(pairs))
	for _, pair := range pairs {
		key := pair.GetName()
		if semconvFamily {
			key = semconvAttributeKey(key)
		}
		attrs = append(attrs, attribute.String(key, pair.GetValue()))
	}
	return attribute.NewSet(attrs...)
}

// bucketCount, histogramCount and zeroCount read the integer or float
// variant, whichever the exposition used.
func bucketCount(b *dto.Bucket) uint64 {
	if b.CumulativeCount != nil {
		return b.GetCumulativeCount()
	}
	return floatToCount(b.GetCumulativeCountFloat())
}

func histogramCount(h *dto.Histogram) uint64 {
	if h.SampleCount != nil {
		return h.GetSampleCount()
	}
	return floatToCount(h.GetSampleCountFloat())
}

func zeroCount(h *dto.Histogram) uint64 {
	if h.ZeroCount != nil {
		return h.GetZeroCount()
	}
	return floatToCount(h.GetZeroCountFloat())
}

func floatToCount(v float64) uint64 {
	if v <= 0 || math.IsNaN(v) {
		return 0
	}
	if v >= math.MaxUint64 {
		return math.MaxUint64
	}
	return uint64(v)
}

// saturatingSub keeps a non-monotonic snapshot from wrapping around.
func saturatingSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

var _ sdkmetric.Producer = (*Producer)(nil)

const (
	namespaceAttribute        = attribute.Key("namespace")
	semconvNamespaceAttribute = attribute.Key("k8s.namespace.name")
)

// FilterNamespaces keeps only the data points whose namespace is allowed,
// so one tenant's push never carries another tenant's series.
func FilterNamespaces(scopeMetrics []metricdata.ScopeMetrics, allowed func(string) bool) []metricdata.ScopeMetrics {
	if len(scopeMetrics) == 0 || allowed == nil {
		return nil
	}
	keep := func(set attribute.Set) bool {
		if value, ok := set.Value(namespaceAttribute); ok {
			return allowed(value.AsString())
		}
		if value, ok := set.Value(semconvNamespaceAttribute); ok {
			return allowed(value.AsString())
		}
		return false
	}

	var out []metricdata.ScopeMetrics
	for _, scope := range scopeMetrics {
		var metrics []metricdata.Metrics
		for _, m := range scope.Metrics {
			data, ok := filterAggregation(m.Data, keep)
			if !ok {
				continue
			}
			m.Data = data
			metrics = append(metrics, m)
		}
		if len(metrics) == 0 {
			continue
		}
		scope.Metrics = metrics
		out = append(out, scope)
	}
	return out
}

// filterAggregation applies keep to every data point of one metric,
// reporting false when nothing survives or the aggregation is unknown.
func filterAggregation(data metricdata.Aggregation, keep func(attribute.Set) bool) (metricdata.Aggregation, bool) {
	switch d := data.(type) {
	case metricdata.Sum[float64]:
		d.DataPoints = filterPoints(d.DataPoints, func(p metricdata.DataPoint[float64]) attribute.Set { return p.Attributes }, keep)
		return d, len(d.DataPoints) > 0
	case metricdata.Sum[int64]:
		d.DataPoints = filterPoints(d.DataPoints, func(p metricdata.DataPoint[int64]) attribute.Set { return p.Attributes }, keep)
		return d, len(d.DataPoints) > 0
	case metricdata.Gauge[float64]:
		d.DataPoints = filterPoints(d.DataPoints, func(p metricdata.DataPoint[float64]) attribute.Set { return p.Attributes }, keep)
		return d, len(d.DataPoints) > 0
	case metricdata.Gauge[int64]:
		d.DataPoints = filterPoints(d.DataPoints, func(p metricdata.DataPoint[int64]) attribute.Set { return p.Attributes }, keep)
		return d, len(d.DataPoints) > 0
	case metricdata.Histogram[float64]:
		d.DataPoints = filterPoints(d.DataPoints, func(p metricdata.HistogramDataPoint[float64]) attribute.Set { return p.Attributes }, keep)
		return d, len(d.DataPoints) > 0
	case metricdata.Histogram[int64]:
		d.DataPoints = filterPoints(d.DataPoints, func(p metricdata.HistogramDataPoint[int64]) attribute.Set { return p.Attributes }, keep)
		return d, len(d.DataPoints) > 0
	case metricdata.ExponentialHistogram[float64]:
		d.DataPoints = filterPoints(d.DataPoints, func(p metricdata.ExponentialHistogramDataPoint[float64]) attribute.Set { return p.Attributes }, keep)
		return d, len(d.DataPoints) > 0
	case metricdata.ExponentialHistogram[int64]:
		d.DataPoints = filterPoints(d.DataPoints, func(p metricdata.ExponentialHistogramDataPoint[int64]) attribute.Set { return p.Attributes }, keep)
		return d, len(d.DataPoints) > 0
	default:
		return nil, false
	}
}

func filterPoints[P any](points []P, attributes func(P) attribute.Set, keep func(attribute.Set) bool) []P {
	var out []P
	for _, point := range points {
		if keep(attributes(point)) {
			out = append(out, point)
		}
	}
	return out
}

// NamespaceScopedProducer wraps a producer so that only the namespaces
// allowed at Produce time reach the caller. allowed is consulted on every
// point, so it must be safe for concurrent use.
type NamespaceScopedProducer struct {
	inner   sdkmetric.Producer
	allowed func(string) bool
}

// NewNamespaceScopedProducer builds a NamespaceScopedProducer over inner.
func NewNamespaceScopedProducer(inner sdkmetric.Producer, allowed func(string) bool) *NamespaceScopedProducer {
	return &NamespaceScopedProducer{inner: inner, allowed: allowed}
}

// Produce returns the inner producer's metrics restricted to the allowed
// namespaces.
func (p *NamespaceScopedProducer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	if p == nil || p.inner == nil {
		return nil, nil
	}
	scopeMetrics, err := p.inner.Produce(ctx)
	if err != nil {
		return nil, err
	}
	return FilterNamespaces(scopeMetrics, p.allowed), nil
}

var _ sdkmetric.Producer = (*NamespaceScopedProducer)(nil)
