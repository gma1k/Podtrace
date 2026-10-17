package inspect

import (
	"math"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Inspections read metrics, not events.
type Sample struct {
	Namespace    string
	Workload     string
	WorkloadKind string
	Container    string
	Pod          string

	Labels map[string]string

	Value float64

	Count uint64
	Sum   float64

	Buckets []Bucket

	NativeBuckets bool
	NativeSchema  int32
}

// Bucket is one cumulative histogram bucket.
type Bucket struct {
	UpperBound float64
	Count      uint64
}

// Label returns one family-specific label, empty when absent.
func (s Sample) Label(name string) string { return s.Labels[name] }

// Snapshot is one gather, indexed by metric family.
type Snapshot struct {
	At       time.Time
	families map[string][]Sample

	partial bool
}

func (s Snapshot) Family(name string) []Sample { return s.families[name] }

func (s Snapshot) IsZero() bool { return s.At.IsZero() }

// FamilySource yields the current metrics of named families only.
type FamilySource interface {
	CollectFamilies(names []string) map[string][]*dto.Metric
	RuleFamilies() []string
}

// TakeFrom builds a snapshot from a FamilySource, touching only the families
// the rules and the correlation read.
func TakeFrom(src FamilySource, now time.Time) Snapshot {
	names := append(append([]string(nil), src.RuleFamilies()...), EdgeFamilies()...)
	families := src.CollectFamilies(names)

	snap := Snapshot{At: now, families: make(map[string][]Sample, len(families))}
	for name, metrics := range families {
		samples := make([]Sample, 0, len(metrics))
		for _, m := range metrics {
			samples = append(samples, sampleOf(m))
		}
		snap.families[name] = samples
	}
	return snap
}

// Take gathers the registry into a snapshot. Prefer TakeFrom where a
// FamilySource is available.
func Take(g prometheus.Gatherer, now time.Time) (Snapshot, error) {
	families, err := g.Gather()
	if err != nil {
		if len(families) == 0 {
			return Snapshot{}, err
		}
	}
	snap := TakeFamilies(families, now)
	snap.partial = err != nil
	return snap, err
}

// TakeFamilies builds a snapshot from families already gathered, such as a
// decoded /metrics scrape of another process.
func TakeFamilies(families []*dto.MetricFamily, now time.Time) Snapshot {
	snap := Snapshot{At: now, families: make(map[string][]Sample, len(families))}
	for _, f := range families {
		name := f.GetName()
		samples := make([]Sample, 0, len(f.GetMetric()))
		for _, m := range f.GetMetric() {
			samples = append(samples, sampleOf(m))
		}
		snap.families[name] = samples
	}
	return snap
}

// sampleOf reduces one gathered metric to a Sample.
func sampleOf(m *dto.Metric) Sample {
	s := Sample{Labels: map[string]string{}}
	for _, pair := range m.GetLabel() {
		name, value := pair.GetName(), pair.GetValue()
		switch name {
		case "namespace":
			s.Namespace = value
		case "workload":
			s.Workload = value
		case "workload_kind":
			s.WorkloadKind = value
		case "container":
			s.Container = value
		case "pod":
			s.Pod = value
		default:
			s.Labels[name] = value
		}
	}

	switch {
	case m.GetCounter() != nil:
		s.Value = m.GetCounter().GetValue()
	case m.GetGauge() != nil:
		s.Value = m.GetGauge().GetValue()
	case m.GetHistogram() != nil:
		h := m.GetHistogram()
		s.Count = h.GetSampleCount()
		s.Sum = h.GetSampleSum()
		s.Value = h.GetSampleSum()
		if raw := h.GetBucket(); len(raw) > 0 {
			s.Buckets = make([]Bucket, 0, len(raw))
			for _, b := range raw {
				s.Buckets = append(s.Buckets, Bucket{
					UpperBound: b.GetUpperBound(),
					Count:      b.GetCumulativeCount(),
				})
			}
		} else if native := nativeBuckets(h); len(native) > 0 {
			s.Buckets = native
			s.NativeBuckets = true
			s.NativeSchema = h.GetSchema()
		}
	case m.GetUntyped() != nil:
		s.Value = m.GetUntyped().GetValue()
	}
	return s
}

// nativeBuckets decodes a native (exponential) histogram into cumulative
// buckets in upper-bound order.
func nativeBuckets(h *dto.Histogram) []Bucket {
	if len(h.GetPositiveSpan()) == 0 && h.GetZeroCount() == 0 {
		return nil
	}
	base := nativeBase(h.GetSchema())

	out := make([]Bucket, 0, len(h.GetPositiveDelta())+1)
	var cumulative uint64
	if zero := h.GetZeroCount(); zero > 0 {
		cumulative = zero
		out = append(out, Bucket{UpperBound: h.GetZeroThreshold(), Count: cumulative})
	}

	deltas := h.GetPositiveDelta()
	var index int32
	var count int64
	next := 0
	for spanNumber, span := range h.GetPositiveSpan() {
		if spanNumber == 0 {
			index = span.GetOffset()
		} else {
			index += span.GetOffset()
		}
		for i := uint32(0); i < span.GetLength(); i++ {
			if next >= len(deltas) {
				return nil
			}
			count += deltas[next]
			next++
			if count < 0 {
				return nil
			}
			cumulative += uint64(count)
			out = append(out, Bucket{UpperBound: math.Pow(base, float64(index)), Count: cumulative})
			index++
		}
	}
	return out
}

// nativeBase is the growth factor between adjacent buckets of a schema.
func nativeBase(schema int32) float64 {
	return math.Pow(2, math.Pow(2, -float64(schema)))
}

// nativeBoundaryAtOrAbove returns the smallest bucket boundary of the schema
// that is not below bound.
func nativeBoundaryAtOrAbove(bound float64, schema int32) float64 {
	base := nativeBase(schema)
	index := math.Ceil(math.Log(bound)/math.Log(base) - 1e-9)
	return math.Pow(base, index)
}

// seriesKey identifies a series across snapshots so a delta can be taken.
func seriesKey(s Sample) string {
	key := s.Namespace + "\x00" + s.Workload + "\x00" + s.WorkloadKind +
		"\x00" + s.Container + "\x00" + s.Pod
	for _, name := range sortedKeys(s.Labels) {
		key += "\x00" + name + "=" + s.Labels[name]
	}
	return key
}
