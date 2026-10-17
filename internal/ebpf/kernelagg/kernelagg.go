// Package kernelagg drains the kernel-side metric aggregation map.
//
// The BPF probes fold observations into a per-CPU map instead of shipping one
// ringbuf record per event, which is what turns the metrics plane's cost from
// O(events) into O(series). This package reads that map, sums the per-CPU
// copies, and hands the agent deltas to add into the Prometheus collectors it
// already owns.
package kernelagg

import (
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Schema is the Prometheus native-histogram schema the kernel records in.
// Bucket b covers (2^((b-1)/8), 2^(b/8)].
const Schema = 3

// BucketNone marks a row carrying only counters, with no latency observation.
const BucketNone = uint16(0xFFFF)

// MapName and EnabledMapName are the BPF map names this package binds to.
const (
	MapName        = "agg_metrics"
	EnabledMapName = "agg_enabled"
)

// Key mirrors struct agg_key in bpf/agg.h. Field order and padding must match
// the C layout exactly; a mismatch silently misreads every row.
type Key struct {
	CgroupID  uint64
	PeerIP    uint32
	PeerPort  uint16
	EventType uint8
	Variant   uint8
	Bucket    uint16
	Role      uint8
	_         [5]byte
}

// Value mirrors struct agg_value in bpf/agg.h.
type Value struct {
	Count uint64
	SumNS uint64
	Bytes uint64
}

// Row is one drained key with its per-CPU values already summed.
type Row struct {
	Key   Key
	Value Value
}

// Variant unpacks the dimensions the kernel could not derive from event type
// alone.
type Variant struct {
	Transport   uint8
	StatusClass uint8
	IsError     bool
}

// DecodeVariant unpacks the byte packed by AGG_VARIANT in bpf/agg.h.
func DecodeVariant(v uint8) Variant {
	return Variant{
		Transport:   v & 0x7,
		StatusClass: (v >> 3) & 0x7,
		IsError:     v&(1<<6) != 0,
	}
}

// Mode selects what the probes do with an observation.
type Mode uint32

const (
	ModeOff    Mode = 0
	ModeOn     Mode = 1
	ModeBypass Mode = 2
)

func (m Mode) String() string {
	switch m {
	case ModeOn:
		return "on"
	case ModeBypass:
		return "bypass"
	default:
		return "off"
	}
}

// SetMode tells the probes how to treat observations.
func SetMode(m *ebpf.Map, mode Mode) error {
	if m == nil {
		return errors.New("kernelagg: enabled map is nil")
	}
	key := uint32(0)
	value := uint32(mode)
	if err := m.Update(&key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("kernelagg: set mode: %w", err)
	}
	return nil
}

// Drain reads every row and removes it, returning the summed deltas.
//
// Each row is read and removed in one step. Reading every row first and
// deleting them all afterwards loses whatever the probes add to a row in
// between, an undercount that grows with the number of series.
func Drain(m *ebpf.Map) ([]Row, error) {
	if m == nil {
		return nil, errors.New("kernelagg: metrics map is nil")
	}
	iter := m.Iterate()
	t := &mapTaker{m: m}
	return drainRows(iter.Next, iter.Err, t.take)
}

// rowMap is the part of *ebpf.Map a drain uses.
type rowMap interface {
	LookupAndDelete(key, valueOut any) error
	Lookup(key, valueOut any) error
	Delete(key any) error
}

// mapTaker removes one row at a time, atomically where the kernel can.
type mapTaker struct {
	m        rowMap
	separate bool
}

func (t *mapTaker) take(k *Key) (Value, error) {
	var perCPU []Value
	if !t.separate {
		err := t.m.LookupAndDelete(k, &perCPU)
		if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
			return SumPerCPU(perCPU), nil
		}
		if !errors.Is(err, ebpf.ErrNotSupported) && !errors.Is(err, unix.EINVAL) {
			return Value{}, err
		}
		t.separate = true
	}
	if err := t.m.Lookup(k, &perCPU); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Value{}, nil
		}
		return Value{}, err
	}
	if err := t.m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return Value{}, err
	}
	return SumPerCPU(perCPU), nil
}

// drainRows holds the drain logic, separated from the map I/O so it can be
// exercised without a BPF map, creating one needs privileges a unit test
// does not have. Keys are collected first, then each is taken: the read and
// the removal of a row happen together.
func drainRows(
	next func(key, value any) bool,
	iterErr func() error,
	take func(*Key) (Value, error),
) ([]Row, error) {
	var (
		key    Key
		perCPU []Value
		keys   []Key
		rows   []Row
	)

	for next(&key, &perCPU) {
		keys = append(keys, key)
	}
	if err := iterErr(); err != nil {
		return nil, fmt.Errorf("kernelagg: iterate: %w", err)
	}

	for i := range keys {
		total, err := take(&keys[i])
		if err != nil {
			return rows, fmt.Errorf("kernelagg: take: %w", err)
		}
		if total.Count == 0 && total.Bytes == 0 {
			continue
		}
		rows = append(rows, Row{Key: keys[i], Value: total})
	}
	return rows, nil
}

// SumPerCPU folds the per-CPU copies of one row into a single delta.
func SumPerCPU(vals []Value) Value {
	var total Value
	for _, v := range vals {
		total.Count += v.Count
		total.SumNS += v.SumNS
		total.Bytes += v.Bytes
	}
	return total
}

// BucketUpperBound returns the inclusive upper bound, in seconds, of a
// schema-3 bucket.
func BucketUpperBound(bucket uint16) float64 {
	return math.Exp2(float64(bucket) / float64(uint(1)<<Schema))
}

// schemaBounds are the normalized upper bounds of the schema-3 sub-buckets
// within [0.5, 1), matching what client_golang searches when it places a
// value.
var schemaBounds = func() []float64 {
	steps := 1 << Schema
	out := make([]float64, steps)
	for k := 1; k <= steps; k++ {
		out[k-1] = 0.5 * math.Exp2(float64(k)/float64(steps))
	}
	return out
}()

// BucketIndex returns the kernel's bucket for a nanosecond duration,
// mirroring agg_bucket(agg_scale(ns)) in bpf/agg.h.
func BucketIndex(ns uint64) uint16 {
	v := ScaledUnits(ns)
	if v == 0 {
		return 0
	}
	frac, exp := math.Frexp(float64(v))
	return clampBucket(sort.SearchFloat64s(schemaBounds, frac) + (exp-1)*(1<<Schema))
}

const scaleUnitLog2 = 30

// ScaledUnits converts nanoseconds to 2^-30-second units, exactly
// floor(ns * 2^30 / 10^9), in the same integer steps as agg_scale() in
// bpf/agg.h so both sides bucket identically.
func ScaledUnits(ns uint64) uint64 {
	const (
		correction  = 73741824 // 2^30 - 10^9
		nsPerSecond = 1000000000
	)
	whole := ns / nsPerSecond
	rest := ns - whole*nsPerSecond
	return ns + whole*correction + rest*correction/nsPerSecond
}

const nativeIndexOffset = scaleUnitLog2*(1<<Schema) - 1

// NativeIndex returns the Prometheus native-histogram bucket, in seconds, that
// a kernel bucket corresponds to.
func NativeIndex(bucket uint16) int {
	return int(bucket) - nativeIndexOffset
}

// clampBucket narrows a computed index to the width the kernel key uses.
func clampBucket(index int) uint16 {
	if index < 0 {
		return 0
	}
	if index > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(index)
}
