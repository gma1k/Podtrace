package kernelagg

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestKeyAndValueMatchTheKernelLayout(t *testing.T) {
	if got := binary.Size(Key{}); got != 24 {
		t.Errorf("binary.Size(Key) = %d, want 24 to match struct agg_key. A mismatch does not "+
			"fail loudly at every row — it can silently misread the key and attribute metrics "+
			"to the wrong workload", got)
	}
	if got := binary.Size(Value{}); got != 24 {
		t.Errorf("binary.Size(Value) = %d, want 24 to match struct agg_value", got)
	}
}

func TestBucketIndexMatchesTheDocumentedSchema(t *testing.T) {
	if BucketIndex(0) != 0 {
		t.Error("zero must land in bucket 0")
	}
	for _, tc := range []struct {
		ns   uint64
		want uint16
	}{
		{1000, 80}, {1_000_000, 160}, {30_000_000_000, 279},
	} {
		if got := BucketIndex(tc.ns); got != tc.want {
			t.Errorf("BucketIndex(%d) = %d, want %d; the Go and BPF indices must agree or the "+
				"emitted histogram is keyed on buckets the kernel never used", tc.ns, got, tc.want)
		}
	}
}

func TestSumPerCPUFoldsEveryCPUsCopy(t *testing.T) {
	got := SumPerCPU([]Value{
		{Count: 2, SumNS: 100, Bytes: 10},
		{Count: 3, SumNS: 200, Bytes: 20},
		{},
	})
	want := Value{Count: 5, SumNS: 300, Bytes: 30}
	if got != want {
		t.Errorf("SumPerCPU = %+v, want %+v. A per-CPU map hands back one value per CPU; "+
			"reading only the first would under-report by a factor of the core count", got, want)
	}
	if got := SumPerCPU(nil); got != (Value{}) {
		t.Errorf("SumPerCPU(nil) = %+v, want zero", got)
	}
}

type fakeMap struct {
	rows    map[Key]Value
	order   []Key
	pos     int
	err     error
	taken   []Key
	takeErr error
	onTake  func(k Key)
}

func newFakeMap(rows ...Row) *fakeMap {
	f := &fakeMap{rows: map[Key]Value{}}
	for _, r := range rows {
		f.rows[r.Key] = r.Value
		f.order = append(f.order, r.Key)
	}
	return f
}

func (f *fakeMap) next(key, value any) bool {
	if f.pos >= len(f.order) {
		return false
	}
	k := f.order[f.pos]
	f.pos++
	*(key.(*Key)) = k
	*(value.(*[]Value)) = []Value{f.rows[k]}
	return true
}

func (f *fakeMap) errFn() error { return f.err }

func (f *fakeMap) take(k *Key) (Value, error) {
	f.taken = append(f.taken, *k)
	if f.takeErr != nil {
		return Value{}, f.takeErr
	}
	if f.onTake != nil {
		f.onTake(*k)
	}
	v := f.rows[*k]
	delete(f.rows, *k)
	return v, nil
}

func TestDrainReturnsDeltasAndClearsEveryKey(t *testing.T) {
	f := newFakeMap(
		Row{Key: Key{CgroupID: 1, Bucket: 10}, Value: Value{Count: 2, SumNS: 500}},
		Row{Key: Key{CgroupID: 2, Bucket: BucketNone}, Value: Value{Bytes: 90}},
	)

	rows, err := drainRows(f.next, f.errFn, f.take)
	if err != nil {
		t.Fatalf("drainRows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("returned %d rows, want 2", len(rows))
	}
	if len(f.rows) != 0 {
		t.Errorf("%d keys left in the map, want 0. A row left behind is counted again next drain, "+
			"double-reporting the interval", len(f.rows))
	}
}

func TestAnIncrementDuringTheDrainIsReportedNotDeleted(t *testing.T) {
	first := Key{CgroupID: 1}
	second := Key{CgroupID: 2}
	f := newFakeMap(
		Row{Key: first, Value: Value{Count: 1}},
		Row{Key: second, Value: Value{Count: 1}},
	)
	f.onTake = func(k Key) {
		if k == second {
			v := f.rows[first]
			v.Count += 5
			f.rows[first] = v
		}
	}

	rows, err := drainRows(f.next, f.errFn, f.take)
	if err != nil {
		t.Fatalf("drainRows: %v", err)
	}
	var reported uint64
	for _, r := range rows {
		reported += r.Value.Count
	}
	left := f.rows[first].Count
	if reported+left != 7 {
		t.Errorf("reported %d and left %d of 7 increments; an increment that lands while the drain runs "+
			"must be reported now or stay for the next drain, never deleted unseen", reported, left)
	}
}

func TestAnEmptyRowIsClearedButNotReported(t *testing.T) {
	f := newFakeMap(Row{Key: Key{CgroupID: 7}, Value: Value{}})

	rows, err := drainRows(f.next, f.errFn, f.take)
	if err != nil {
		t.Fatalf("drainRows: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("returned %d rows for a zero delta, want 0", len(rows))
	}
	if len(f.taken) != 1 {
		t.Errorf("an empty row must still be cleared, or it accumulates in a bounded map")
	}
}

func TestDrainSurfacesIterationAndTakeFailures(t *testing.T) {
	f := newFakeMap()
	f.err = errors.New("iterate exploded")
	if _, err := drainRows(f.next, f.errFn, f.take); err == nil {
		t.Error("an iteration failure was swallowed; the drain would look like an idle interval")
	}

	f2 := newFakeMap(
		Row{Key: Key{CgroupID: 1}, Value: Value{Count: 1}},
	)
	f2.takeErr = errors.New("take exploded")
	if _, err := drainRows(f2.next, f2.errFn, f2.take); err == nil {
		t.Error("a take failure was swallowed; those rows are counted again next drain")
	}
}

func TestNilMapsAreRejectedRatherThanPanicking(t *testing.T) {
	if _, err := Drain(nil); err == nil {
		t.Error("Drain(nil) returned no error")
	}
	if err := SetMode(nil, ModeOn); err == nil {
		t.Error("SetMode(nil) returned no error")
	}
}

func TestVariantRoundTripsThroughTheKernelPacking(t *testing.T) {
	cases := []struct {
		raw  uint8
		want Variant
	}{
		{0, Variant{}},
		{2, Variant{Transport: 2}},
		{5 << 3, Variant{StatusClass: 5}},
		{1 << 6, Variant{IsError: true}},
		{3 | 4<<3 | 1<<6, Variant{Transport: 3, StatusClass: 4, IsError: true}},
	}
	for _, tc := range cases {
		if got := DecodeVariant(tc.raw); got != tc.want {
			t.Errorf("DecodeVariant(%d) = %+v, want %+v. The byte is packed by AGG_VARIANT in "+
				"bpf/agg.h; a decode that disagrees mislabels protocol and outcome", tc.raw, got, tc.want)
		}
	}
}

func TestModeNamesAreStableForLogs(t *testing.T) {
	for mode, want := range map[Mode]string{
		ModeOff: "off", ModeOn: "on", ModeBypass: "bypass", Mode(99): "off",
	} {
		if got := mode.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", mode, got, want)
		}
	}
}

func TestBucketUpperBoundMatchesTheSchema(t *testing.T) {
	if got := BucketUpperBound(0); got != 1 {
		t.Errorf("bucket 0 upper bound = %v, want 1 (2^0)", got)
	}
	if got := BucketUpperBound(8); got < 1.999 || got > 2.001 {
		t.Errorf("bucket 8 upper bound = %v, want 2 (2^(8/8)); eight schema-3 buckets span "+
			"exactly one octave", got)
	}
}

func TestBucketIndexIsMonotonicAndCannotWrap(t *testing.T) {
	// 1ns is exactly 2^0, so bucket 0 is correct for it, not a wrap.
	if got := BucketIndex(1); got != 0 {
		t.Errorf("BucketIndex(1) = %d, want 0", got)
	}

	prev := BucketIndex(1)
	for shift := uint(1); shift < 64; shift++ {
		got := BucketIndex(1 << shift)
		if got < prev {
			t.Fatalf("BucketIndex(1<<%d) = %d went backwards from %d; a wrap files the "+
				"observation in a bucket the kernel never used, which is silent rather than "+
				"loud", shift, got, prev)
		}
		prev = got
	}

	if prev == 0xFFFF {
		t.Errorf("BucketIndex(1<<63) = %d hit the uint16 clamp; every duration a probe can "+
			"measure must land in a real bucket", prev)
	}
}

func TestClampBucketBoundsTheIndexBothWays(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want uint16
	}{
		{-1, 0}, {0, 0}, {512, 512}, {65535, 65535}, {65536, 65535}, {1 << 30, 65535},
	} {
		if got := clampBucket(tc.in); got != tc.want {
			t.Errorf("clampBucket(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
