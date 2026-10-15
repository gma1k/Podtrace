package oncpu

import "testing"

func TestADrainCountsIncrementsBetweenReadAndDelete(t *testing.T) {
	key := Key{CgroupID: 7, PID: 10, StackID: 1}
	f := &fakeMaps{
		counts: []Key{key},
		values: []uint64{3},
		latest: map[Key]uint64{key: 5},
		stacks: map[uint32][]uint64{1: {0x10}},
	}
	d, err := drain(f.io())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Samples) != 1 || d.Samples[0].Count != 5 {
		t.Fatalf("samples = %+v, want the count as it stood when removed (5)", d.Samples)
	}
}

func TestADrainKeepsStacksThatNewCountsReference(t *testing.T) {
	f := &fakeMaps{
		counts: []Key{{StackID: 1}, {StackID: 2}},
		values: []uint64{1, 1},
		stacks: map[uint32][]uint64{1: {0x10}, 2: {0x20}},
		live:   map[uint32]struct{}{2: {}},
	}
	if _, err := drain(f.io()); err != nil {
		t.Fatal(err)
	}
	if f.deletedStacks != 1 {
		t.Fatalf("deleted %d stacks, want only the unreferenced one", f.deletedStacks)
	}
}

type sliceIterator struct{ keys []Key }

func (s *sliceIterator) Next(key, value any) bool {
	if len(s.keys) == 0 {
		return false
	}
	*key.(*Key) = s.keys[0]
	*value.(*uint64) = 1
	s.keys = s.keys[1:]
	return true
}

func TestLiveStackIDsCollectsReferencedStacks(t *testing.T) {
	got := liveStackIDs(&sliceIterator{keys: []Key{{StackID: 3}, {StackID: 3}, {StackID: 9}}})
	if len(got) != 2 {
		t.Fatalf("live = %v, want stacks 3 and 9", got)
	}
	if _, ok := got[9]; !ok {
		t.Fatalf("live = %v, missing 9", got)
	}
}
