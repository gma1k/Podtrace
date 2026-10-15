package oncpu

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeMaps struct {
	counts   []Key
	values   []uint64
	stacks   map[uint32][]uint64
	requests map[uint64]Done
	lost     map[uint32][]uint64

	latest                         map[Key]uint64
	live                           map[uint32]struct{}
	countErr, requestErr           error
	deleteCountErr, deleteStackErr error
	deleteRequestErr, readLostErr  error
	resetLostErr                   error
	deletedCounts, deletedStacks   int
	deletedRequests                int
	reset                          map[uint32][]uint64
}

func (f *fakeMaps) io() drainIO {
	ci, ri := 0, 0
	reqIDs := make([]uint64, 0, len(f.requests))
	for id := range f.requests {
		reqIDs = append(reqIDs, id)
	}
	f.reset = map[uint32][]uint64{}
	return drainIO{
		nextCount: func(key, value any) bool {
			if ci >= len(f.counts) {
				return false
			}
			*key.(*Key) = f.counts[ci]
			*value.(*uint64) = f.values[ci]
			ci++
			return true
		},
		countErr: func() error { return f.countErr },
		takeCount: func(k *Key, count *uint64) error {
			f.deletedCounts++
			if v, ok := f.latest[*k]; ok {
				*count = v
			}
			return f.deleteCountErr
		},
		lookupStack: func(id uint32, out *[stackDepth]uint64) error {
			s, ok := f.stacks[id]
			if !ok {
				return ebpf.ErrKeyNotExist
			}
			copy(out[:], s)
			return nil
		},
		deleteStack: func(uint32) error {
			f.deletedStacks++
			return f.deleteStackErr
		},
		liveStackIDs: func() map[uint32]struct{} { return f.live },
		nextRequest: func(key, value any) bool {
			if ri >= len(reqIDs) {
				return false
			}
			*key.(*uint64) = reqIDs[ri]
			*value.(*Done) = f.requests[reqIDs[ri]]
			ri++
			return true
		},
		requestErr: func() error { return f.requestErr },
		deleteRequest: func(*uint64) error {
			f.deletedRequests++
			return f.deleteRequestErr
		},
		readLost: func(reason uint32, out *[]uint64) error {
			if f.readLostErr != nil {
				return f.readLostErr
			}
			*out = append([]uint64(nil), f.lost[reason]...)
			return nil
		},
		resetLost: func(reason uint32, zero []uint64) error {
			f.reset[reason] = zero
			return f.resetLostErr
		},
	}
}

func TestADrainReturnsEachStackWithItsCountAndClearsTheMaps(t *testing.T) {
	f := &fakeMaps{
		counts: []Key{
			{CgroupID: 7, PID: 10, StackID: 1},
			{CgroupID: 7, PID: 10, StackID: 1, CorrelationID: 99},
			{CgroupID: 8, PID: 11, StackID: 2},
		},
		values:   []uint64{5, 3, 2},
		stacks:   map[uint32][]uint64{1: {0x10, 0x20}, 2: {0x30}},
		requests: map[uint64]Done{99: {LatencyNS: 1500, CgroupID: 7}},
		lost:     map[uint32][]uint64{LostStack: {1, 2}, LostFull: {0, 0}},
	}
	d, err := drain(f.io())
	if err != nil {
		t.Fatal(err)
	}
	want := []Sample{
		{CgroupID: 7, PID: 10, Stack: []uint64{0x10, 0x20}, Count: 5},
		{CgroupID: 7, PID: 10, CorrelationID: 99, Stack: []uint64{0x10, 0x20}, Count: 3},
		{CgroupID: 8, PID: 11, Stack: []uint64{0x30}, Count: 2},
	}
	if !reflect.DeepEqual(d.Samples, want) {
		t.Errorf("samples = %+v, want %+v", d.Samples, want)
	}
	if len(d.Completions) != 1 || d.Completions[0] != (Completion{CorrelationID: 99, CgroupID: 7, LatencyNS: 1500}) {
		t.Errorf("completions = %+v", d.Completions)
	}
	if d.Lost[LostStack] != 3 || d.Lost[LostFull] != 0 {
		t.Errorf("lost = %v, want 3 stack losses summed across CPUs", d.Lost)
	}
	if f.deletedCounts != 3 || f.deletedStacks != 2 || f.deletedRequests != 1 {
		t.Errorf("deleted %d counts, %d stacks, %d requests; every row read must be removed",
			f.deletedCounts, f.deletedStacks, f.deletedRequests)
	}
	if zero, ok := f.reset[LostStack]; !ok || len(zero) != 2 || zero[0] != 0 {
		t.Errorf("the stack-loss counter was not zeroed per CPU: %v", f.reset)
	}
	if _, ok := f.reset[LostFull]; ok {
		t.Error("a counter already at zero was rewritten")
	}
}

func TestASampleWhoseStackIsGoneIsCountedAsUnresolved(t *testing.T) {
	f := &fakeMaps{
		counts: []Key{{CgroupID: 7, StackID: 4}, {CgroupID: 7, StackID: 5}},
		values: []uint64{6, 1},
		stacks: map[uint32][]uint64{5: {0, 0}},
	}
	d, err := drain(f.io())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Samples) != 0 || d.Unresolved != 7 {
		t.Errorf("samples = %+v, unresolved = %d; a missing or empty stack is a loss, not a sample",
			d.Samples, d.Unresolved)
	}
}

func TestADeleteOfARowAlreadyGoneIsNotAnError(t *testing.T) {
	f := &fakeMaps{
		counts:           []Key{{StackID: 1}},
		values:           []uint64{1},
		stacks:           map[uint32][]uint64{1: {0x1}},
		requests:         map[uint64]Done{1: {}},
		deleteCountErr:   ebpf.ErrKeyNotExist,
		deleteStackErr:   ebpf.ErrKeyNotExist,
		deleteRequestErr: ebpf.ErrKeyNotExist,
	}
	if _, err := drain(f.io()); err != nil {
		t.Errorf("drain = %v", err)
	}
}

func TestAWalkTheKernelOutpacedKeepsWhatItRead(t *testing.T) {
	f := &fakeMaps{
		counts:     []Key{{CgroupID: 7, StackID: 1, CorrelationID: 5}},
		values:     []uint64{4},
		stacks:     map[uint32][]uint64{1: {0x10}},
		requests:   map[uint64]Done{5: {LatencyNS: 900, CgroupID: 7}},
		countErr:   ebpf.ErrIterationAborted,
		requestErr: ebpf.ErrIterationAborted,
	}
	d, err := drain(f.io())
	if err != nil {
		t.Fatalf("drain = %v; an aborted walk is not a failed drain", err)
	}
	if len(d.Samples) != 1 || len(d.Completions) != 1 {
		t.Errorf("drained %d samples and %d completions, want the 1 of each that were read", len(d.Samples), len(d.Completions))
	}
	if f.deletedCounts != 1 || f.deletedRequests != 1 {
		t.Errorf("deleted %d counts and %d requests; rows read must still be removed", f.deletedCounts, f.deletedRequests)
	}
}

func TestEveryMapFailureStopsTheDrain(t *testing.T) {
	boom := errors.New("boom")
	for name, f := range map[string]*fakeMaps{
		"iterate counts":   {countErr: boom},
		"delete count":     {counts: []Key{{}}, values: []uint64{1}, deleteCountErr: boom},
		"delete stack":     {counts: []Key{{}}, values: []uint64{1}, stacks: map[uint32][]uint64{0: {1}}, deleteStackErr: boom},
		"iterate requests": {requestErr: boom},
		"delete request":   {requests: map[uint64]Done{1: {}}, deleteRequestErr: boom},
		"read lost":        {readLostErr: boom},
		"reset lost":       {lost: map[uint32][]uint64{LostFull: {4}}, resetLostErr: boom},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := drain(f.io()); !errors.Is(err, boom) {
				t.Errorf("drain = %v, want the %s failure", err, name)
			}
		})
	}
}

func TestTrimStackStopsAtTheFirstEmptySlot(t *testing.T) {
	if got := trimStack([]uint64{1, 2, 0, 3}); !reflect.DeepEqual(got, []uint64{1, 2}) {
		t.Errorf("trimStack = %v", got)
	}
	if got := trimStack([]uint64{0}); got != nil {
		t.Errorf("an empty stack trimmed to %v", got)
	}
}

func TestMapsFromNeedsEverySamplerMap(t *testing.T) {
	if _, err := MapsFrom(map[string]*ebpf.Map{CountsMapName: {}}); err == nil {
		t.Error("an object missing the sampler maps was accepted")
	}
	m, err := MapsFrom(map[string]*ebpf.Map{
		CountsMapName: {}, StacksMapName: {}, RequestsMapName: {}, LostMapName: {},
	})
	if err != nil || m.Counts == nil || m.Stacks == nil || m.Requests == nil || m.Lost == nil {
		t.Errorf("MapsFrom = %+v, %v", m, err)
	}
}

func TestSetFlagsRefusesAMissingMap(t *testing.T) {
	if err := SetFlags(nil, FlagSampler); err == nil {
		t.Error("no error for a nil map")
	}
}

func TestLostReasonsHaveStableNames(t *testing.T) {
	for reason, want := range map[uint32]string{
		LostStack: "stack_unavailable", LostFull: "count_map_full", 9: "unknown",
	} {
		if got := LostReason(reason); got != want {
			t.Errorf("LostReason(%d) = %q, want %q", reason, got, want)
		}
	}
}
