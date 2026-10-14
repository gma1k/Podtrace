//go:build bpf_loadtest && linux

package kernelagg

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func newTestMaps(t *testing.T) (metrics, enabled *ebpf.Map) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	metrics, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.LRUCPUHash, KeySize: 24, ValueSize: 24, MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("cannot create the metrics map (needs privileges): %v", err)
	}
	t.Cleanup(func() { _ = metrics.Close() })

	enabled, err = ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("create the enabled map: %v", err)
	}
	t.Cleanup(func() { _ = enabled.Close() })
	return metrics, enabled
}

func TestKernelSetModeWritesTheModeThroughToTheMap(t *testing.T) {
	_, enabled := newTestMaps(t)

	for _, mode := range []Mode{ModeOn, ModeBypass, ModeOff} {
		if err := SetMode(enabled, mode); err != nil {
			t.Fatalf("SetMode(%s): %v", mode, err)
		}
		var got uint32
		key := uint32(0)
		if err := enabled.Lookup(&key, &got); err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if Mode(got) != mode {
			t.Errorf("map holds mode %d, want %d; the probes read this value on every "+
				"observation, so a wrong write silently changes what they do", got, mode)
		}
	}
}

func TestKernelDrainReadsAndClearsRealRows(t *testing.T) {
	metrics, _ := newTestMaps(t)

	nCPU, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	key := Key{CgroupID: 99, EventType: 2, Bucket: 40}
	vals := make([]Value, nCPU)
	vals[0] = Value{Count: 4, SumNS: 8000, Bytes: 512}
	if err := metrics.Put(&key, vals); err != nil {
		t.Fatalf("put: %v", err)
	}

	rows, err := Drain(metrics)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("drained %d rows, want 1", len(rows))
	}
	if rows[0].Value.Count != 4 || rows[0].Value.Bytes != 512 {
		t.Errorf("drained %+v, want the per-CPU sum of the written row", rows[0].Value)
	}

	again, err := Drain(metrics)
	if err != nil {
		t.Fatalf("second Drain: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("second drain returned %d rows, want 0. Values are deltas: a row left in the "+
			"map is counted twice and inflates every rate over that interval", len(again))
	}
}

func TestKernelSetModeSurfacesAWriteFailure(t *testing.T) {
	_, enabled := newTestMaps(t)
	if err := enabled.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := SetMode(enabled, ModeOn); err == nil {
		t.Error("writing to a closed map reported success. The agent decides whether to fall " +
			"back to the event path on this error, so swallowing it would leave the probes off " +
			"while the agent believed aggregation was running")
	}
}
