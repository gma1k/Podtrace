package tracer

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestProcessCPUWithoutACollection(t *testing.T) {
	var tr *Tracer
	if err := tr.CountProcessCPU(); err == nil {
		t.Error("CountProcessCPU must fail without a loaded collection")
	}
	times, err := tr.DrainProcessCPU()
	if err != nil || times != nil {
		t.Errorf("DrainProcessCPU without a collection = %v, %v; want nil, nil", times, err)
	}
	if _, err := drainProcessCPU(nil); err == nil {
		t.Error("draining a missing map must fail")
	}
}

func TestDrainProcessCPUReadsAndClears(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 8})
	if err != nil {
		t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
	}
	defer func() { _ = m.Close() }()
	for pid, ns := range map[uint32]uint64{100: 4_000_000, 200: 0, 300: 7} {
		if err := m.Put(pid, ns); err != nil {
			t.Fatal(err)
		}
	}
	got, err := drainProcessCPU(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[100] != 4_000_000 || got[300] != 7 {
		t.Fatalf("drained %v, want map[100:4000000 300:7]", got)
	}
	again, err := drainProcessCPU(m)
	if err != nil || len(again) != 0 {
		t.Fatalf("a second drain = %v, %v; want nothing left", again, err)
	}
}
