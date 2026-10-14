//go:build bpf_loadtest && linux

package oncpu

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
)

func kernelMaps(t *testing.T) (Maps, *ebpf.Map) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	create := func(spec *ebpf.MapSpec) *ebpf.Map {
		m, err := ebpf.NewMap(spec)
		if err != nil {
			t.Skipf("cannot create a %s map (needs privileges): %v", spec.Type, err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	maps := Maps{
		Counts:   create(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 24, ValueSize: 8, MaxEntries: 16}),
		Stacks:   create(&ebpf.MapSpec{Type: ebpf.StackTrace, KeySize: 4, ValueSize: 8 * stackDepth, MaxEntries: 16}),
		Requests: create(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 16, MaxEntries: 16}),
		Lost:     create(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: uint32(lostReasons)}),
	}
	enabled := create(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	return maps, enabled
}

func perfEventProgram(t *testing.T) *ebpf.Program {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.PerfEvent,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		t.Skipf("cannot load a perf_event program (needs privileges): %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	return prog
}

func TestKernelSetFlagsWritesTheSwitch(t *testing.T) {
	_, enabled := kernelMaps(t)
	for _, flags := range []uint32{FlagSampler, FlagSampler | FlagRequests, FlagRequests, 0} {
		if err := SetFlags(enabled, flags); err != nil {
			t.Fatalf("SetFlags(%d): %v", flags, err)
		}
		var got uint32
		if err := enabled.Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		if got != flags {
			t.Errorf("the map holds %d after SetFlags(%d)", got, flags)
		}
	}
}

func TestKernelDrainReadsAndClearsRealMaps(t *testing.T) {
	maps, _ := kernelMaps(t)
	key := Key{CgroupID: 7, CorrelationID: 9, PID: 1, StackID: 3}
	if err := maps.Counts.Put(&key, uint64(5)); err != nil {
		t.Fatal(err)
	}
	if err := maps.Requests.Put(uint64(9), Done{LatencyNS: 1500, CgroupID: 7}); err != nil {
		t.Fatal(err)
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	lost := make([]uint64, cpus)
	lost[0] = 4
	if err := maps.Lost.Put(LostFull, lost); err != nil {
		t.Fatal(err)
	}

	d, err := Drain(maps)
	if err != nil {
		t.Fatal(err)
	}
	if d.Unresolved != 5 || len(d.Samples) != 0 {
		t.Errorf("drained %+v; a count whose stack the kernel never stored is a loss", d)
	}
	if len(d.Completions) != 1 || d.Completions[0] != (Completion{CorrelationID: 9, CgroupID: 7, LatencyNS: 1500}) {
		t.Errorf("completions = %+v", d.Completions)
	}
	if d.Lost[LostFull] != 4 {
		t.Errorf("lost = %v", d.Lost)
	}

	again, err := Drain(maps)
	if err != nil {
		t.Fatal(err)
	}
	if again.Unresolved != 0 || len(again.Completions) != 0 || again.Lost[LostFull] != 0 {
		t.Errorf("a second drain returned %+v; the first must clear what it read", again)
	}
}

func TestKernelTheSamplerAttachesToEveryOnlineCPU(t *testing.T) {
	prog := perfEventProgram(t)
	want, err := onlineCPUs()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Attach(prog)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if s.CPUs() != len(want) {
		t.Errorf("attached to %d CPUs, want %d", s.CPUs(), len(want))
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestKernelSetFlagsReportsAWriteTheMapRefuses(t *testing.T) {
	kernelMaps(t)
	wide, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Skipf("cannot create a map: %v", err)
	}
	t.Cleanup(func() { _ = wide.Close() })
	if err := SetFlags(wide, FlagSampler); err == nil {
		t.Error("a switch the map could not store was reported as set")
	}
}
