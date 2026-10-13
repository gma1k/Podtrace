package tracer

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

const (
	procCPUMapName        = "proc_cpu_ns"
	procCPUEnabledMapName = "proc_cpu_enabled"
)

// CountProcessCPU has the kernel add up each targeted process's on-CPU time
// at every context switch, so a report can show CPU time for processes that
// exited before /proc could be read, at nanosecond rather than tick precision.
func (t *Tracer) CountProcessCPU() error {
	if t == nil || t.collection == nil {
		return errors.New("process CPU time: no BPF collection loaded")
	}
	m := t.collection.Maps[procCPUEnabledMapName]
	if m == nil {
		return errors.New("process CPU time: the BPF object has no " + procCPUEnabledMapName + " map")
	}
	key, on := uint32(0), uint32(1)
	if err := m.Update(&key, &on, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("process CPU time: %w", err)
	}
	return nil
}

// DrainProcessCPU reads and clears the on-CPU nanoseconds CountProcessCPU
// added up, keyed by process ID.
func (t *Tracer) DrainProcessCPU() (map[uint32]uint64, error) {
	if t == nil || t.collection == nil {
		return nil, nil
	}
	return drainProcessCPU(t.collection.Maps[procCPUMapName])
}

func drainProcessCPU(m *ebpf.Map) (map[uint32]uint64, error) {
	if m == nil {
		return nil, errors.New("process CPU time: the BPF object has no " + procCPUMapName + " map")
	}
	out := make(map[uint32]uint64)
	var pid uint32
	var ns uint64
	iter := m.Iterate()
	for iter.Next(&pid, &ns) {
		if ns > 0 {
			out[pid] += ns
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("process CPU time: %w", err)
	}
	for pid := range out {
		_ = m.Delete(&pid)
	}
	return out, nil
}
