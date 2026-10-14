//go:build bpf_loadtest && linux

package tracer

import (
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
)

func TestKernelStampingAndTheSamplerSwitchIndependently(t *testing.T) {
	coll := onCPUCollection(t)
	tr := &Tracer{collection: coll}

	if err := tr.StampRequests(); err != nil {
		t.Fatalf("StampRequests: %v", err)
	}
	if got := enabledValue(t, coll); got != oncpu.FlagRequests {
		t.Fatalf("flags = %d after stamping, want %d", got, oncpu.FlagRequests)
	}
	if _, err := tr.StartOnCPUSampler(); err != nil {
		t.Fatalf("StartOnCPUSampler: %v", err)
	}
	if got := enabledValue(t, coll); got != oncpu.FlagRequests|oncpu.FlagSampler {
		t.Errorf("flags = %d with both on", got)
	}
	tr.stopOnCPUSampler()
	if got := enabledValue(t, coll); got != oncpu.FlagRequests {
		t.Errorf("stopping the sampler left flags %d; stamping still needs the request hooks", got)
	}
}

func TestKernelAStampingSwitchThatCannotBeSetIsReported(t *testing.T) {
	coll := onCPUCollection(t)
	wide, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Skipf("cannot create a map: %v", err)
	}
	t.Cleanup(func() { _ = wide.Close() })
	_ = coll.Maps[oncpu.EnabledMapName].Close()
	coll.Maps[oncpu.EnabledMapName] = wide

	tr := &Tracer{collection: coll}
	if err := tr.StampRequests(); err == nil || tr.onCPUFlags != 0 {
		t.Errorf("StampRequests = %v, flags %d; a switch the map refused was reported as on", err, tr.onCPUFlags)
	}
}
