//go:build bpf_loadtest && linux

package tracer

import (
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

func TestKernelEveryFexitReturnLoadsWhereTheKernelHasTheHelper(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	if !tracingProgramsAvailable() {
		t.Skip("no tracing programs on this kernel")
	}
	if !funcRetAvailable() {
		t.Fatal("this kernel runs fexit programs but the bpf_get_func_ret probe says it cannot; " +
			"a broken probe silently sends every return back to the kretprobes")
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	for _, name := range probes.ReturnTracingPrograms() {
		if tr.collection.Programs[name] == nil {
			t.Errorf("%s was dropped on a kernel that can load it", name)
		}
	}
}
