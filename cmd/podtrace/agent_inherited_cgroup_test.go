package main

import (
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf"
)

type inheritingTracer struct{ ebpf.TracerInterface }

func (inheritingTracer) InheritedCgroupParent(id uint64) (uint64, bool) {
	if id == 7 {
		return 3, true
	}
	return 0, false
}

func TestAgentAdapterExposesTheTracersInheritedCgroups(t *testing.T) {
	a := &ebpfBackendAdapter{tr: inheritingTracer{}}
	if p, ok := a.InheritedCgroupParent(7); !ok || p != 3 {
		t.Errorf("InheritedCgroupParent(7) = %d, %v; want 3, true", p, ok)
	}
	if _, ok := a.InheritedCgroupParent(8); ok {
		t.Error("an unknown cgroup has no parent")
	}
	plain := &ebpfBackendAdapter{tr: struct{ ebpf.TracerInterface }{}}
	if _, ok := plain.InheritedCgroupParent(7); ok {
		t.Error("a tracer without the record must report none")
	}
}
