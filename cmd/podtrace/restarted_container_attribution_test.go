package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/kubernetes"
)

type fakeInherited map[uint64]uint64

func (f fakeInherited) InheritedCgroupParent(id uint64) (uint64, bool) {
	p, ok := f[id]
	return p, ok
}

func TestARestartedContainerIsAttributedToItsPodBeforeThePodWatchCatchesUp(t *testing.T) {
	podDir := filepath.Join(t.TempDir(), "kubepods-pod0001")
	oldContainer := filepath.Join(podDir, "cri-containerd-old.scope")
	if err := os.MkdirAll(oldContainer, 0o755); err != nil {
		t.Fatal(err)
	}
	podID, err := cgroupIDFromPath(podDir)
	if err != nil {
		t.Fatal(err)
	}
	oldID, err := cgroupIDFromPath(oldContainer)
	if err != nil {
		t.Fatal(err)
	}

	idx := newSourcePodIndex([]*kubernetes.PodInfo{{
		Namespace: "ux", PodName: "oomer", ContainerName: "stress", ContainerID: "old", CgroupPath: oldContainer,
	}})
	const restarted = uint64(987654321)
	if idx.Resolve(&events.Event{CgroupID: restarted}) != nil {
		t.Fatal("without the tracer's view an unknown cgroup must stay unattributed")
	}

	idx.followRestartedContainers(fakeInherited{restarted: podID})
	got := idx.Resolve(&events.Event{CgroupID: restarted})
	if got == nil || got.PodName != "oomer" || got.Namespace != "ux" {
		t.Fatalf("restarted container resolved to %+v, want pod ux/oomer", got)
	}
	if got.ContainerID != "" || got.CgroupPath != "" {
		t.Errorf("a restarted container must not inherit the old container's identity: %+v", got)
	}
	if p := idx.Resolve(&events.Event{CgroupID: oldID}); p == nil || p.ContainerName != "stress" {
		t.Errorf("the original container must still resolve exactly: %+v", p)
	}
	if idx.Resolve(&events.Event{CgroupID: 42}) != nil {
		t.Error("a cgroup outside every targeted pod was attributed")
	}

	idx.followRestartedContainers(struct{}{})
}
