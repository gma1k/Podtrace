package tracer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/events"
)

func TestPodCgroupParents(t *testing.T) {
	systemd := "/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/" +
		"kubelet-kubepods-besteffort-pod030a9a31_6d1e_4b0e_9b51_5a7c8b2f3e41.slice"
	cgroupfs := "/sys/fs/cgroup/kubepods/burstable/pod7d3f1c2a-4b5e-4f6a-8b9c-0d1e2f3a4b5c"
	got := podCgroupParents([]string{
		systemd + "/cri-containerd-aaaa.scope",
		systemd + "/cri-containerd-bbbb.scope",
		cgroupfs + "/cccc",
		cgroupfs,
		"/sys/fs/cgroup/kubepods/besteffort",
		"/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice",
		"/sys/fs/cgroup/system.slice/containerd.service",
	})
	want := []string{systemd, cgroupfs}
	if len(got) != len(want) {
		t.Fatalf("podCgroupParents = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("podCgroupParents[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestUserspaceFilterKeepsEventsFromAContainerCreatedUnderATargetedPod(t *testing.T) {
	tr := &Tracer{}
	tr.storeCgroupIDs(map[uint64]struct{}{100: {}})
	tr.inheritedCache.Store(uint64(200), uint64(50))

	if !tr.cgroupAllows(&events.Event{CgroupID: 100}) {
		t.Error("a targeted container's event was dropped")
	}
	if !tr.cgroupAllows(&events.Event{CgroupID: 200}) {
		t.Error("an event from a container the kernel inherited under a targeted pod was dropped")
	}
	if tr.cgroupAllows(&events.Event{CgroupID: 300}) {
		t.Error("an event from an unrelated cgroup was kept")
	}
	if parent, ok := tr.InheritedCgroupParent(200); !ok || parent != 50 {
		t.Errorf("InheritedCgroupParent(200) = %d, %v; want 50, true", parent, ok)
	}
	if _, ok := tr.InheritedCgroupParent(0); ok {
		t.Error("cgroup 0 has no parent")
	}
}

func TestSyncParentCgroupsKeepsWantedAndDropsOrphans(t *testing.T) {
	parents, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 1, MaxEntries: 8})
	if err != nil {
		t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
	}
	defer func() { _ = parents.Close() }()
	inherited, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inherited.Close() }()
	for _, kv := range [][2]uint64{{11, 1}, {12, 2}} {
		if err := inherited.Put(kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := parents.Put(uint64(2), uint8(1)); err != nil {
		t.Fatal(err)
	}

	if err := syncParentCgroups(parents, inherited, map[uint64]struct{}{1: {}}); err != nil {
		t.Fatal(err)
	}
	var flag uint8
	if parents.Lookup(uint64(1), &flag) != nil || parents.Lookup(uint64(2), &flag) == nil {
		t.Error("parent map must hold exactly the wanted pod cgroups")
	}
	var parent uint64
	if inherited.Lookup(uint64(11), &parent) != nil {
		t.Error("a child of a still-targeted pod was dropped")
	}
	if inherited.Lookup(uint64(12), &parent) == nil {
		t.Error("a child of a pod no longer targeted was kept")
	}
}

func TestSyncCgroupInheritanceKeepsCachedChildrenOfStillTargetedPods(t *testing.T) {
	parents, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 1, MaxEntries: 8})
	if err != nil {
		t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
	}
	inherited, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 8})
	if err != nil {
		t.Fatal(err)
	}
	podDir := filepath.Join(t.TempDir(), "kubepods-besteffort-pod030a9a31_6d1e_4b0e_9b51_5a7c8b2f3e41.slice")
	container := filepath.Join(podDir, "cri-containerd-aaaa.scope")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	podID, err := getCgroupIDFromPath(podDir)
	if err != nil {
		t.Fatal(err)
	}
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{
		targetParentCgroupMapName: parents,
		inheritedCgroupMapName:    inherited,
	}}, probesClosed: true}
	defer tr.collection.Close()
	tr.inheritedCache.Store(uint64(500), podID)
	tr.inheritedCache.Store(uint64(501), podID+1)

	tr.syncCgroupInheritance([]string{container})

	if _, ok := tr.inheritedCache.Load(uint64(500)); !ok {
		t.Error("a cached child of a pod that is still targeted was dropped")
	}
	if _, ok := tr.inheritedCache.Load(uint64(501)); ok {
		t.Error("a cached child of a pod that is no longer targeted was kept")
	}
	var flag uint8
	if err := parents.Lookup(podID, &flag); err != nil {
		t.Errorf("the pod cgroup was not registered as a parent: %v", err)
	}
}
