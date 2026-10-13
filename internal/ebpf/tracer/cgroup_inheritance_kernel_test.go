package tracer

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func compiledObjectPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "internal", "ebpf", "embedded", "podtrace."+runtime.GOARCH+".bpf.o")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root not found")
		}
		dir = parent
	}
}

func loadOnly(t *testing.T, program string, maps ...string) *ebpf.Collection {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(compiledObjectPath(t))
	if err != nil {
		t.Skipf("BPF object not built: %v", err)
	}
	keep := map[string]bool{}
	for _, m := range maps {
		keep[m] = true
	}
	for name := range spec.Maps {
		if !keep[name] && !strings.HasPrefix(name, ".") {
			delete(spec.Maps, name)
		}
	}
	for name := range spec.Programs {
		if name != program {
			delete(spec.Programs, name)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Skipf("cannot load BPF here (needs root): %v", err)
	}
	return coll
}

func TestCgroupMkdirHookInheritsContainersCreatedUnderATargetedPod(t *testing.T) {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("cgroup v2 not mounted at /sys/fs/cgroup")
	}
	coll := loadOnly(t, cgroupMkdirProgramName, targetParentCgroupMapName, inheritedCgroupMapName)
	defer coll.Close()

	pod := filepath.Join("/sys/fs/cgroup", "podtrace-test-pod030a9a31_6d1e_4b0e_9b51_5a7c8b2f3e41.slice")
	other := filepath.Join("/sys/fs/cgroup", "podtrace-test-unrelated")
	existing := filepath.Join(pod, "ctr-existing")
	if err := os.MkdirAll(existing, 0o755); err != nil {
		t.Skipf("cannot create cgroups here (needs root): %v", err)
	}
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	restarted := filepath.Join(pod, "ctr-restarted")
	unrelated := filepath.Join(other, "ctr")
	t.Cleanup(func() {
		for _, d := range []string{restarted, existing, unrelated, pod, other} {
			_ = os.Remove(d)
		}
	})

	tr := &Tracer{collection: coll}
	defer func() { closeLinks(tr.links) }()
	tr.syncCgroupInheritance([]string{existing})
	if !tr.cgroupMkdirAttached {
		t.Fatal("the cgroup_mkdir hook was not attached")
	}
	tr.ensureCgroupMkdirHook()
	if len(tr.links) != 1 {
		t.Fatalf("hook attached %d times, want once", len(tr.links))
	}

	if err := os.Mkdir(restarted, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(unrelated, 0o755); err != nil {
		t.Fatal(err)
	}
	podID, _ := getCgroupIDFromPath(pod)
	restartedID, _ := getCgroupIDFromPath(restarted)
	unrelatedID, _ := getCgroupIDFromPath(unrelated)

	parent, ok := tr.InheritedCgroupParent(restartedID)
	if !ok || parent != podID {
		t.Fatalf("a container created under the targeted pod: parent=%d ok=%v, want %d", parent, ok, podID)
	}
	if _, ok := tr.InheritedCgroupParent(restartedID); !ok {
		t.Fatal("the cached lookup lost the container")
	}
	if _, ok := tr.InheritedCgroupParent(unrelatedID); ok {
		t.Fatal("a container created under an untargeted cgroup was inherited")
	}

	tr.syncCgroupInheritance(nil)
	tr.inheritedCache.Delete(restartedID)
	if _, ok := tr.InheritedCgroupParent(restartedID); ok {
		t.Fatal("a container of a pod no longer targeted is still inherited")
	}
}

func TestCountProcessCPUTurnsTheKernelCounterOn(t *testing.T) {
	enabled, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
	}
	times, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 8})
	if err != nil {
		t.Fatal(err)
	}
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{
		procCPUEnabledMapName: enabled,
		procCPUMapName:        times,
	}}}
	defer tr.collection.Close()

	if err := tr.CountProcessCPU(); err != nil {
		t.Fatal(err)
	}
	var on uint32
	if err := enabled.Lookup(uint32(0), &on); err != nil || on != 1 {
		t.Fatalf("enable flag = %d, %v; want 1", on, err)
	}
	if err := times.Put(uint32(42), uint64(4_000_000)); err != nil {
		t.Fatal(err)
	}
	got, err := tr.DrainProcessCPU()
	if err != nil || got[42] != 4_000_000 {
		t.Fatalf("DrainProcessCPU = %v, %v", got, err)
	}

	missing := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	if err := missing.CountProcessCPU(); err == nil {
		t.Error("a BPF object without the enable map must be reported")
	}
}

func TestInheritanceIsANoOpWithoutItsMaps(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	tr.syncCgroupInheritance([]string{"/sys/fs/cgroup/kubepods-pod030a9a31_6d1e_4b0e_9b51_5a7c8b2f3e41.slice/ctr"})
	if tr.cgroupMkdirAttached {
		t.Error("the hook must not attach without its maps")
	}
	if _, ok := tr.InheritedCgroupParent(7); ok {
		t.Error("no inherited map, no parent")
	}
}

func TestInheritanceFailuresLeaveTheHookDetached(t *testing.T) {
	badParents, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 4})
	if err != nil {
		t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
	}
	inherited, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 4})
	if err != nil {
		t.Fatal(err)
	}
	podDir := filepath.Join(t.TempDir(), "kubepods-pod030a9a31_6d1e_4b0e_9b51_5a7c8b2f3e41.slice")
	container := filepath.Join(podDir, "ctr")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{
		targetParentCgroupMapName: badParents,
		inheritedCgroupMapName:    inherited,
	}}}
	defer tr.collection.Close()

	tr.syncCgroupInheritance([]string{container})
	if tr.cgroupMkdirAttached {
		t.Error("the hook attached although the parent map could not be written")
	}

	goodParents, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 1, MaxEntries: 4})
	if err != nil {
		t.Fatal(err)
	}
	tr.collection.Maps[targetParentCgroupMapName] = goodParents
	tr.syncCgroupInheritance([]string{container})
	if tr.cgroupMkdirAttached {
		t.Error("the hook reported attached although the object has no cgroup_mkdir program")
	}
}

func TestCountProcessCPUReportsAMapItCannotWrite(t *testing.T) {
	wrongSize, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Skipf("cannot create a BPF map here (needs CAP_BPF): %v", err)
	}
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{procCPUEnabledMapName: wrongSize}}}
	defer tr.collection.Close()
	if err := tr.CountProcessCPU(); err == nil {
		t.Error("a failed write of the enable flag must be reported")
	}
}
