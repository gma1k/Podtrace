package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

const conmonSortsFirstID = "d3adbeefd3adbeefd3adbeefd3adbeefd3adbeefd3adbeefd3adbeefd3adbeef"

func useCgroupAndProcBase(t *testing.T) (cgroupBase, procBase string) {
	t.Helper()
	origCgroup, origProc := config.CgroupBasePath, config.ProcBasePath
	cgroupBase, procBase = t.TempDir(), t.TempDir()
	config.SetCgroupBasePath(cgroupBase)
	config.SetProcBasePath(procBase)
	t.Cleanup(func() {
		config.SetCgroupBasePath(origCgroup)
		config.SetProcBasePath(origProc)
	})
	return cgroupBase, procBase
}

func makeCgroupLeaf(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeProcCgroup(t *testing.T, procBase, pid, content string) {
	t.Helper()
	dir := filepath.Join(procBase, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func crioPodSlice(base string) string {
	return filepath.Join(base, "kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod11111111_2222_3333_4444_555555555555.slice")
}

func TestV2WalkSkipsTheConmonScopeBesideTheContainer(t *testing.T) {
	base, _ := useCgroupAndProcBase(t)
	pod := crioPodSlice(base)
	makeCgroupLeaf(t, filepath.Join(pod, "crio-conmon-"+conmonSortsFirstID+".scope"))
	container := filepath.Join(pod, "crio-"+conmonSortsFirstID+".scope")
	makeCgroupLeaf(t, container)

	got, err := findCgroupPathV2(conmonSortsFirstID)
	if err != nil {
		t.Fatal(err)
	}
	if got != container {
		t.Fatalf("resolved %q, want the container scope %q", got, container)
	}
}

func TestV2WalkFindsNothingWhenOnlyConmonCarriesTheID(t *testing.T) {
	base, _ := useCgroupAndProcBase(t)
	makeCgroupLeaf(t, filepath.Join(crioPodSlice(base), "crio-conmon-"+conmonSortsFirstID+".scope"))

	if got, err := findCgroupPathV2(conmonSortsFirstID); err == nil {
		t.Fatalf("resolved %q, want no match", got)
	}
}

func TestV1WalkSkipsTheConmonScopeBesideTheContainer(t *testing.T) {
	base, _ := useCgroupAndProcBase(t)
	pod := crioPodSlice(base)
	makeCgroupLeaf(t, filepath.Join(pod, "crio-conmon-"+conmonSortsFirstID+".scope"))
	container := filepath.Join(pod, "crio-"+conmonSortsFirstID+".scope")
	makeCgroupLeaf(t, container)

	got, err := findCgroupPathV1(conmonSortsFirstID)
	if err != nil {
		t.Fatal(err)
	}
	if got != container {
		t.Fatalf("resolved %q, want the container scope %q", got, container)
	}
}

func TestProcFallbackSkipsConmonEvenWhenItHasTheLowerPID(t *testing.T) {
	base, proc := useCgroupAndProcBase(t)
	pod := crioPodSlice(base)
	relativePod := "/" + filepath.Join("kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod11111111_2222_3333_4444_555555555555.slice")
	makeCgroupLeaf(t, filepath.Join(pod, "crio-conmon-"+conmonSortsFirstID+".scope"))
	container := filepath.Join(pod, "crio-"+conmonSortsFirstID+".scope")
	makeCgroupLeaf(t, container)
	writeProcCgroup(t, proc, "100", "0::"+relativePod+"/crio-conmon-"+conmonSortsFirstID+".scope\n")
	writeProcCgroup(t, proc, "200", "0::"+relativePod+"/crio-"+conmonSortsFirstID+".scope\n")

	got, err := findCgroupPathFromProc(conmonSortsFirstID)
	if err != nil {
		t.Fatal(err)
	}
	if got != container {
		t.Fatalf("resolved %q, want the container scope %q", got, container)
	}
}

func TestProcFallbackNeverReturnsAHierarchyRoot(t *testing.T) {
	base, proc := useCgroupAndProcBase(t)
	makeCgroupLeaf(t, base)
	writeProcCgroup(t, proc, "300",
		"1:name=systemd:/kubepods/podx/"+conmonSortsFirstID+"\n0::/\n")

	if got, err := findCgroupPathFromProc(conmonSortsFirstID); err == nil {
		t.Fatalf("resolved %q, want no match rather than a hierarchy root", got)
	}
}

func TestProcFallbackIgnoresLinesThatDoNotNameTheContainer(t *testing.T) {
	base, proc := useCgroupAndProcBase(t)
	makeCgroupLeaf(t, filepath.Join(base, "system.slice", "unrelated.service"))
	writeProcCgroup(t, proc, "400",
		"1:name=systemd:/kubepods/podx/"+conmonSortsFirstID+"\n0::/system.slice/unrelated.service\n")

	if got, err := findCgroupPathFromProc(conmonSortsFirstID); err == nil {
		t.Fatalf("resolved %q, want no match for a line without the container ID", got)
	}
}
