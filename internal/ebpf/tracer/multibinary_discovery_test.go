package tracer

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/sysfs"
)

func fakeContainerProc(t *testing.T, containerID string, pids []uint32, exeOf map[uint32]string) string {
	t.Helper()
	base := t.TempDir()
	cgroupBase := filepath.Join(base, "cgroup")
	procBase := filepath.Join(base, "proc")
	cgroupDir := filepath.Join(cgroupBase, "kubepods", containerID)
	if err := os.MkdirAll(cgroupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(base, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	procsContent := ""
	for _, pid := range pids {
		procsContent += fmt.Sprintf("%d\n", pid)
		name := exeOf[pid]
		if name == "" {
			continue
		}
		bin := filepath.Join(binDir, name)
		if _, err := os.Stat(bin); os.IsNotExist(err) {
			if err := os.WriteFile(bin, []byte(name), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		pidDir := filepath.Join(procBase, fmt.Sprintf("%d", pid))
		if err := os.MkdirAll(pidDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(bin, filepath.Join(pidDir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cgroupDir, "cgroup.procs"), []byte(procsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	oldCgroup, oldProc := config.CgroupBasePath, config.ProcBasePath
	config.SetCgroupBasePath(cgroupBase)
	config.SetProcBasePath(procBase)
	sysfs.ResetForTesting()
	t.Cleanup(func() {
		config.SetCgroupBasePath(oldCgroup)
		config.SetProcBasePath(oldProc)
		sysfs.ResetForTesting()
	})
	return cgroupDir
}

func TestPidsForContainer_DedupesByExecutableInode(t *testing.T) {
	const cid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	cgroupDir := fakeContainerProc(t, cid,
		[]uint32{101, 102, 103, 104},
		map[uint32]string{
			101: "shell",
			102: "shell",
			103: "gotls",
			104: "",
		})

	tr := &Tracer{}
	tr.setCgroupPaths([]string{cgroupDir})
	pids := tr.pidsForContainer(cid, nil)
	if len(pids) != 2 || pids[0] != 101 || pids[1] != 103 {
		t.Fatalf("pidsForContainer = %v, want [101 103] (one PID per distinct executable)", pids)
	}
}

func TestPidsForContainer_CapsDistinctBinaries(t *testing.T) {
	const cid = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"
	pids := make([]uint32, 0, maxDistinctBinariesPerContainer+3)
	exeOf := map[uint32]string{}
	for i := 0; i < maxDistinctBinariesPerContainer+3; i++ {
		pid := uint32(200 + i)
		pids = append(pids, pid)
		exeOf[pid] = fmt.Sprintf("bin%d", i)
	}
	cgroupDir := fakeContainerProc(t, cid, pids, exeOf)

	tr := &Tracer{}
	tr.setCgroupPaths([]string{cgroupDir})
	got := tr.pidsForContainer(cid, nil)
	if len(got) != maxDistinctBinariesPerContainer {
		t.Fatalf("pidsForContainer returned %d PIDs, want cap %d", len(got), maxDistinctBinariesPerContainer)
	}
}

func TestSetContainerTargets_AttachesOnlyNewPIDsAndKeepsExistingProbes(t *testing.T) {
	var lastPIDs []uint32
	attachCalls := 0
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{}}
	old := &fakeLink{}
	tr.attachContainerGroupFn = func(g probes.ProbeGroup, id string, pids []uint32) []link.Link {
		if g != probes.GroupTLS {
			return nil
		}
		attachCalls++
		lastPIDs = append([]uint32(nil), pids...)
		if attachCalls == 1 {
			return []link.Link{old}
		}
		return []link.Link{&fakeLink{}}
	}

	if err := tr.SetContainerTargets([]ContainerProbeTarget{{ID: "containeraaaa", PIDs: []uint32{1}}}); err != nil {
		t.Fatalf("SetContainerTargets: %v", err)
	}
	if attachCalls != 1 || len(lastPIDs) != 1 || lastPIDs[0] != 1 {
		t.Fatalf("first attach: calls=%d pids=%v, want 1 call with [1]", attachCalls, lastPIDs)
	}

	if err := tr.SetContainerTargets([]ContainerProbeTarget{{ID: "containeraaaa", PIDs: []uint32{2, 1}}}); err != nil {
		t.Fatalf("SetContainerTargets: %v", err)
	}
	if attachCalls != 2 || len(lastPIDs) != 1 || lastPIDs[0] != 2 {
		t.Fatalf("second attach: calls=%d pids=%v, want one more call for the new PID [2] only", attachCalls, lastPIDs)
	}
	if old.closes.Load() != 0 {
		t.Fatalf("existing link closed %d times; a new process must not tear down probes that are still valid", old.closes.Load())
	}
	if got := len(tr.containerUprobes["containeraaaa"].links[probes.GroupTLS]); got != 2 {
		t.Fatalf("container holds %d TLS links, want 2", got)
	}

	if err := tr.SetContainerTargets([]ContainerProbeTarget{{ID: "containeraaaa", PIDs: []uint32{2}}}); err != nil {
		t.Fatalf("SetContainerTargets: %v", err)
	}
	if err := tr.SetContainerTargets([]ContainerProbeTarget{{ID: "containeraaaa", PIDs: []uint32{1, 2}}}); err != nil {
		t.Fatalf("SetContainerTargets: %v", err)
	}
	if attachCalls != 2 || old.closes.Load() != 0 {
		t.Fatalf("calls=%d closes=%d after PIDs left and returned, want no attach and no detach", attachCalls, old.closes.Load())
	}

	if err := tr.SetContainerTargets([]ContainerProbeTarget{{ID: "containerbbbb", PIDs: []uint32{7}}}); err != nil {
		t.Fatalf("SetContainerTargets: %v", err)
	}
	if old.closes.Load() != 1 {
		t.Fatalf("link of a container that left the target set closed %d times, want 1", old.closes.Load())
	}
}
