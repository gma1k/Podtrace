package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/sysfs"
)

func withProcessStartTimes(t *testing.T, starts map[uint32]uint64) {
	t.Helper()
	orig := processStartTimeOf
	processStartTimeOf = func(pid uint32) (uint64, bool) {
		started, ok := starts[pid]
		return started, ok
	}
	t.Cleanup(func() { processStartTimeOf = orig })
}

func writeCgroupProcs(t *testing.T, procs string) string {
	t.Helper()
	base := t.TempDir()
	saved := config.CgroupBasePath
	config.SetCgroupBasePath(base)
	sysfs.ResetForTesting()
	t.Cleanup(func() {
		config.SetCgroupBasePath(saved)
		sysfs.ResetForTesting()
	})
	groupDir := filepath.Join(base, "pod")
	if err := os.MkdirAll(groupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(groupDir, "cgroup.procs"), []byte(procs), 0o644); err != nil {
		t.Fatal(err)
	}
	return groupDir
}

func TestMainPIDFromCgroupProcs_LaterStartedLowerPIDLoses(t *testing.T) {
	groupDir := writeCgroupProcs(t, "31000\n12\n")
	withProcessStartTimes(t, map[uint32]uint64{31000: 100, 12: 9000})
	if got := mainPIDFromCgroupProcs(groupDir); got != 31000 {
		t.Errorf("mainPIDFromCgroupProcs = %d, want 31000 (earliest started)", got)
	}
}

func TestMainPIDFromCgroupProcs_EqualStartTimesPickLowestPID(t *testing.T) {
	groupDir := writeCgroupProcs(t, "50\n40\n60\n")
	withProcessStartTimes(t, map[uint32]uint64{50: 7, 40: 7, 60: 7})
	if got := mainPIDFromCgroupProcs(groupDir); got != 40 {
		t.Errorf("mainPIDFromCgroupProcs = %d, want 40", got)
	}
}

func TestMainPIDFromCgroupProcs_TimedPIDBeatsUntimed(t *testing.T) {
	groupDir := writeCgroupProcs(t, "5\n80\n")
	withProcessStartTimes(t, map[uint32]uint64{80: 500})
	if got := mainPIDFromCgroupProcs(groupDir); got != 80 {
		t.Errorf("mainPIDFromCgroupProcs = %d, want 80 (pid 5 has exited)", got)
	}
}

func TestMainPIDFromCgroupProcs_NoStartTimesFallsBackToLowestPID(t *testing.T) {
	groupDir := writeCgroupProcs(t, "9\n3\n7\n")
	withProcessStartTimes(t, nil)
	if got := mainPIDFromCgroupProcs(groupDir); got != 3 {
		t.Errorf("mainPIDFromCgroupProcs = %d, want 3", got)
	}
}
