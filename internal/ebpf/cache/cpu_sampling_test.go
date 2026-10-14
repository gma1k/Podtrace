package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

func writeStat(t *testing.T, base string, pid uint32, utime uint64) {
	t.Helper()
	dir := filepath.Join(base, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (worker) S 1 1 1 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0 0 0 0", pid, utime)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
}

func withFakeProc(t *testing.T) (string, *time.Time) {
	t.Helper()
	base := t.TempDir()
	origBase, origNow := config.ProcBasePath, cpuNow
	now := time.Unix(1_000_000, 0)
	config.ProcBasePath = base
	cpuNow = func() time.Time { return now }
	ResetCPUTimes()
	t.Cleanup(func() {
		config.ProcBasePath, cpuNow = origBase, origNow
		ResetCPUTimes()
	})
	return base, &now
}

func TestARepeatedSnapshotWithinTheIntervalDoesNotRereadProc(t *testing.T) {
	base, now := withFakeProc(t)
	const pid uint32 = 4100
	writeStat(t, base, pid, 100)
	SnapshotCPUTime(pid)
	first := GetCPUTime(pid).TotalNS

	writeStat(t, base, pid, 900)
	*now = now.Add(cpuSampleInterval / 2)
	SnapshotCPUTime(pid)
	if got := GetCPUTime(pid).TotalNS; got != first {
		t.Fatalf("TotalNS moved to %d within the sample interval; every event re-read /proc", got)
	}

	*now = now.Add(cpuSampleInterval)
	SnapshotCPUTime(pid)
	got := GetCPUTime(pid)
	if got.TotalNS == first {
		t.Error("TotalNS never refreshed after the sample interval passed")
	}
	if got.BaselineNS != first {
		t.Errorf("BaselineNS = %d, want the first sample %d", got.BaselineNS, first)
	}
}

func TestAFullCacheEvictsTheStalestEntriesNotEveryBaseline(t *testing.T) {
	base, now := withFakeProc(t)
	cpuTimeMu.Lock()
	for i := 0; i < maxCPUTimeEntries; i++ {
		cpuTimes[uint32(100000+i)] = cpuTimeEntry{
			ProcessCPUTime: ProcessCPUTime{TotalNS: 1, BaselineNS: 1},
			sampledAt:      now.Add(time.Duration(i) * time.Millisecond),
		}
	}
	cpuTimeMu.Unlock()

	const pid uint32 = 4200
	writeStat(t, base, pid, 50)
	SnapshotCPUTime(pid)

	cpuTimeMu.RLock()
	size := len(cpuTimes)
	_, oldestKept := cpuTimes[100000]
	_, newestKept := cpuTimes[uint32(100000+maxCPUTimeEntries-1)]
	cpuTimeMu.RUnlock()
	if size < maxCPUTimeEntries/2 {
		t.Fatalf("cache shrank to %d entries; overflow wiped every other process's baseline", size)
	}
	if oldestKept {
		t.Error("the stalest entry survived eviction")
	}
	if !newestKept {
		t.Error("the most recently sampled entry was evicted")
	}
	if GetCPUTime(pid).TotalNS == 0 {
		t.Error("the new pid was not recorded after eviction")
	}
}

func TestASmallFullCacheStillEvictsOneEntry(t *testing.T) {
	_, now := withFakeProc(t)
	cpuTimeMu.Lock()
	cpuTimes[1] = cpuTimeEntry{sampledAt: now.Add(-time.Minute)}
	cpuTimes[2] = cpuTimeEntry{sampledAt: *now}
	evictStalestCPUTimes()
	_, oldKept := cpuTimes[1]
	_, newKept := cpuTimes[2]
	cpuTimeMu.Unlock()
	if oldKept || !newKept {
		t.Errorf("after eviction old=%v new=%v; want only the stalest of a small cache dropped", oldKept, newKept)
	}
}
