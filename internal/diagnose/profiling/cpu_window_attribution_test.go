package profiling

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/cache"
)

func fakeProcWithProcess(t *testing.T, pid uint32, startTicks, cpuTicks uint64, uptime string) {
	t.Helper()
	dir := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = dir
	t.Cleanup(func() { config.ProcBasePath = orig })
	cache.ResetCPUTimes()
	t.Cleanup(cache.ResetCPUTimes)

	if err := os.MkdirAll(filepath.Join(dir, fmt.Sprint(pid)), 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (app) S 1 1 1 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0 %d 0 0", pid, cpuTicks, startTicks)
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(pid), "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uptime"), []byte(uptime), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestALongRunningProcessWithoutABaselineIsNotChargedItsLifetime(t *testing.T) {
	ticks := clockTicksPerSecond()
	fakeProcWithProcess(t, 4321, 10*ticks, 3600*ticks, "86400.00 1.00\n")

	if got := procCPUDeltaNS(4321, 30*time.Second); got != 0 {
		t.Errorf("delta = %v, want 0: an hour of CPU from a day-old process is not the last 30s", time.Duration(got))
	}
}

func TestAProcessStartedDuringTheWindowIsChargedItsLifetime(t *testing.T) {
	ticks := clockTicksPerSecond()
	fakeProcWithProcess(t, 4322, 100*ticks-5*ticks, 2*ticks, "100.00 1.00\n")

	if got, want := procCPUDeltaNS(4322, 30*time.Second), uint64(2*time.Second); got != want {
		t.Errorf("delta = %v, want %v", time.Duration(got), time.Duration(want))
	}
}

func TestABaselineLargerThanTheTotalMeansThePIDWasReused(t *testing.T) {
	ticks := clockTicksPerSecond()
	fakeProcWithProcess(t, 4323, 10*ticks, 1*ticks, "86400.00 1.00\n")
	cache.SnapshotCPUTime(4323)
	_ = os.WriteFile(filepath.Join(config.ProcBasePath, "4323", "stat"),
		[]byte(fmt.Sprintf("4323 (new) S 1 1 1 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0 %d 0 0", 0, 10*ticks)), 0o644)

	if got := procCPUDeltaNS(4323, 30*time.Second); got != 0 {
		t.Errorf("delta = %v, want 0 for a pid whose CPU total went backwards", time.Duration(got))
	}
}

func TestStartedWithinIsFalseWhenProcCannotSayWhen(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no stat":           {"uptime": "100.00 1.00\n"},
		"stat without comm": {"4330/stat": "garbage", "uptime": "100.00 1.00\n"},
		"stat too short":    {"4330/stat": "4330 (app) S 1 1", "uptime": "100.00 1.00\n"},
		"start not numeric": {"4330/stat": "4330 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 soon 0 0", "uptime": "100.00 1.00\n"},
		"no uptime":         {"4330/stat": "4330 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9500 0 0"},
		"empty uptime":      {"4330/stat": "4330 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9500 0 0", "uptime": "\n"},
		"uptime not number": {"4330/stat": "4330 (app) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9500 0 0", "uptime": "later 1.00\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			orig := config.ProcBasePath
			config.ProcBasePath = dir
			t.Cleanup(func() { config.ProcBasePath = orig })
			for path, content := range files {
				full := filepath.Join(dir, path)
				_ = os.MkdirAll(filepath.Dir(full), 0o755)
				_ = os.WriteFile(full, []byte(content), 0o644)
			}
			if startedWithin(4330, time.Hour) {
				t.Error("startedWithin = true without a readable start time")
			}
		})
	}
}
