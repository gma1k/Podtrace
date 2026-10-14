package cache

import (
	"os"
	"testing"
)

func TestReadUint64LE(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want uint64
	}{
		{"zero", []byte{0, 0, 0, 0, 0, 0, 0, 0}, 0},
		{"one", []byte{1, 0, 0, 0, 0, 0, 0, 0}, 1},
		{"low byte", []byte{0xff, 0, 0, 0, 0, 0, 0, 0}, 0xff},
		{"high byte", []byte{0, 0, 0, 0, 0, 0, 0, 1}, 1 << 56},
		{"all ones", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ^uint64(0)},
		{"mixed", []byte{0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0}, 0x12345678},
		{"trailing bytes ignored", []byte{1, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := readUint64LE(tt.in); got != tt.want {
				t.Errorf("readUint64LE(%v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestGetCPUTime_Cache(t *testing.T) {
	ResetCPUTimes()
	t.Cleanup(ResetCPUTimes)

	if got := GetCPUTime(424242); got.TotalNS != 0 {
		t.Errorf("GetCPUTime(unknown) = %d, want 0", got.TotalNS)
	}

	const pid uint32 = 1234
	const want uint64 = 5_000_000_000
	cpuTimeMu.Lock()
	cpuTimes[pid] = cpuTimeEntry{ProcessCPUTime: ProcessCPUTime{TotalNS: want}}
	cpuTimeMu.Unlock()

	if got := GetCPUTime(pid); got.TotalNS != want {
		t.Errorf("GetCPUTime(%d) = %d, want %d", pid, got.TotalNS, want)
	}
}

func TestMergeCPUSample_Baseline(t *testing.T) {
	first := mergeCPUSample(ProcessCPUTime{}, false, 3_000_000_000)
	if first.TotalNS != 3_000_000_000 || first.BaselineNS != 3_000_000_000 {
		t.Fatalf("first sample: total=%d baseline=%d, want both 3e9", first.TotalNS, first.BaselineNS)
	}

	second := mergeCPUSample(first, true, 3_400_000_000)
	if second.TotalNS != 3_400_000_000 {
		t.Errorf("TotalNS=%d, want 3.4e9 (latest)", second.TotalNS)
	}
	if second.BaselineNS != 3_000_000_000 {
		t.Errorf("BaselineNS=%d, want 3e9 preserved (not reset to latest)", second.BaselineNS)
	}
	if got := second.TotalNS - second.BaselineNS; got != 400_000_000 {
		t.Errorf("window delta = %d, want 4e8 (0.4s CPU during the trace)", got)
	}
}

func TestResetCPUTimes(t *testing.T) {
	t.Cleanup(ResetCPUTimes)

	const pid uint32 = 9876
	cpuTimeMu.Lock()
	cpuTimes[pid] = cpuTimeEntry{ProcessCPUTime: ProcessCPUTime{TotalNS: 42}}
	cpuTimeMu.Unlock()

	if got := GetCPUTime(pid); got.TotalNS != 42 {
		t.Fatalf("precondition: GetCPUTime(%d) = %d, want 42", pid, got.TotalNS)
	}

	ResetCPUTimes()

	if got := GetCPUTime(pid); got.TotalNS != 0 {
		t.Errorf("after ResetCPUTimes, GetCPUTime(%d) = %d, want 0", pid, got.TotalNS)
	}
}

func TestLoadClockTicks(t *testing.T) {
	got := loadClockTicks()
	if got == 0 {
		t.Fatalf("loadClockTicks() = 0, want positive")
	}
	if again := loadClockTicks(); again != got {
		t.Errorf("loadClockTicks() second call = %d, want %d (memoized)", again, got)
	}
}

func TestSnapshotCPUTime_UnreadablePID(t *testing.T) {
	ResetCPUTimes()
	t.Cleanup(ResetCPUTimes)

	SnapshotCPUTime(0)
	if got := GetCPUTime(0); got.TotalNS != 0 {
		t.Errorf("SnapshotCPUTime(0) recorded %d, want nothing", got.TotalNS)
	}
}

func TestSnapshotCPUTime_SelfRecordsEntry(t *testing.T) {
	ResetCPUTimes()
	t.Cleanup(ResetCPUTimes)

	self := uint32(os.Getpid())
	SnapshotCPUTime(self)

	cpuTimeMu.RLock()
	_, ok := cpuTimes[self]
	cpuTimeMu.RUnlock()
	if !ok {
		t.Errorf("SnapshotCPUTime(self=%d) did not record an entry", self)
	}
}
