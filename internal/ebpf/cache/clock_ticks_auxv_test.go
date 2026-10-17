package cache

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func TestClockTicksReadsATCLKTCKNotATUID(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	auxv := make([]byte, 0, 48)
	for _, pair := range [][2]uint64{{11, 1000}, {17, 250}, {0, 0}} {
		auxv = binary.LittleEndian.AppendUint64(auxv, pair[0])
		auxv = binary.LittleEndian.AppendUint64(auxv, pair[1])
	}
	if err := os.WriteFile(filepath.Join(dir, "self", "auxv"), auxv, 0o644); err != nil {
		t.Fatal(err)
	}

	orig := config.ProcBasePath
	config.ProcBasePath = dir
	cpuTimeMu.Lock()
	savedTicks, savedOK := clockTicks, clockTicksOK
	clockTicks, clockTicksOK = 100, false
	cpuTimeMu.Unlock()
	t.Cleanup(func() {
		config.ProcBasePath = orig
		cpuTimeMu.Lock()
		clockTicks, clockTicksOK = savedTicks, savedOK
		cpuTimeMu.Unlock()
	})

	if got := ClockTicks(); got != 250 {
		t.Errorf("ClockTicks() = %d, want AT_CLKTCK (250), not AT_UID (1000)", got)
	}
}
