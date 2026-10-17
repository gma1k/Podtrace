package probes

import (
	"os"
	"testing"
)

func TestProcessStartTimeReadsALiveProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	start, ok := ProcessStartTime(pid)
	if !ok || start == 0 {
		t.Fatalf("ProcessStartTime(%d) = %d, %v; want this process's start time", pid, start, ok)
	}
	inner, _ := processStartTime(pid)
	if start != inner {
		t.Errorf("exported %d differs from internal %d", start, inner)
	}
}
