//go:build bpf_loadtest && linux

package tracer

import (
	"os/exec"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
)

func TestKernelAForkCarriesTheChildsPidAndName(t *testing.T) {
	log := traceGroup(t, probes.GroupCPU, func(ev *events.Event) bool {
		return ev.Type == events.EventFork
	})
	var pids []int
	for i := 0; i < 5; i++ {
		cmd := exec.Command("/bin/true")
		if err := cmd.Run(); err != nil {
			t.Fatalf("run a child: %v", err)
		}
		pids = append(pids, cmd.Process.Pid)
	}
	time.Sleep(2 * time.Second)

	byPID := map[uint32]*events.Event{}
	for _, ev := range log.events() {
		byPID[ev.PID] = ev
	}
	seen := 0
	for _, pid := range pids {
		ev, ok := byPID[uint32(pid)]
		if !ok {
			continue
		}
		seen++
		if ev.Target != "tracer.test" {
			t.Errorf("fork of pid %d names %q, want the forking program's name", pid, ev.Target)
		}
	}
	if seen == 0 {
		t.Errorf("none of the %d forked children was reported with its pid %v", len(pids), pids)
	}
}
