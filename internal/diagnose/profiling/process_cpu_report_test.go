package profiling

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/events"
)

const (
	exitedWget     uint32 = 4194001
	exitedNslookup uint32 = 4194002
)

func shortLivedEvents() []*events.Event {
	return []*events.Event{
		{PID: exitedWget, ProcessName: "wget", Type: events.EventTCPSend},
		{PID: exitedWget, ProcessName: "wget", Type: events.EventTCPRecv},
		{PID: exitedNslookup, ProcessName: "nslookup", Type: events.EventDNS},
	}
}

func TestKernelCPUTimeCoversProcessesThatExited(t *testing.T) {
	report := GenerateProcessCPUReport(shortLivedEvents(), 10*time.Second, map[uint32]uint64{
		exitedWget:     4_000_000,
		exitedNslookup: 12_500_000,
	})
	for _, want := range []string{
		"PID 4194001 (wget):",
		"(4.0ms / 10.00s)",
		"PID 4194002 (nslookup):",
		"(12.5ms / 10.00s)",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "events (") {
		t.Errorf("the CPU section must not repeat the event ranking:\n%s", report)
	}
}

func TestNoCPUDataPrintsOneLineInsteadOfTheRanking(t *testing.T) {
	report := GenerateProcessCPUReport(shortLivedEvents(), 10*time.Second, nil)
	want := "CPU Usage by Process:\n" +
		"  CPU time unavailable for the 2 traced processes (all exited before sampling); " +
		"see Process Activity for event counts.\n\n"
	if report != want {
		t.Errorf("got:\n%q\nwant:\n%q", report, want)
	}
}

func TestCPUUnavailableSaysWhy(t *testing.T) {
	alive := uint32(os.Getpid())
	cases := []struct {
		name     string
		activity []tracker.PidInfo
		want     string
	}{
		{"one exited", []tracker.PidInfo{{Pid: exitedWget}},
			"CPU time unavailable for the 1 traced process (it exited before sampling); see Process Activity for event counts."},
		{"some exited", []tracker.PidInfo{{Pid: exitedWget}, {Pid: alive}},
			"CPU time unavailable for the 2 traced processes (1 exited before sampling, the rest had no CPU samples); see Process Activity for event counts."},
		{"none exited", []tracker.PidInfo{{Pid: alive}},
			"CPU time unavailable for the 1 traced process (no CPU samples); see Process Activity for event counts."},
	}
	for _, tc := range cases {
		if got := cpuUnavailable(tc.activity); got != tc.want {
			t.Errorf("%s:\ngot  %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

func TestKernelCPUTimeTakesPrecedenceOverProc(t *testing.T) {
	alive := uint32(os.Getpid())
	evs := []*events.Event{{PID: alive, ProcessName: "podtrace-test", Type: events.EventRead}}
	report := GenerateProcessCPUReport(evs, 10*time.Second, map[uint32]uint64{alive: 2_500_000_000})
	if !strings.Contains(report, "(2.50s / 10.00s)") {
		t.Errorf("the kernel's figure must be used when it has one:\n%s", report)
	}
}

func TestFormatCPUTime(t *testing.T) {
	cases := map[float64]string{
		0:       "0.0ms",
		0.004:   "4.0ms",
		0.9994:  "999.4ms",
		1:       "1.00s",
		12.3456: "12.35s",
	}
	for in, want := range cases {
		if got := formatCPUTime(in); got != want {
			t.Errorf("formatCPUTime(%v) = %q, want %q", in, got, want)
		}
	}
}
