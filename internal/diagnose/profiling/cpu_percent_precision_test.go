package profiling

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func shortLivedProcessEvents() []*events.Event {
	now := uint64(time.Now().UnixNano())
	return []*events.Event{
		{PID: 4051323, ProcessName: "wget", Type: events.EventConnect, Timestamp: now},
		{PID: 4009367, ProcessName: "sh", Type: events.EventDNS, Timestamp: now},
		{PID: 4051269, ProcessName: "nslookup", Type: events.EventDNS, Timestamp: now},
	}
}

func TestProcessCPUReport_ShortLivedProcessesAreNotShownAsZero(t *testing.T) {
	kernelNS := map[uint32]uint64{
		4051323: uint64(6700 * time.Microsecond),
		4009367: uint64(4200 * time.Microsecond),
		4051269: uint64(1 * time.Microsecond),
	}
	report := GenerateProcessCPUReport(shortLivedProcessEvents(), 15*time.Second, kernelNS)

	for _, want := range []string{"0.04% CPU (6.7ms / 15.00s)", "0.03% CPU (4.2ms / 15.00s)", "<0.01% CPU (0.0ms / 15.00s)"} {
		if !strings.Contains(report, want) {
			t.Errorf("report is missing %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, " 0.0% CPU") {
		t.Errorf("a process that used CPU must not read as 0.0%%:\n%s", report)
	}
	if !strings.Contains(report, "Total CPU usage: 0.07% (10.9ms / 15.00s)") {
		t.Errorf("the total must keep the same precision:\n%s", report)
	}
}

func TestProcessCPUReport_ColumnsAreAligned(t *testing.T) {
	kernelNS := map[uint32]uint64{
		4051323: uint64(6700 * time.Microsecond),
		4009367: uint64(2 * time.Second),
		4051269: uint64(1500 * time.Microsecond),
	}
	report := GenerateProcessCPUReport(shortLivedProcessEvents(), 15*time.Second, kernelNS)

	column := -1
	for _, line := range strings.Split(report, "\n") {
		if !strings.HasPrefix(line, "    PID ") {
			continue
		}
		at := strings.Index(line, " CPU (")
		if column == -1 {
			column = at
		} else if at != column {
			t.Errorf("CPU column at %d, want %d, in %q:\n%s", at, column, line, report)
		}
	}
	if column == -1 {
		t.Fatalf("no process rows in:\n%s", report)
	}
}

func TestFormatCPUPercent(t *testing.T) {
	for p, want := range map[float64]string{
		0:       "0%",
		0.004:   "<0.01%",
		0.0446:  "0.04%",
		0.5:     "0.50%",
		1:       "1.0%",
		13.333:  "13.3%",
		250.009: "250.0%",
	} {
		if got := formatCPUPercent(p); got != want {
			t.Errorf("formatCPUPercent(%v) = %q, want %q", p, got, want)
		}
	}
}
