package profiling

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestGenerateCPUUsageReport(t *testing.T) {
	duration := 10 * time.Second

	var testEvents []*events.Event
	report := GenerateCPUUsageReport(testEvents, duration)
	if report == "" {
		t.Error("GenerateCPUUsageReport should return a report even with no events")
	}
	if !strings.Contains(report, "CPU Usage by Process") {
		t.Error("Report should contain 'CPU Usage by Process'")
	}

	testEvents = []*events.Event{
		{
			PID:         1,
			ProcessName: "init",
			Type:        events.EventDNS,
			Timestamp:   uint64(time.Now().UnixNano()),
		},
		{
			PID:         1,
			ProcessName: "init",
			Type:        events.EventConnect,
			Timestamp:   uint64(time.Now().UnixNano()),
		},
	}

	selfPID := uint32(os.Getpid())
	if selfPID > 1 {
		testEvents = append(testEvents, &events.Event{
			PID:         selfPID,
			ProcessName: "test-process",
			Type:        events.EventTCPSend,
			Timestamp:   uint64(time.Now().UnixNano()),
		})
	}

	report = GenerateCPUUsageReport(testEvents, duration)
	if !strings.Contains(report, "CPU Usage by Process") {
		t.Error("Report should contain 'CPU Usage by Process'")
	}
	if strings.Contains(report, "Pod Processes") || strings.Contains(report, "System/Kernel Processes") {
	} else {
		if !strings.Contains(report, "No CPU events") && !strings.Contains(report, "Total CPU usage") {
			t.Error("Report should contain either process information or indicate no events")
		}
	}
}


func TestCPUUsageReportWithKernelThreads(t *testing.T) {
	duration := 10 * time.Second

	testEvents := []*events.Event{
		{
			PID:         1,
			ProcessName: "init",
			Type:        events.EventDNS,
			Timestamp:   uint64(time.Now().UnixNano()),
		},
		{
			PID:         2,
			ProcessName: "kthreadd",
			Type:        events.EventSchedSwitch,
			Timestamp:   uint64(time.Now().UnixNano()),
		},
	}

	report := GenerateCPUUsageReport(testEvents, duration)
	if !strings.Contains(report, "CPU Usage by Process") {
		t.Error("Report should contain 'CPU Usage by Process'")
	}
	if !strings.Contains(report, "Pod Processes") && !strings.Contains(report, "System/Kernel Processes") {
		if !strings.Contains(report, "Total CPU usage") {
			t.Error("Report should contain process information or total CPU usage")
		}
	}
	_ = report
}

