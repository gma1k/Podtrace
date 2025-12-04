package diagnose

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/profiling"
	"github.com/podtrace/podtrace/internal/events"
)

func TestGenerateCPUUsageReport(t *testing.T) {
	duration := 10 * time.Second

	var testEvents []*events.Event
	report := profiling.GenerateCPUUsageReport(testEvents, duration)
	if report == "" {
		t.Error("GenerateCPUUsageReport should return a report even with no events")
	}
	if !contains(report, "CPU Usage by Process") {
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

	report = profiling.GenerateCPUUsageReport(testEvents, duration)
	if !contains(report, "CPU Usage by Process") {
		t.Error("Report should contain 'CPU Usage by Process'")
	}
	if contains(report, "Pod Processes") || contains(report, "System/Kernel Processes") {
	} else {
		if !contains(report, "No CPU events") && !contains(report, "Total CPU usage") {
			t.Error("Report should contain either process information or indicate no events")
		}
	}
}

func TestIsKernelThread(t *testing.T) {
	tests := []struct {
		name     string
		pid      uint32
		expected bool
	}{
		{"kworker/0:0", 100, true},
		{"[kworker/1:1]", 101, true},
		{"ksoftirqd/0", 102, true},
		{"irq/24-eth0", 103, true},
		{"nginx", 1234, false},
		{"python", 5678, false},
		{"sh", 9999, false},
		{"[rcu_sched]", 50, true},
		{"migration/0", 51, true},
	}

	for _, tt := range tests {
		result := profiling.IsKernelThread(tt.pid, tt.name)
		if result != tt.expected {
			t.Errorf("IsKernelThread(%d, %s) = %v, expected %v",
				tt.pid, tt.name, result, tt.expected)
		}
	}
}

func TestGenerateCPUUsageFromProc(t *testing.T) {
	duration := 10 * time.Second

	report := profiling.GenerateCPUUsageFromProc(duration)
	if report == "" {
		t.Error("GenerateCPUUsageFromProc should return a report")
	}
	if !contains(report, "CPU Usage by Process") {
		t.Error("Report should contain 'CPU Usage by Process'")
	}
	if !contains(report, "No CPU events collected") {
		t.Error("Report should indicate no events collected")
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

	report := profiling.GenerateCPUUsageReport(testEvents, duration)
	if !contains(report, "CPU Usage by Process") {
		t.Error("Report should contain 'CPU Usage by Process'")
	}
	if !contains(report, "Pod Processes") && !contains(report, "System/Kernel Processes") {
		if !contains(report, "Total CPU usage") {
			t.Error("Report should contain process information or total CPU usage")
		}
	}
	_ = report
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}
