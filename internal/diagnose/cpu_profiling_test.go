package diagnose

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestGenerateCPUUsageReport(t *testing.T) {
	d := NewDiagnostician()
	duration := 10 * time.Second

	report := d.generateCPUUsageReport(duration)
	if report == "" {
		t.Error("generateCPUUsageReport should return a report even with no events")
	}
	if !contains(report, "CPU Usage by Process") {
		t.Error("Report should contain 'CPU Usage by Process'")
	}

	d.AddEvent(&events.Event{
		PID:         1234,
		ProcessName: "test-process",
		Type:        events.EventDNS,
		Timestamp:   uint64(time.Now().UnixNano()),
	})

	d.AddEvent(&events.Event{
		PID:         1234,
		ProcessName: "test-process",
		Type:        events.EventConnect,
		Timestamp:   uint64(time.Now().UnixNano()),
	})

	d.AddEvent(&events.Event{
		PID:         5678,
		ProcessName: "another-process",
		Type:        events.EventTCPSend,
		Timestamp:   uint64(time.Now().UnixNano()),
	})

	report = d.generateCPUUsageReport(duration)
	if !contains(report, "CPU Usage by Process") {
		t.Error("Report should contain 'CPU Usage by Process'")
	}
	if !contains(report, "Pod Processes") {
		t.Error("Report should contain 'Pod Processes' section")
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
		result := isKernelThread(tt.pid, tt.name)
		if result != tt.expected {
			t.Errorf("isKernelThread(%d, %s) = %v, expected %v",
				tt.pid, tt.name, result, tt.expected)
		}
	}
}

func TestGenerateCPUUsageFromProc(t *testing.T) {
	d := NewDiagnostician()
	duration := 10 * time.Second

	report := d.generateCPUUsageFromProc(duration)
	if report == "" {
		t.Error("generateCPUUsageFromProc should return a report")
	}
	if !contains(report, "CPU Usage by Process") {
		t.Error("Report should contain 'CPU Usage by Process'")
	}
	if !contains(report, "No CPU events collected") {
		t.Error("Report should indicate no events collected")
	}
}

func TestCPUUsageReportWithKernelThreads(t *testing.T) {
	d := NewDiagnostician()
	duration := 10 * time.Second

	d.AddEvent(&events.Event{
		PID:         1234,
		ProcessName: "nginx",
		Type:        events.EventDNS,
		Timestamp:   uint64(time.Now().UnixNano()),
	})

	d.AddEvent(&events.Event{
		PID:         10,
		ProcessName: "kworker/0:0",
		Type:        events.EventSchedSwitch,
		Timestamp:   uint64(time.Now().UnixNano()),
	})

	report := d.generateCPUUsageReport(duration)
	if !contains(report, "Pod Processes") {
		t.Error("Report should have Pod Processes section")
	}
	_ = report
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && 
			(s[:len(substr)] == substr || 
			 s[len(s)-len(substr):] == substr ||
			 containsMiddle(s, substr))))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
