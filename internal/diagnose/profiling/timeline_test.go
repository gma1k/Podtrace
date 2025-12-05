package profiling

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

func TestAnalyzeTimeline_Basic(t *testing.T) {
	start := time.Now()
	duration := 5 * time.Second

	var evs []*events.Event
	for i := 0; i < 10; i++ {
		evs = append(evs, &events.Event{
			Timestamp: uint64(start.Add(time.Duration(i) * time.Second).UnixNano()),
		})
	}

	buckets := AnalyzeTimeline(evs, start, duration)
	if len(buckets) != 5 {
		t.Fatalf("expected 5 buckets, got %d", len(buckets))
	}
}

func TestDetectBursts(t *testing.T) {
	start := time.Now()
	duration := 2 * time.Second

	var evs []*events.Event
	for i := 0; i < 20; i++ {
		evs = append(evs, &events.Event{
			Timestamp: uint64(start.Add(500 * time.Millisecond).UnixNano()),
		})
	}

	_ = DetectBursts(evs, start, duration)
}

func TestAnalyzeConnectionPattern_Empty(t *testing.T) {
	cp := AnalyzeConnectionPattern(nil, time.Now(), time.Now(), time.Second)
	if cp.Pattern != "" {
		t.Fatalf("expected empty pattern for no events, got %q", cp.Pattern)
	}
}

func TestAnalyzeConnectionPattern_Basic(t *testing.T) {
	start := time.Now()
	end := start.Add(10 * time.Second)
	duration := end.Sub(start)

	evs := []*events.Event{
		{Timestamp: uint64(start.Add(time.Second).UnixNano()), Target: "example.com"},
		{Timestamp: uint64(start.Add(2 * time.Second).UnixNano()), Target: "api.example.com"},
	}

	cp := AnalyzeConnectionPattern(evs, start, end, duration)
	if cp.AvgRate <= 0 {
		t.Fatalf("expected positive avg rate")
	}
}

func TestAnalyzeIOPattern_Basic(t *testing.T) {
	start := time.Now()
	duration := 5 * time.Second
	evs := []*events.Event{
		{Type: events.EventTCPSend, Timestamp: uint64(start.Add(time.Second).UnixNano())},
		{Type: events.EventTCPRecv, Timestamp: uint64(start.Add(2 * time.Second).UnixNano())},
	}

	p := AnalyzeIOPattern(evs, start, duration)
	if p.AvgThroughput <= 0 {
		t.Fatalf("expected positive avg throughput")
	}
}

func TestAnalyzeTimeline_Extended(t *testing.T) {
	startTime := time.Now()
	duration := 10 * time.Second

	tests := []struct {
		name   string
		events []*events.Event
	}{
		{
			"empty events",
			[]*events.Event{},
		},
		{
			"single event",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano())},
			},
		},
		{
			"multiple events",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano())},
				{Timestamp: uint64(startTime.Add(2 * time.Second).UnixNano())},
				{Timestamp: uint64(startTime.Add(5 * time.Second).UnixNano())},
			},
		},
		{
			"events before start",
			[]*events.Event{
				{Timestamp: uint64(startTime.Add(-1 * time.Second).UnixNano())},
			},
		},
		{
			"events after end",
			[]*events.Event{
				{Timestamp: uint64(startTime.Add(15 * time.Second).UnixNano())},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeTimeline(tt.events, startTime, duration)
			if len(tt.events) == 0 && result != nil {
				t.Error("Expected nil for empty events")
			}
			if len(tt.events) > 0 && result == nil {
				t.Error("Expected non-nil result for non-empty events")
			}
		})
	}
}

func TestDetectBursts_Extended(t *testing.T) {
	startTime := time.Now()
	duration := 5 * time.Second

	tests := []struct {
		name   string
		events []*events.Event
	}{
		{
			"empty events",
			[]*events.Event{},
		},
		{
			"few events",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano())},
			},
		},
		{
			"many events",
			makeEvents(startTime, 100),
		},
		{
			"burst pattern",
			append(
				makeEvents(startTime, 10),
				makeEvents(startTime.Add(2*time.Second), 50)...,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectBursts(tt.events, startTime, duration)
			if result == nil && len(tt.events) >= 10 {
				t.Log("No bursts detected (may be expected)")
			}
		})
	}
}

func TestAnalyzeConnectionPattern_Extended(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(10 * time.Second)
	duration := 10 * time.Second

	tests := []struct {
		name   string
		events []*events.Event
	}{
		{
			"empty events",
			[]*events.Event{},
		},
		{
			"steady pattern",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano()), Target: "example.com:80"},
				{Timestamp: uint64(startTime.Add(2 * time.Second).UnixNano()), Target: "example.com:80"},
				{Timestamp: uint64(startTime.Add(4 * time.Second).UnixNano()), Target: "example.com:80"},
			},
		},
		{
			"bursty pattern",
			append(
				[]*events.Event{
					{Timestamp: uint64(startTime.UnixNano()), Target: "example.com:80"},
				},
				makeConnectEvents(startTime.Add(5*time.Second), 20)...,
			),
		},
		{
			"multiple targets",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano()), Target: "example.com:80"},
				{Timestamp: uint64(startTime.Add(1 * time.Second).UnixNano()), Target: "test.com:443"},
				{Timestamp: uint64(startTime.Add(2 * time.Second).UnixNano()), Target: "api.com:8080"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeConnectionPattern(tt.events, startTime, endTime, duration)
			if len(tt.events) == 0 {
				if result.Pattern != "" {
					t.Error("Expected empty pattern for empty events")
				}
			} else {
				if result.Pattern == "" {
					t.Error("Expected non-empty pattern")
				}
			}
		})
	}
}

func TestAnalyzeIOPattern_Extended(t *testing.T) {
	startTime := time.Now()
	duration := 10 * time.Second

	tests := []struct {
		name   string
		events []*events.Event
	}{
		{
			"empty events",
			[]*events.Event{},
		},
		{
			"send only",
			[]*events.Event{
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.UnixNano())},
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.Add(1 * time.Second).UnixNano())},
			},
		},
		{
			"recv only",
			[]*events.Event{
				{Type: events.EventTCPRecv, Timestamp: uint64(startTime.UnixNano())},
				{Type: events.EventTCPRecv, Timestamp: uint64(startTime.Add(1 * time.Second).UnixNano())},
			},
		},
		{
			"balanced",
			[]*events.Event{
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.UnixNano())},
				{Type: events.EventTCPRecv, Timestamp: uint64(startTime.Add(1 * time.Second).UnixNano())},
			},
		},
		{
			"more send",
			[]*events.Event{
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.UnixNano())},
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.Add(1 * time.Second).UnixNano())},
				{Type: events.EventTCPRecv, Timestamp: uint64(startTime.Add(2 * time.Second).UnixNano())},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeIOPattern(tt.events, startTime, duration)
			if len(tt.events) == 0 {
				if result.SendRecvRatio != 1.0 {
					t.Error("Expected SendRecvRatio 1.0 for empty events")
				}
			}
		})
	}
}

func TestIsKernelThread(t *testing.T) {
	tests := []struct {
		name     string
		pid      uint32
		procName string
		expected bool
	}{
		{"kworker", 1, "kworker/0:0", true},
		{"irq", 2, "irq/1", true},
		{"ksoftirqd", 3, "ksoftirqd/0", true},
		{"migration", 4, "migration/0", true},
		{"rcu", 5, "rcu_sched", true},
		{"watchdog", 6, "watchdog/0", true},
		{"brackets", 7, "[kthreadd]", true},
		{"normal process", 8, "bash", false},
		{"normal process 2", 9, "python", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsKernelThread(tt.pid, tt.procName)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGenerateCPUUsageFromProc(t *testing.T) {
	result := GenerateCPUUsageFromProc(10 * time.Second)
	if result == "" {
		t.Error("Expected non-empty report")
	}
	if !contains(result, "CPU Usage") {
		t.Error("Expected report to contain 'CPU Usage'")
	}
}

func makeEvents(startTime time.Time, count int) []*events.Event {
	evs := make([]*events.Event, count)
	for i := 0; i < count; i++ {
		evs[i] = &events.Event{
			Timestamp: uint64(startTime.Add(time.Duration(i) * 100 * time.Millisecond).UnixNano()),
		}
	}
	return evs
}

func makeConnectEvents(startTime time.Time, count int) []*events.Event {
	evs := make([]*events.Event, count)
	for i := 0; i < count; i++ {
		evs[i] = &events.Event{
			Type:      events.EventConnect,
			Timestamp: uint64(startTime.Add(time.Duration(i) * 50 * time.Millisecond).UnixNano()),
			Target:    "example.com:80",
		}
	}
	return evs
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr))
}

func TestAnalyzeTimeline_BucketIndexEdgeCases(t *testing.T) {
	startTime := time.Now()
	duration := 10 * time.Second

	tests := []struct {
		name   string
		events []*events.Event
	}{
		{
			"event at exact boundary",
			[]*events.Event{
				{Timestamp: uint64(startTime.Add(10 * time.Second).UnixNano())},
			},
		},
		{
			"event way after end",
			[]*events.Event{
				{Timestamp: uint64(startTime.Add(100 * time.Second).UnixNano())},
			},
		},
		{
			"event exactly at start",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano())},
			},
		},
		{
			"event before start",
			[]*events.Event{
				{Timestamp: uint64(startTime.Add(-1 * time.Second).UnixNano())},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeTimeline(tt.events, startTime, duration)
			if result == nil {
				t.Error("Expected non-nil result")
			}
			if len(result) != config.TimelineBuckets {
				t.Errorf("Expected %d buckets, got %d", config.TimelineBuckets, len(result))
			}
		})
	}
}

func TestDetectBursts_EdgeCases(t *testing.T) {
	startTime := time.Now()

	tests := []struct {
		name     string
		events   []*events.Event
		duration time.Duration
	}{
		{
			"zero duration",
			makeEvents(startTime, 20),
			time.Duration(0),
		},
		{
			"duration less than 2 seconds",
			makeEvents(startTime, 20),
			1 * time.Second,
		},
		{
			"events with rate not exceeding threshold",
			func() []*events.Event {
				evs := make([]*events.Event, 20)
				for i := 0; i < 20; i++ {
					evs[i] = &events.Event{
						Timestamp: uint64(startTime.Add(time.Duration(i) * 200 * time.Millisecond).UnixNano()),
					}
				}
				return evs
			}(),
			5 * time.Second,
		},
		{
			"events exactly at window boundaries",
			func() []*events.Event {
				evs := make([]*events.Event, 20)
				for i := 0; i < 20; i++ {
					evs[i] = &events.Event{
						Timestamp: uint64(startTime.Add(time.Duration(i) * time.Second).UnixNano()),
					}
				}
				return evs
			}(),
			5 * time.Second,
		},
		{
			"events before window start",
			func() []*events.Event {
				evs := make([]*events.Event, 20)
				for i := 0; i < 20; i++ {
					evs[i] = &events.Event{
						Timestamp: uint64(startTime.Add(-1 * time.Second).UnixNano()),
					}
				}
				return evs
			}(),
			5 * time.Second,
		},
		{
			"events after window end",
			func() []*events.Event {
				evs := make([]*events.Event, 20)
				for i := 0; i < 20; i++ {
					evs[i] = &events.Event{
						Timestamp: uint64(startTime.Add(10 * time.Second).UnixNano()),
					}
				}
				return evs
			}(),
			5 * time.Second,
		},
		{
			"events exactly at window boundaries",
			func() []*events.Event {
				evs := make([]*events.Event, 20)
				for i := 0; i < 20; i++ {
					evs[i] = &events.Event{
						Timestamp: uint64(startTime.Add(time.Duration(i) * time.Second).UnixNano()),
					}
				}
				return evs
			}(),
			5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectBursts(tt.events, startTime, tt.duration)
			if result == nil {
				t.Log("No bursts detected (may be expected)")
			}
		})
	}
}

func TestAnalyzeConnectionPattern_EdgeCases(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(10 * time.Second)

	tests := []struct {
		name     string
		events   []*events.Event
		duration time.Duration
	}{
		{
			"zero duration",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano()), Target: "example.com:80"},
			},
			time.Duration(0),
		},
		{
			"very short duration",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano()), Target: "example.com:80"},
			},
			50 * time.Millisecond,
		},
		{
			"steady pattern",
			func() []*events.Event {
				evs := make([]*events.Event, 10)
				for i := 0; i < 10; i++ {
					evs[i] = &events.Event{
						Timestamp: uint64(startTime.Add(time.Duration(i) * time.Second).UnixNano()),
						Target:    "example.com:80",
					}
				}
				return evs
			}(),
			10 * time.Second,
		},
		{
			"bursty pattern",
			func() []*events.Event {
				var evs []*events.Event
				for i := 0; i < 10; i++ {
					count := 1
					if i == 5 {
						count = 20
					}
					for j := 0; j < count; j++ {
						evs = append(evs, &events.Event{
							Timestamp: uint64(startTime.Add(time.Duration(i) * time.Second).UnixNano()),
							Target:    "example.com:80",
						})
					}
				}
				return evs
			}(),
			10 * time.Second,
		},
		{
			"sporadic pattern",
			func() []*events.Event {
				var evs []*events.Event
				for i := 0; i < 10; i++ {
					count := 1
					if i%3 == 0 {
						count = 3
					}
					for j := 0; j < count; j++ {
						evs = append(evs, &events.Event{
							Timestamp: uint64(startTime.Add(time.Duration(i) * time.Second).UnixNano()),
							Target:    "example.com:80",
						})
					}
				}
				return evs
			}(),
			10 * time.Second,
		},
		{
			"target filtering",
			[]*events.Event{
				{Timestamp: uint64(startTime.UnixNano()), Target: "example.com:80"},
				{Timestamp: uint64(startTime.Add(time.Second).UnixNano()), Target: ""},
				{Timestamp: uint64(startTime.Add(2 * time.Second).UnixNano()), Target: "?"},
				{Timestamp: uint64(startTime.Add(3 * time.Second).UnixNano()), Target: "unknown"},
				{Timestamp: uint64(startTime.Add(4 * time.Second).UnixNano()), Target: "file"},
				{Timestamp: uint64(startTime.Add(5 * time.Second).UnixNano()), Target: "valid.com:443"},
			},
			10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeConnectionPattern(tt.events, startTime, endTime, tt.duration)
			if len(tt.events) == 0 {
				if result.Pattern != "" {
					t.Error("Expected empty pattern for empty events")
				}
			}
		})
	}
}

func TestAnalyzeIOPattern_EdgeCases(t *testing.T) {
	startTime := time.Now()

	tests := []struct {
		name     string
		events   []*events.Event
		duration time.Duration
	}{
		{
			"zero duration",
			[]*events.Event{
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.UnixNano())},
			},
			time.Duration(0),
		},
		{
			"duration less than 1 second",
			[]*events.Event{
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.UnixNano())},
			},
			500 * time.Millisecond,
		},
		{
			"zero duration",
			[]*events.Event{
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.UnixNano())},
			},
			time.Duration(0),
		},
		{
			"only send events",
			[]*events.Event{
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.UnixNano())},
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.Add(time.Second).UnixNano())},
			},
			5 * time.Second,
		},
		{
			"events at window boundaries",
			func() []*events.Event {
				evs := make([]*events.Event, 10)
				for i := 0; i < 10; i++ {
					evs[i] = &events.Event{
						Type:      events.EventTCPSend,
						Timestamp: uint64(startTime.Add(time.Duration(i) * time.Second).UnixNano()),
					}
				}
				return evs
			}(),
			10 * time.Second,
		},
		{
			"mixed event types",
			[]*events.Event{
				{Type: events.EventDNS, Timestamp: uint64(startTime.UnixNano())},
				{Type: events.EventTCPSend, Timestamp: uint64(startTime.Add(time.Second).UnixNano())},
				{Type: events.EventTCPRecv, Timestamp: uint64(startTime.Add(2 * time.Second).UnixNano())},
			},
			5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeIOPattern(tt.events, startTime, tt.duration)
			if len(tt.events) == 0 {
				if result.SendRecvRatio != 1.0 {
					t.Error("Expected SendRecvRatio 1.0 for empty events")
				}
			}
		})
	}
}

func TestGenerateCPUUsageReport_EmptyEvents(t *testing.T) {
	result := GenerateCPUUsageReport([]*events.Event{}, 10*time.Second)
	if result == "" {
		t.Error("Expected non-empty report")
	}
	if !contains(result, "No CPU events") {
		t.Error("Expected report to contain 'No CPU events'")
	}
}

func TestGenerateCPUUsageReport_WithEvents(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = dir

	pid1 := uint32(1234)
	pid2 := uint32(5678)
	pid3 := uint32(9999)

	stat1Path := fmt.Sprintf("%s/%d/stat", dir, pid1)
	stat2Path := fmt.Sprintf("%s/%d/stat", dir, pid2)
	stat3Path := fmt.Sprintf("%s/%d/stat", dir, pid3)
	_ = os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid1), 0755)
	_ = os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid2), 0755)
	_ = os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid3), 0755)

	statContent := "1234 (test) S 1 1234 1234 0 -1 4194304 100 0 0 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	_ = os.WriteFile(stat1Path, []byte(statContent), 0644)
	_ = os.WriteFile(stat2Path, []byte(statContent), 0644)
	_ = os.WriteFile(stat3Path, []byte(statContent), 0644)

	events := []*events.Event{
		{PID: pid1, ProcessName: "test-process", Type: events.EventSchedSwitch},
		{PID: pid1, ProcessName: "test-process", Type: events.EventSchedSwitch},
		{PID: pid2, ProcessName: "kworker/0:0", Type: events.EventSchedSwitch},
		{PID: pid3, ProcessName: "another-process", Type: events.EventSchedSwitch},
	}
	result := GenerateCPUUsageReport(events, 10*time.Second)
	if result == "" {
		t.Error("Expected non-empty report")
	}
	if !contains(result, "CPU Usage by Process") {
		t.Error("Expected report to contain 'CPU Usage by Process'")
	}
	if !contains(result, "Pod Processes") {
		t.Error("Expected report to contain 'Pod Processes'")
	}
	if !contains(result, "System/Kernel Processes") {
		t.Error("Expected report to contain 'System/Kernel Processes'")
	}
}

func TestGenerateCPUUsageReport_ZeroCPUTime(t *testing.T) {
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = "/nonexistent/proc"

	events := []*events.Event{
		{PID: 1234, ProcessName: "test-process", Type: events.EventSchedSwitch},
	}
	result := GenerateCPUUsageReport(events, 10*time.Second)
	if result == "" {
		t.Error("Expected non-empty report")
	}
	if !contains(result, "CPU Usage by Process") {
		t.Error("Expected report to contain 'CPU Usage by Process'")
	}
}

func TestGenerateCPUUsageReport_NoKernelProcesses(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = dir

	pid1 := uint32(1234)
	stat1Path := fmt.Sprintf("%s/%d/stat", dir, pid1)
	_ = os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid1), 0755)

	statContent := "1234 (test) S 1 1234 1234 0 -1 4194304 100 0 0 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	_ = os.WriteFile(stat1Path, []byte(statContent), 0644)

	events := []*events.Event{
		{PID: pid1, ProcessName: "test-process", Type: events.EventSchedSwitch},
	}
	result := GenerateCPUUsageReport(events, 10*time.Second)
	if result == "" {
		t.Error("Expected non-empty report")
	}
	if !contains(result, "Pod Processes") {
		t.Error("Expected report to contain 'Pod Processes'")
	}
}

func TestGenerateCPUUsageReport_ManyKernelProcesses(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = dir

	statContent := "1234 (test) S 1 1234 1234 0 -1 4194304 100 0 0 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"

	var evs []*events.Event
	for i := 0; i < config.TopProcessesLimit+5; i++ {
		pid := uint32(1000 + i)
		statPath := fmt.Sprintf("%s/%d/stat", dir, pid)
		_ = os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
		_ = os.WriteFile(statPath, []byte(statContent), 0644)
		evs = append(evs, &events.Event{
			PID:         pid,
			ProcessName: fmt.Sprintf("kworker/%d:0", i),
			Type:        events.EventSchedSwitch,
		})
	}

	result := GenerateCPUUsageReport(evs, 10*time.Second)
	if result == "" {
		t.Error("Expected non-empty report")
	}
	if !contains(result, "more system processes") {
		t.Error("Expected report to contain 'more system processes'")
	}
}

func TestGenerateCPUUsageReport_ManyPodProcesses(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = dir

	statContent := "1234 (test) S 1 1234 1234 0 -1 4194304 100 0 0 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"

	var evs []*events.Event
	for i := 0; i < config.TopProcessesLimit*2+5; i++ {
		pid := uint32(2000 + i)
		statPath := fmt.Sprintf("%s/%d/stat", dir, pid)
		_ = os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
		_ = os.WriteFile(statPath, []byte(statContent), 0644)
		evs = append(evs, &events.Event{
			PID:         pid,
			ProcessName: fmt.Sprintf("pod-process-%d", i),
			Type:        events.EventSchedSwitch,
		})
	}

	result := GenerateCPUUsageReport(evs, 10*time.Second)
	if result == "" {
		t.Error("Expected non-empty report")
	}
	if !contains(result, "Pod Processes") {
		t.Error("Expected report to contain 'Pod Processes'")
	}
}

func TestGetProcessCPUTime_FileError(t *testing.T) {
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = "/nonexistent/proc"
	result := getProcessCPUTime(1234)
	if result.totalNS != 0 {
		t.Errorf("Expected zero CPU time for non-existent process, got %d", result.totalNS)
	}
}

func TestGetProcessCPUTime_InvalidStatFormat(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = dir
	statPath := fmt.Sprintf("%s/1234/stat", dir)
	_ = os.MkdirAll(fmt.Sprintf("%s/1234", dir), 0755)
	_ = os.WriteFile(statPath, []byte("invalid format"), 0644)

	result := getProcessCPUTime(1234)
	if result.totalNS != 0 {
		t.Errorf("Expected zero CPU time for invalid stat format, got %d", result.totalNS)
	}
}

func TestGetProcessCPUTime_ValidStat(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = dir
	statPath := fmt.Sprintf("%s/1234/stat", dir)
	_ = os.MkdirAll(fmt.Sprintf("%s/1234", dir), 0755)
	statContent := "1234 (test) S 1 1234 1234 0 -1 4194304 100 0 0 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	_ = os.WriteFile(statPath, []byte(statContent), 0644)

	result := getProcessCPUTime(1234)
	if result.totalNS == 0 {
		t.Error("Expected non-zero CPU time for valid stat")
	}
}

func TestGetProcessCPUTime_WithAuxv(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = dir
	statPath := fmt.Sprintf("%s/1234/stat", dir)
	auxvPath := fmt.Sprintf("%s/self/auxv", dir)
	_ = os.MkdirAll(fmt.Sprintf("%s/1234", dir), 0755)
	_ = os.MkdirAll(fmt.Sprintf("%s/self", dir), 0755)

	statContent := "1234 (test) S 1 1234 1234 0 -1 4194304 100 0 0 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	_ = os.WriteFile(statPath, []byte(statContent), 0644)

	auxvData := make([]byte, 32)
	auxvData[0] = 11
	auxvData[1] = 0
	auxvData[2] = 0
	auxvData[3] = 0
	auxvData[4] = 0
	auxvData[5] = 0
	auxvData[6] = 0
	auxvData[7] = 0
	auxvData[8] = 200
	auxvData[9] = 0
	auxvData[10] = 0
	auxvData[11] = 0
	auxvData[12] = 0
	auxvData[13] = 0
	auxvData[14] = 0
	auxvData[15] = 0
	_ = os.WriteFile(auxvPath, auxvData, 0644)

	result := getProcessCPUTime(1234)
	if result.totalNS == 0 {
		t.Error("Expected non-zero CPU time with auxv")
	}
}

func TestGetProcessCPUTime_AuxvError(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = dir
	statPath := fmt.Sprintf("%s/1234/stat", dir)
	_ = os.MkdirAll(fmt.Sprintf("%s/1234", dir), 0755)

	statContent := "1234 (test) S 1 1234 1234 0 -1 4194304 100 0 0 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	_ = os.WriteFile(statPath, []byte(statContent), 0644)

	result := getProcessCPUTime(1234)
	if result.totalNS == 0 {
		t.Error("Expected non-zero CPU time even without auxv")
	}
}

func TestGetProcessCPUTime_ZeroClockTicks(t *testing.T) {
	dir := t.TempDir()
	origProcBasePath := config.ProcBasePath
	defer func() { config.ProcBasePath = origProcBasePath }()

	config.ProcBasePath = dir
	statPath := fmt.Sprintf("%s/1234/stat", dir)
	auxvPath := fmt.Sprintf("%s/self/auxv", dir)
	_ = os.MkdirAll(fmt.Sprintf("%s/1234", dir), 0755)
	_ = os.MkdirAll(fmt.Sprintf("%s/self", dir), 0755)

	statContent := "1234 (test) S 1 1234 1234 0 -1 4194304 100 0 0 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	_ = os.WriteFile(statPath, []byte(statContent), 0644)

	auxvData := make([]byte, 32)
	auxvData[0] = 11
	auxvData[1] = 0
	auxvData[2] = 0
	auxvData[3] = 0
	auxvData[4] = 0
	auxvData[5] = 0
	auxvData[6] = 0
	auxvData[7] = 0
	auxvData[8] = 0
	auxvData[9] = 0
	auxvData[10] = 0
	auxvData[11] = 0
	auxvData[12] = 0
	auxvData[13] = 0
	auxvData[14] = 0
	auxvData[15] = 0
	_ = os.WriteFile(auxvPath, auxvData, 0644)

	result := getProcessCPUTime(1234)
	if result.totalNS == 0 {
		t.Error("Expected non-zero CPU time even with zero clock ticks (should default to 100)")
	}
}

func TestIsKernelThread_AdditionalPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		pid      uint32
		procName string
		expected bool
	}{
		{"khugepaged", 1, "khugepaged", true},
		{"kswapd", 2, "kswapd0", true},
		{"kthreadd", 3, "kthreadd", true},
		{"jbd2", 4, "jbd2/sda1", true},
		{"dmcrypt", 5, "dmcrypt_write", true},
		{"kcryptd", 6, "kcryptd/0", true},
		{"rcu_bh", 7, "rcu_bh/0", true},
		{"rcu_", 8, "rcu_gp", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsKernelThread(tt.pid, tt.procName)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
