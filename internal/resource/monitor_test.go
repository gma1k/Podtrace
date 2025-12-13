package resource

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestNewResourceMonitor(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")

	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	if monitor == nil {
		t.Fatal("NewResourceMonitor() returned nil")
	}

	if monitor.cgroupPath != cgroupPath {
		t.Errorf("Expected cgroupPath %s, got %s", cgroupPath, monitor.cgroupPath)
	}

	if monitor.namespace != "test-ns" {
		t.Errorf("Expected namespace 'test-ns', got %s", monitor.namespace)
	}

	if monitor.checkInterval != 5*time.Second {
		t.Errorf("Expected checkInterval 5s, got %v", monitor.checkInterval)
	}
}

func TestResourceMonitor_GetLimits(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")

	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits == nil {
		t.Fatal("GetLimits() returned nil")
	}

	if len(limits) != 0 {
		t.Errorf("Expected empty limits, got %d", len(limits))
	}
}

func TestResourceMonitor_StartStop(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")

	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	monitor.Start(ctx)

	time.Sleep(10 * time.Millisecond)

	cancel()
	monitor.Stop()
}

func TestGetCgroupInode(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")

	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	inode, err := getCgroupInode(cgroupPath)
	if err != nil {
		t.Fatalf("getCgroupInode() error = %v", err)
	}

	if inode == 0 {
		t.Error("getCgroupInode() returned 0")
	}
}

func TestGetCgroupInode_NonExistent(t *testing.T) {
	_, err := getCgroupInode("/nonexistent/path")
	if err == nil {
		t.Error("Expected error for non-existent path")
	}
}

func TestIsCgroupV2(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(string) error
		expectedV2  bool
		expectError bool
	}{
		{
			name: "cgroup v2 with controllers file",
			setup: func(path string) error {
				controllersFile := filepath.Join(path, "cgroup.controllers")
				return os.WriteFile(controllersFile, []byte("cpu memory io"), 0644)
			},
			expectedV2:  true,
			expectError: false,
		},
		{
			name: "cgroup v1 with cpu subdirectory",
			setup: func(path string) error {
				cpuDir := filepath.Join(path, "cpu")
				return os.MkdirAll(cpuDir, 0755)
			},
			expectedV2:  false,
			expectError: false,
		},
		{
			name: "cgroup v1 with memory subdirectory",
			setup: func(path string) error {
				memDir := filepath.Join(path, "memory")
				return os.MkdirAll(memDir, 0755)
			},
			expectedV2:  false,
			expectError: false,
		},
		{
			name: "neither v1 nor v2",
			setup: func(path string) error {
				return nil
			},
			expectedV2:  false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cgroupPath := filepath.Join(tmpDir, "test-cgroup")

			if err := os.MkdirAll(cgroupPath, 0755); err != nil {
				t.Fatalf("Failed to create test cgroup dir: %v", err)
			}

			if err := tt.setup(cgroupPath); err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			isV2, err := isCgroupV2(cgroupPath)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if isV2 != tt.expectedV2 {
					t.Errorf("Expected isV2=%v, got %v", tt.expectedV2, isV2)
				}
			}
		})
	}
}

func TestParseCPUMax(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantQuota     uint64
		wantPeriod    uint64
		wantUnlimited bool
	}{
		{"unlimited", "max", 0, 0, true},
		{"quota only", "100000", 100000, 100000, false},
		{"quota and period", "100000 100000", 100000, 100000, false},
		{"empty", "", 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quota, period, unlimited := parseCPUMax(tt.input)
			if unlimited != tt.wantUnlimited {
				t.Errorf("parseCPUMax() unlimited = %v, want %v", unlimited, tt.wantUnlimited)
			}
			if !tt.wantUnlimited {
				if quota != tt.wantQuota {
					t.Errorf("parseCPUMax() quota = %v, want %v", quota, tt.wantQuota)
				}
				if period != tt.wantPeriod && tt.wantPeriod != 0 {
					t.Errorf("parseCPUMax() period = %v, want %v", period, tt.wantPeriod)
				}
			}
		})
	}
}

func TestParseMemoryMax(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  uint64
	}{
		{"unlimited", "max", ^uint64(0)},
		{"bytes", "1073741824", 1073741824},
		{"zero", "0", 0},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMemoryMax(tt.input)
			if got != tt.want {
				t.Errorf("parseMemoryMax() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseIOMax(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  uint64
	}{
		{"read and write", "8:0 rbps=1048576 wbps=2097152", 2097152},
		{"read only", "8:0 rbps=1048576", 1048576},
		{"write only", "8:0 wbps=2097152", 2097152},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIOMax(tt.input)
			if got != tt.want {
				t.Errorf("parseIOMax() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCPUStat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  uint64
	}{
		{"with usage_usec", "usage_usec 12345", 12345},
		{"multiple lines", "nr_periods 10\nusage_usec 54321\nnr_throttled 2", 54321},
		{"no usage_usec", "nr_periods 10", 0},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCPUStat(tt.input)
			if got != tt.want {
				t.Errorf("parseCPUStat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseIOStat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  uint64
	}{
		{"read and write", "8:0 rbytes=1048576 wbytes=2097152", 3145728},
		{"read only", "8:0 rbytes=1048576", 1048576},
		{"write only", "8:0 wbytes=2097152", 2097152},
		{"multiple devices", "8:0 rbytes=1048576 wbytes=2097152\n8:16 rbytes=512000 wbytes=1024000", 4681728},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIOStat(tt.input)
			if got != tt.want {
				t.Errorf("parseIOStat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadCgroupFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-file")
	content := "test content\n"

	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	got, err := readCgroupFile(testFile)
	if err != nil {
		t.Fatalf("readCgroupFile() error = %v", err)
	}

	expected := "test content"
	if got != expected {
		t.Errorf("readCgroupFile() = %q, want %q", got, expected)
	}
}

func TestReadCgroupFile_NonExistent(t *testing.T) {
	_, err := readCgroupFile("/nonexistent/file")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestParseIOV1(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  uint64
	}{
		{"single line", "8:0 Read 1048576", 1048576},
		{"multiple lines", "8:0 Read 1048576\n8:0 Write 2097152", 3145728},
		{"invalid format", "invalid line", 0},
		{"empty", "", 0},
		{"missing value", "8:0 Read", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIOV1(tt.input)
			if got != tt.want {
				t.Errorf("parseIOV1() = %v, want %v", got, tt.want)
			}
		})
	}
}


func TestResourceMonitor_ReadLimitsV2(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory io"), 0644)

	tests := []struct {
		name     string
		setup    func() error
		wantCPU  bool
		wantMem  bool
		wantIO   bool
	}{
		{
			name: "all limits",
			setup: func() error {
				_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)
				_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644)
				_ = os.WriteFile(filepath.Join(cgroupPath, "io.max"), []byte("8:0 rbps=1048576 wbps=2097152"), 0644)
				return nil
			},
			wantCPU: true,
			wantMem: true,
			wantIO:  true,
		},
		{
			name: "unlimited cpu",
			setup: func() error {
				_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("max"), 0644)
				_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644)
				return nil
			},
			wantCPU: false,
			wantMem: true,
			wantIO:  false,
		},
		{
			name: "unlimited memory",
			setup: func() error {
				_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)
				_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("max"), 0644)
				return nil
			},
			wantCPU: true,
			wantMem: false,
			wantIO:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Remove(filepath.Join(cgroupPath, "io.max"))
			if err := tt.setup(); err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			eventChan := make(chan *events.Event, 10)
			monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
			if err != nil {
				t.Fatalf("NewResourceMonitor() error = %v", err)
			}

			limits := monitor.GetLimits()
			if tt.wantCPU && limits[ResourceCPU] == nil {
				t.Error("Expected CPU limit but got none")
			}
			if !tt.wantCPU && limits[ResourceCPU] != nil {
				t.Error("Expected no CPU limit but got one")
			}
			if tt.wantMem && limits[ResourceMemory] == nil {
				t.Error("Expected memory limit but got none")
			}
			if !tt.wantMem && limits[ResourceMemory] != nil {
				t.Error("Expected no memory limit but got one")
			}
			if tt.wantIO && limits[ResourceIO] == nil {
				t.Error("Expected IO limit but got none")
			}
			if !tt.wantIO && limits[ResourceIO] != nil {
				t.Error("Expected no IO limit but got one")
			}
		})
	}
}

func TestResourceMonitor_ReadLimitsV1(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpu"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "memory"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "blkio"), 0755)

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_quota_us"), []byte("100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_period_us"), []byte("100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory", "memory.limit_in_bytes"), []byte("1073741824"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "blkio", "blkio.throttle.read_bps_device"), []byte("8:0 Read 1048576"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceCPU] == nil {
		t.Error("Expected CPU limit but got none")
	}
	if limits[ResourceMemory] == nil {
		t.Error("Expected memory limit but got none")
	}
	if limits[ResourceIO] == nil {
		t.Error("Expected IO limit but got none")
	}
}

func TestResourceMonitor_SyncToBPF_NilMap(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	err = monitor.syncToBPF()
	if err != nil {
		t.Errorf("syncToBPF() with nil map should not error, got: %v", err)
	}
}

func TestResourceMonitor_UpdateUsageV2(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory io"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "io.max"), []byte("8:0 rbps=1048576"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.stat"), []byte("usage_usec 50000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.current"), []byte("536870912"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "io.stat"), []byte("8:0 rbytes=524288 wbytes=262144"), 0644)

	err = monitor.updateUsageV2()
	if err != nil {
		t.Errorf("updateUsageV2() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceCPU] != nil && limits[ResourceCPU].UsageBytes == 0 {
		t.Error("Expected CPU usage to be updated")
	}
	if limits[ResourceMemory] != nil && limits[ResourceMemory].UsageBytes == 0 {
		t.Error("Expected memory usage to be updated")
	}
	if limits[ResourceIO] != nil && limits[ResourceIO].UsageBytes == 0 {
		t.Error("Expected IO usage to be updated")
	}
}

func TestResourceMonitor_UpdateUsageV1(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpu"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpuacct"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "memory"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "blkio"), 0755)

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_quota_us"), []byte("100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_period_us"), []byte("100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory", "memory.limit_in_bytes"), []byte("1073741824"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpuacct", "cpuacct.usage"), []byte("50000000000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory", "memory.usage_in_bytes"), []byte("536870912"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "blkio", "blkio.io_service_bytes"), []byte("8:0 Read 524288"), 0644)

	err = monitor.updateUsageV1()
	if err != nil {
		t.Errorf("updateUsageV1() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceCPU] != nil && limits[ResourceCPU].UsageBytes == 0 {
		t.Error("Expected CPU usage to be updated")
	}
	if limits[ResourceMemory] != nil && limits[ResourceMemory].UsageBytes == 0 {
		t.Error("Expected memory usage to be updated")
	}
}

func TestResourceMonitor_CheckAlerts_WithNilAlertsMap(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1000000"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	monitor.mu.Lock()
	monitor.limits[ResourceCPU] = &ResourceLimit{
		LimitBytes:   100000,
		UsageBytes:  96000,
		ResourceType: ResourceCPU,
	}
	monitor.mu.Unlock()

	monitor.checkAlerts()

	select {
	case <-eventChan:
		t.Error("Expected no event when alertsMap is nil (function returns early)")
	default:
	}
}

func TestResourceMonitor_CheckAlerts_UtilizationLevels(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	tests := []struct {
		name           string
		limitBytes     uint64
		usageBytes     uint64
		expectedEvents int
	}{
		{"low utilization", 100000, 50000, 0},
		{"warning level", 100000, 85000, 0},
		{"critical level", 100000, 92000, 0},
		{"emergency level", 100000, 97000, 0},
		{"over 100%", 100000, 150000, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			monitor.mu.Lock()
			monitor.limits[ResourceCPU] = &ResourceLimit{
				LimitBytes:   tt.limitBytes,
				UsageBytes:   tt.usageBytes,
				ResourceType: ResourceCPU,
			}
			monitor.mu.Unlock()

			monitor.checkAlerts()

			eventCount := 0
			for {
				select {
				case <-eventChan:
					eventCount++
				default:
					if eventCount != tt.expectedEvents {
						t.Errorf("Expected %d events, got %d (alertsMap is nil so function returns early)", tt.expectedEvents, eventCount)
					}
					return
				}
			}
		})
	}
}

func TestResourceMonitor_CheckAlerts_ZeroLimit(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	monitor.mu.Lock()
	monitor.limits[ResourceCPU] = &ResourceLimit{
		LimitBytes:   0,
		UsageBytes:  100000,
		ResourceType: ResourceCPU,
	}
	monitor.mu.Unlock()

	monitor.checkAlerts()

	select {
	case <-eventChan:
		t.Error("Expected no event for zero limit")
	default:
	}
}

func TestResourceMonitor_MonitorLoop_ContextCancel(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	monitor.Start(ctx)

	time.Sleep(50 * time.Millisecond)

	cancel()
	monitor.Stop()
}

func TestResourceMonitor_MonitorLoop_StopChannel(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	ctx := context.Background()
	monitor.Start(ctx)

	time.Sleep(50 * time.Millisecond)

	monitor.Stop()
}

func TestResourceMonitor_ReadLimits_ErrorPath(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	err = monitor.readLimits()
	if err == nil {
		t.Error("Expected error when cgroup version cannot be determined")
	}
}

func TestResourceMonitor_UpdateResourceUsage_ErrorPath(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	err = monitor.updateResourceUsage()
	if err == nil {
		t.Error("Expected error when cgroup version cannot be determined")
	}
}

func TestResourceMonitor_ReadLimitsV2_ErrorReadingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory io"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	err = monitor.readLimitsV2()
	if err != nil {
		t.Logf("readLimitsV2() returned error (expected when files don't exist): %v", err)
	}
}

func TestResourceMonitor_ReadLimitsV1_ErrorReadingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpu"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "memory"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "blkio"), 0755)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	err = monitor.readLimitsV1()
	if err != nil {
		t.Logf("readLimitsV1() returned error (expected when files don't exist): %v", err)
	}
}

func TestResourceMonitor_UpdateUsageV2_ErrorReadingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory io"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	err = monitor.updateUsageV2()
	if err != nil {
		t.Logf("updateUsageV2() returned error (expected when stat files don't exist): %v", err)
	}
}

func TestResourceMonitor_UpdateUsageV1_ErrorReadingFiles(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpu"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpuacct"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "memory"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "blkio"), 0755)

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_quota_us"), []byte("100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_period_us"), []byte("100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory", "memory.limit_in_bytes"), []byte("1073741824"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	err = monitor.updateUsageV1()
	if err != nil {
		t.Logf("updateUsageV1() returned error (expected when stat files don't exist): %v", err)
	}
}

func TestResourceMonitor_UpdateUsageV1_WithLimits(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpu"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpuacct"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "memory"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "blkio"), 0755)

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_quota_us"), []byte("100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_period_us"), []byte("100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory", "memory.limit_in_bytes"), []byte("1073741824"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpuacct", "cpuacct.usage"), []byte("50000000000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory", "memory.usage_in_bytes"), []byte("536870912"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "blkio", "blkio.io_service_bytes"), []byte("8:0 Read 524288\n8:0 Write 262144"), 0644)

	monitor.mu.Lock()
	monitor.limits[ResourceCPU] = &ResourceLimit{
		LimitBytes:   100000,
		ResourceType: ResourceCPU,
	}
	monitor.limits[ResourceMemory] = &ResourceLimit{
		LimitBytes:   1073741824,
		ResourceType: ResourceMemory,
	}
	monitor.limits[ResourceIO] = &ResourceLimit{
		LimitBytes:   1048576,
		ResourceType: ResourceIO,
	}
	monitor.mu.Unlock()

	err = monitor.updateUsageV1()
	if err != nil {
		t.Errorf("updateUsageV1() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceCPU] != nil && limits[ResourceCPU].UsageBytes == 0 {
		t.Error("Expected CPU usage to be updated")
	}
	if limits[ResourceMemory] != nil && limits[ResourceMemory].UsageBytes == 0 {
		t.Error("Expected memory usage to be updated")
	}
	if limits[ResourceIO] != nil && limits[ResourceIO].UsageBytes == 0 {
		t.Error("Expected IO usage to be updated")
	}
}

func TestResourceMonitor_UpdateUsageV2_WithLimits(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory io"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "io.max"), []byte("8:0 rbps=1048576"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.stat"), []byte("usage_usec 50000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.current"), []byte("536870912"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "io.stat"), []byte("8:0 rbytes=524288 wbytes=262144"), 0644)

	monitor.mu.Lock()
	monitor.limits[ResourceCPU] = &ResourceLimit{
		LimitBytes:   100000,
		ResourceType: ResourceCPU,
	}
	monitor.limits[ResourceMemory] = &ResourceLimit{
		LimitBytes:   1073741824,
		ResourceType: ResourceMemory,
	}
	monitor.limits[ResourceIO] = &ResourceLimit{
		LimitBytes:   1048576,
		ResourceType: ResourceIO,
	}
	monitor.mu.Unlock()

	err = monitor.updateUsageV2()
	if err != nil {
		t.Errorf("updateUsageV2() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceCPU] != nil && limits[ResourceCPU].UsageBytes == 0 {
		t.Error("Expected CPU usage to be updated")
	}
	if limits[ResourceMemory] != nil && limits[ResourceMemory].UsageBytes == 0 {
		t.Error("Expected memory usage to be updated")
	}
	if limits[ResourceIO] != nil && limits[ResourceIO].UsageBytes == 0 {
		t.Error("Expected IO usage to be updated")
	}
}

func TestResourceMonitor_UpdateUsageV2_NoLimits(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory io"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.stat"), []byte("usage_usec 50000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.current"), []byte("536870912"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "io.stat"), []byte("8:0 rbytes=524288"), 0644)

	err = monitor.updateUsageV2()
	if err != nil {
		t.Errorf("updateUsageV2() error = %v", err)
	}
}

func TestResourceMonitor_UpdateUsageV1_NoLimits(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpu"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpuacct"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "memory"), 0755)
	_ = os.MkdirAll(filepath.Join(cgroupPath, "blkio"), 0755)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpuacct", "cpuacct.usage"), []byte("50000000000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory", "memory.usage_in_bytes"), []byte("536870912"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "blkio", "blkio.io_service_bytes"), []byte("8:0 Read 524288"), 0644)

	err = monitor.updateUsageV1()
	if err != nil {
		t.Errorf("updateUsageV1() error = %v", err)
	}
}

func TestResourceMonitor_ReadLimitsV2_UnlimitedCPU(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("max"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceCPU] != nil {
		t.Error("Expected no CPU limit for unlimited")
	}
	if limits[ResourceMemory] == nil {
		t.Error("Expected memory limit")
	}
}

func TestResourceMonitor_ReadLimitsV2_ZeroCPUQuota(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("0 100000"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceCPU] != nil {
		t.Error("Expected no CPU limit for zero quota")
	}
}

func TestResourceMonitor_ReadLimitsV1_ZeroQuota(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpu"), 0755)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_quota_us"), []byte("0"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_period_us"), []byte("100000"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceCPU] != nil {
		t.Error("Expected no CPU limit for zero quota")
	}
}

func TestResourceMonitor_ReadLimitsV1_MissingPeriod(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpu"), 0755)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_quota_us"), []byte("100000"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceCPU] != nil {
		t.Error("Expected no CPU limit when period is missing")
	}
}

func TestResourceMonitor_ReadLimitsV1_ZeroPeriod(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "cpu"), 0755)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_quota_us"), []byte("100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu", "cpu.cfs_period_us"), []byte("0"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceCPU] != nil {
		t.Error("Expected no CPU limit for zero period")
	}
}

func TestResourceMonitor_ReadLimitsV1_ZeroMemoryLimit(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "memory"), 0755)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory", "memory.limit_in_bytes"), []byte("0"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceMemory] != nil {
		t.Error("Expected no memory limit for zero limit")
	}
}

func TestResourceMonitor_ReadLimitsV2_ZeroMemoryLimit(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("memory"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("0"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceMemory] != nil {
		t.Error("Expected no memory limit for zero limit")
	}
}

func TestResourceMonitor_ReadLimitsV2_UnlimitedMemory(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("memory"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("max"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceMemory] != nil {
		t.Error("Expected no memory limit for unlimited")
	}
}

func TestResourceMonitor_ReadLimitsV2_ZeroIOMax(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("io"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "io.max"), []byte("8:0 rbps=0 wbps=0"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceIO] != nil {
		t.Error("Expected no IO limit for zero max")
	}
}

func TestResourceMonitor_ReadLimitsV1_ZeroIO(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(cgroupPath, "blkio"), 0755)
	_ = os.WriteFile(filepath.Join(cgroupPath, "blkio", "blkio.throttle.read_bps_device"), []byte("8:0 Read 0"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if limits[ResourceIO] != nil {
		t.Error("Expected no IO limit for zero value")
	}
}

func TestResourceMonitor_CheckAlerts_Over100Percent(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	monitor.mu.Lock()
	monitor.limits[ResourceCPU] = &ResourceLimit{
		LimitBytes:   100000,
		UsageBytes:  150000,
		ResourceType: ResourceCPU,
	}
	monitor.mu.Unlock()

	monitor.checkAlerts()

	select {
	case <-eventChan:
		t.Error("Expected no event when alertsMap is nil")
	default:
	}
}

func TestResourceMonitor_CheckAlerts_UnknownResourceType(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	monitor.mu.Lock()
	monitor.limits[99] = &ResourceLimit{
		LimitBytes:   100000,
		UsageBytes:  95000,
		ResourceType: 99,
	}
	monitor.mu.Unlock()

	monitor.checkAlerts()

	select {
	case <-eventChan:
		t.Error("Expected no event when alertsMap is nil")
	default:
	}
}

func TestReadCgroupFile_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty-file")

	if err := os.WriteFile(testFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result, err := readCgroupFile(testFile)
	if err == nil {
		if result != "" {
			t.Errorf("Expected empty string for empty file, got %q", result)
		}
	}
}

func TestParseCPUMax_DefaultPeriod(t *testing.T) {
	quota, period, unlimited := parseCPUMax("100000")
	if unlimited {
		t.Error("Expected not unlimited")
	}
	if quota != 100000 {
		t.Errorf("Expected quota 100000, got %d", quota)
	}
	if period != 100000 {
		t.Errorf("Expected default period 100000, got %d", period)
	}
}

func TestParseCPUMax_Whitespace(t *testing.T) {
	quota, period, unlimited := parseCPUMax("  100000  200000  ")
	if unlimited {
		t.Error("Expected not unlimited")
	}
	if quota != 100000 {
		t.Errorf("Expected quota 100000, got %d", quota)
	}
	if period != 200000 {
		t.Errorf("Expected period 200000, got %d", period)
	}
}

func TestParseMemoryMax_Whitespace(t *testing.T) {
	got := parseMemoryMax("  1073741824  ")
	if got != 1073741824 {
		t.Errorf("Expected 1073741824, got %d", got)
	}
}

func TestParseIOMax_MultipleDevices(t *testing.T) {
	input := "8:0 rbps=1048576 wbps=2097152 8:16 rbps=524288 wbps=1048576"
	got := parseIOMax(input)
	if got != 2097152 {
		t.Errorf("Expected 2097152 (max of all), got %d", got)
	}
}

func TestParseIOV1_MultipleFormats(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  uint64
	}{
		{"standard format", "8:0 Read 1048576", 1048576},
		{"with write", "8:0 Read 1048576\n8:0 Write 2097152", 3145728},
		{"multiple devices", "8:0 Read 1048576\n8:16 Read 524288", 1572864},
		{"invalid numbers", "8:0 Read invalid", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIOV1(tt.input)
			if got != tt.want {
				t.Errorf("parseIOV1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseIOStat_MultipleDevices(t *testing.T) {
	input := "8:0 rbytes=1048576 wbytes=2097152\n8:16 rbytes=524288 wbytes=1048576"
	got := parseIOStat(input)
	expected := uint64(1048576 + 2097152 + 524288 + 1048576)
	if got != expected {
		t.Errorf("Expected %d, got %d", expected, got)
	}
}

func TestParseCPUStat_NoUsageUsec(t *testing.T) {
	input := "nr_periods 10\nnr_throttled 2"
	got := parseCPUStat(input)
	if got != 0 {
		t.Errorf("Expected 0 when usage_usec not present, got %d", got)
	}
}

func TestResourceMonitor_MonitorLoop_Ticker(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	monitor.checkInterval = 10 * time.Millisecond

	ctx := context.Background()
	monitor.Start(ctx)

	time.Sleep(30 * time.Millisecond)

	monitor.Stop()
}

func TestResourceMonitor_NewResourceMonitor_ErrorGettingInode(t *testing.T) {
	_, err := NewResourceMonitor("/nonexistent/path", nil, nil, nil, "test-ns")
	if err == nil {
		t.Error("Expected error when cgroup path doesn't exist")
	}
}

func TestReadCgroupFile_ScannerError(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-file")

	file, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	_ = file.Close()

	_ = os.Chmod(testFile, 0000)
	defer func() { _ = os.Chmod(testFile, 0644) }()

	_, err = readCgroupFile(testFile)
	if err == nil {
		t.Error("Expected error when file cannot be read")
	}
}

func TestResourceMonitor_GetLimits_Copy(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits1 := monitor.GetLimits()
	limits2 := monitor.GetLimits()

	if len(limits1) != len(limits2) {
		t.Errorf("Expected same number of limits, got %d and %d", len(limits1), len(limits2))
	}

	for k, v1 := range limits1 {
		v2, ok := limits2[k]
		if !ok {
			t.Errorf("Expected limit for resource type %d in second call", k)
			continue
		}
		if v1 == v2 {
			t.Error("Expected different pointer (copy), got same pointer")
		}
		if v1.LimitBytes != v2.LimitBytes {
			t.Errorf("Expected same LimitBytes, got %d and %d", v1.LimitBytes, v2.LimitBytes)
		}
	}
}

func TestResourceMonitor_CheckAlerts_NoAlerts(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	monitor.mu.Lock()
	monitor.limits[ResourceCPU] = &ResourceLimit{
		LimitBytes:   100000,
		UsageBytes:  50000,
		ResourceType: ResourceCPU,
	}
	monitor.mu.Unlock()

	monitor.checkAlerts()

	select {
	case <-eventChan:
		t.Error("Expected no event for low utilization")
	default:
	}
}

func TestResourceMonitor_CheckAlerts_Unlimited(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	monitor.mu.Lock()
	monitor.limits[ResourceCPU] = &ResourceLimit{
		LimitBytes:   ^uint64(0),
		UsageBytes:  100000,
		ResourceType: ResourceCPU,
	}
	monitor.mu.Unlock()

	monitor.checkAlerts()

	select {
	case <-eventChan:
		t.Error("Expected no event for unlimited resources")
	default:
	}
}

func TestResourceMonitor_CheckAlerts_NoAlertsMap_Nil(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	monitor.mu.Lock()
	monitor.limits[ResourceCPU] = &ResourceLimit{
		LimitBytes:   100000,
		UsageBytes:  95000,
		ResourceType: ResourceCPU,
	}
	monitor.mu.Unlock()

	monitor.checkAlerts()
}

func TestResourceMonitor_CheckAlerts_ChannelFull_Blocked(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	eventChan := make(chan *events.Event, 1)
	eventChan <- &events.Event{}

	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	monitor.mu.Lock()
	monitor.limits[ResourceCPU] = &ResourceLimit{
		LimitBytes:   100000,
		UsageBytes:  95000,
		ResourceType: ResourceCPU,
	}
	monitor.mu.Unlock()

	monitor.checkAlerts()
}

func TestResourceMonitor_UpdateResourceUsage(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.stat"), []byte("usage_usec 50000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.current"), []byte("536870912"), 0644)

	err = monitor.updateResourceUsage()
	if err != nil {
		t.Errorf("updateResourceUsage() error = %v", err)
	}
}

func TestResourceMonitor_GetLimits_WithData(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		t.Fatalf("Failed to create test cgroup dir: %v", err)
	}

	_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.controllers"), []byte("cpu memory"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("100000 100000"), 0644)
	_ = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644)

	eventChan := make(chan *events.Event, 10)
	monitor, err := NewResourceMonitor(cgroupPath, nil, nil, eventChan, "test-ns")
	if err != nil {
		t.Fatalf("NewResourceMonitor() error = %v", err)
	}

	limits := monitor.GetLimits()
	if len(limits) == 0 {
		t.Error("Expected limits to be populated")
	}

	for resourceType, limit := range limits {
		if limit.ResourceType != resourceType {
			t.Errorf("ResourceType mismatch: expected %d, got %d", resourceType, limit.ResourceType)
		}
		if limit.LimitBytes == 0 {
			t.Errorf("Expected non-zero limit for resource type %d", resourceType)
		}
	}
}
