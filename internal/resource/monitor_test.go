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
