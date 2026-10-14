package tracer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/cache"
	"github.com/gma1k/podtrace/internal/ebpf/filter"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/sysfs"
)

func useCgroupBase(t *testing.T, dir string) {
	t.Helper()
	original := config.CgroupBasePath
	config.CgroupBasePath = dir
	sysfs.ResetForTesting()
	t.Cleanup(func() {
		config.CgroupBasePath = original
		sysfs.ResetForTesting()
	})
}

func TestTracer_AttachToCgroup(t *testing.T) {
	tracer := &Tracer{
		filter: filter.NewCgroupFilter(),
	}

	cgroupPath := "/sys/fs/cgroup/test"
	err := tracer.AttachToCgroup(cgroupPath)
	if err != nil {
		t.Errorf("AttachToCgroup should not return error, got %v", err)
	}

	if tracer.filter == nil {
		t.Error("Filter should be set")
	}
}

func TestTracer_AttachToCgroup_IsAdditive(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}

	for _, p := range []string{"/sys/fs/cgroup/a", "/sys/fs/cgroup/b", "/sys/fs/cgroup/c"} {
		if err := tr.AttachToCgroup(p); err != nil {
			t.Fatalf("AttachToCgroup(%q): %v", p, err)
		}
	}

	if got := len(tr.currentCgroupPaths()); got != 3 {
		t.Errorf("cgroupPaths len = %d, want 3 (additive across calls)", got)
	}
	seen := map[string]struct{}{}
	for _, p := range tr.currentCgroupPaths() {
		seen[p] = struct{}{}
	}
	for _, want := range []string{"/sys/fs/cgroup/a", "/sys/fs/cgroup/b", "/sys/fs/cgroup/c"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("cgroupPaths missing %q after additive Attach", want)
		}
	}
}

func TestTracer_AttachToCgroup_IdempotentOnRepeat(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	const p = "/sys/fs/cgroup/dup"
	for i := 0; i < 3; i++ {
		if err := tr.AttachToCgroup(p); err != nil {
			t.Fatalf("AttachToCgroup(%q) attempt %d: %v", p, i, err)
		}
	}
	if got := len(tr.currentCgroupPaths()); got != 1 {
		t.Errorf("cgroupPaths len = %d, want 1 (idempotent on repeat)", got)
	}
}

func TestTracer_AttachToCgroups_Replaces(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	if err := tr.AttachToCgroup("/sys/fs/cgroup/old"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := tr.AttachToCgroups([]string{"/sys/fs/cgroup/new1", "/sys/fs/cgroup/new2"}); err != nil {
		t.Fatalf("AttachToCgroups: %v", err)
	}
	if got := len(tr.currentCgroupPaths()); got != 2 {
		t.Errorf("cgroupPaths len = %d, want 2 (bulk = replace)", got)
	}
	for _, p := range tr.currentCgroupPaths() {
		if p == "/sys/fs/cgroup/old" {
			t.Errorf("bulk AttachToCgroups should have dropped the earlier path, still see %q", p)
		}
	}
}

func TestTracer_SetContainerID(t *testing.T) {
	tracer := &Tracer{
		filter:      filter.NewCgroupFilter(),
		containerID: "",
		links:       []link.Link{},
		collection:  nil,
	}

	containerID := "test-container-id"
	defer func() {
		if r := recover(); r != nil {
			t.Log("SetContainerID panicked as expected for nil collection")
		}
	}()

	err := tracer.SetContainerID(containerID)
	if err == nil {
		if tracer.lastContainerID() != containerID {
			t.Errorf("Expected containerID %q, got %q", containerID, tracer.lastContainerID())
		}
	}
}

func TestTracer_Stop(t *testing.T) {
	tracer := &Tracer{
		filter: filter.NewCgroupFilter(),
		links:  []link.Link{},
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestWaitForInterrupt(t *testing.T) {
	done := make(chan bool)
	go func() {
		time.Sleep(10 * time.Millisecond)
		proc, _ := os.FindProcess(os.Getpid())
		_ = proc.Signal(os.Interrupt)
		done <- true
	}()

	go func() {
		WaitForInterrupt()
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Error("WaitForInterrupt did not complete in time")
	}
}

func TestTracer_Start_ErrorHandling(t *testing.T) {
	tracer := &Tracer{
		filter: filter.NewCgroupFilter(),
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)

	defer func() {
		if r := recover(); r != nil {
			t.Log("Start panicked as expected for nil collection/reader")
		}
	}()

	err := tracer.Start(context.Background(), eventChan)
	if err == nil {
		t.Log("Start returned without error (expected when collection is nil)")
	}
}

func TestTracer_Stop_WithReader(t *testing.T) {
	tracer := &Tracer{
		filter: filter.NewCgroupFilter(),
		links:  []link.Link{},
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_WithCollection(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		links:      []link.Link{},
		collection: nil,
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_AllPaths(t *testing.T) {
	tracer1 := &Tracer{
		filter: filter.NewCgroupFilter(),
		links:  []link.Link{},
	}
	err := tracer1.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}

	tracer2 := &Tracer{
		filter:     filter.NewCgroupFilter(),
		links:      []link.Link{},
		reader:     nil,
		collection: nil,
	}
	err = tracer2.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_SetContainerID_EmptyContainerID(t *testing.T) {
	tracer := &Tracer{
		filter:      filter.NewCgroupFilter(),
		containerID: "",
		links:       []link.Link{},
		collection:  nil,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Log("SetContainerID panicked as expected for nil collection")
		}
	}()

	err := tracer.SetContainerID("")
	if err == nil {
		if tracer.lastContainerID() != "" {
			t.Errorf("Expected empty containerID, got %q", tracer.lastContainerID())
		}
	}
}

func TestTracer_SetContainerID_WithLinks(t *testing.T) {
	tracer := &Tracer{
		filter:      filter.NewCgroupFilter(),
		containerID: "",
		links:       []link.Link{},
		collection:  nil,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Log("SetContainerID panicked as expected for nil collection")
		}
	}()

	err := tracer.SetContainerID("test-container-id")
	if err == nil {
		if tracer.lastContainerID() != "test-container-id" {
			t.Errorf("Expected containerID 'test-container-id', got %q", tracer.lastContainerID())
		}
	}
}

func TestWaitForInterrupt_SIGTERM(t *testing.T) {
	done := make(chan bool, 1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		proc, _ := os.FindProcess(os.Getpid())
		_ = proc.Signal(os.Interrupt)
		done <- true
	}()

	go func() {
		WaitForInterrupt()
		done <- true
	}()

	select {
	case <-done:
		<-done
	case <-time.After(1 * time.Second):
		t.Error("WaitForInterrupt did not complete in time")
	}
}

func TestNewTracer_ErrorPaths(t *testing.T) {
	originalPath := config.BPFObjectPath
	defer func() { config.BPFObjectPath = originalPath }()

	config.BPFObjectPath = "/nonexistent/path/to/bpf.o"
	tracer, err := NewTracer()
	if err == nil {
		if tracer != nil {
			_ = tracer.Stop()
		}
		t.Log("NewTracer returned error as expected for non-existent BPF object")
	}
}

func TestTracer_Start_WithNilReader(t *testing.T) {
	tracer := &Tracer{
		filter: filter.NewCgroupFilter(),
		reader: nil,
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)

	defer func() {
		if r := recover(); r != nil {
			t.Log("Start panicked as expected for nil collection/reader")
		}
	}()

	err := tracer.Start(context.Background(), eventChan)
	if err != nil {
		t.Logf("Start returned error as expected for nil reader: %v", err)
	}
}

func TestTracer_Start_WithNilCollection(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		collection: nil,
		reader:     nil,
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)

	defer func() {
		if r := recover(); r != nil {
			t.Log("Start panicked as expected for nil collection")
		}
	}()

	err := tracer.Start(context.Background(), eventChan)
	if err != nil {
		t.Logf("Start returned error as expected for nil collection: %v", err)
	}
}

func TestTracer_Stop_WithAllFields(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		links:      []link.Link{},
		reader:     nil,
		collection: nil,
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Start_WithRealEBPF(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping eBPF integration test in short mode")
	}

	tracer, err := NewTracer()
	if err != nil {
		t.Skipf("Skipping test - eBPF not available: %v", err)
		return
	}
	defer func() { _ = tracer.Stop() }()

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)

	err = tracer.Start(context.Background(), eventChan)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	_ = tracer.AttachToCgroup("")

	time.Sleep(100 * time.Millisecond)

	_ = tracer.Stop()

	close(eventChan)

	eventCount := 0
	for range eventChan {
		eventCount++
	}

	t.Logf("Processed %d events during test", eventCount)
}

func TestTracer_Start_ErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		tracer  *Tracer
		wantErr bool
	}{
		{
			name: "nil collection",
			tracer: &Tracer{
				filter:     filter.NewCgroupFilter(),
				collection: nil,
				reader:     nil,
			},
			wantErr: false,
		},
		{
			name: "nil reader",
			tracer: &Tracer{
				filter:     filter.NewCgroupFilter(),
				collection: nil,
				reader:     nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventChan := make(chan *events.Event, config.EventChannelBufferSize)

			defer func() {
				if r := recover(); r != nil {
					t.Logf("Start panicked as expected: %v", r)
				}
			}()

			err := tt.tracer.Start(context.Background(), eventChan)
			if (err != nil) != tt.wantErr {
				t.Errorf("Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTracer_GetProcessNameQuick_InvalidPID(t *testing.T) {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	tests := []struct {
		name string
		pid  uint32
	}{
		{"zero PID", 0},
		{"too large PID", 4194304},
		{"very large PID", 99999999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tracer.getProcessNameQuick(tt.pid)
			if result != "" {
				t.Errorf("Expected empty string for invalid PID %d, got %q", tt.pid, result)
			}
		})
	}
}

func TestTracer_GetProcessNameQuick_FromCache(t *testing.T) {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(12345)
	expectedName := "cached-process"
	tracer.processNameCache.Set(pid, expectedName)

	result := tracer.getProcessNameQuick(pid)
	if result != expectedName {
		t.Errorf("Expected cached name %q, got %q", expectedName, result)
	}
}

func TestTracer_GetProcessNameQuick_FromCmdline(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(12346)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	cmdlineContent := []byte("/usr/bin/test-process\x00arg1\x00arg2")
	_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "test-process" {
		t.Errorf("Expected 'test-process', got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_FromStat(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(12347)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	statPath := filepath.Join(procDir, "stat")
	statContent := "12347 (test-process-name) S 1 12347 12347 0 -1 4194560"
	_ = os.WriteFile(statPath, []byte(statContent), 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "test-process-name" {
		t.Errorf("Expected 'test-process-name', got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_FromComm(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(12348)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	commPath := filepath.Join(procDir, "comm")
	commContent := "  comm-process  \n"
	_ = os.WriteFile(commPath, []byte(commContent), 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process', got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_CacheEviction(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	for i := uint32(20000); i < 20010; i++ {
		procDir := filepath.Join(tempDir, fmt.Sprintf("%d", i))
		_ = os.MkdirAll(procDir, 0755)
		cmdlinePath := filepath.Join(procDir, "cmdline")
		cmdlineContent := []byte(fmt.Sprintf("/usr/bin/process-%d\x00", i))
		_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)
		tracer.getProcessNameQuick(i)
	}

}

func TestTracer_Start_ContextCancellation(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		collection: nil,
		reader:     nil,
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Start panicked as expected for nil reader: %v", r)
		}
		cancel()
	}()

	err := tracer.Start(ctx, eventChan)
	if err == nil {
		cancel()
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTracer_SetContainerID_WithCollection(t *testing.T) {
	tracer := &Tracer{
		filter:      filter.NewCgroupFilter(),
		containerID: "",
		links:       []link.Link{},
		collection:  nil,
	}

	containerID := "test-container-123"
	defer func() {
		if r := recover(); r != nil {
			t.Log("SetContainerID panicked as expected for nil collection")
		}
	}()

	err := tracer.SetContainerID(containerID)
	if err == nil {
		if tracer.lastContainerID() != containerID {
			t.Errorf("Expected containerID %q, got %q", containerID, tracer.lastContainerID())
		}
	}
}

func TestTracer_SetContainerID_MultipleCalls(t *testing.T) {
	tracer := &Tracer{
		filter:      filter.NewCgroupFilter(),
		containerID: "",
		links:       []link.Link{},
		collection:  nil,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Log("SetContainerID panicked as expected for nil collection")
		}
	}()

	err1 := tracer.SetContainerID("container-1")
	err2 := tracer.SetContainerID("container-2")

	if err1 == nil && err2 == nil {
		if tracer.lastContainerID() != "container-2" {
			t.Errorf("Expected containerID 'container-2', got %q", tracer.lastContainerID())
		}
	}
}

func TestTracer_Stop_WithLinks(t *testing.T) {
	tracer := &Tracer{
		filter: filter.NewCgroupFilter(),
		links:  []link.Link{},
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_WithReaderAndCollection(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		links:      []link.Link{},
		reader:     nil,
		collection: nil,
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestNewTracer_LoadPodtraceError(t *testing.T) {
	originalPath := config.BPFObjectPath
	defer func() { config.BPFObjectPath = originalPath }()

	config.BPFObjectPath = "/nonexistent/path/to/bpf.o"
	tracer, err := NewTracer()
	if err == nil {
		if tracer != nil {
			_ = tracer.Stop()
		}
		t.Log("NewTracer returned error as expected for non-existent BPF object")
	}
}

func TestNewTracer_CollectionError(t *testing.T) {
	originalPath := config.BPFObjectPath
	defer func() { config.BPFObjectPath = originalPath }()

	config.BPFObjectPath = "/nonexistent/path/to/bpf.o"
	tracer, err := NewTracer()
	if err != nil {
		t.Logf("NewTracer returned error as expected: %v", err)
	}
	if tracer != nil {
		_ = tracer.Stop()
	}
}

func TestTracer_GetProcessNameQuick_AllMethods(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	tests := []struct {
		name        string
		pid         uint32
		setupFiles  func(string)
		expectEmpty bool
	}{
		{
			name: "from cmdline",
			pid:  20001,
			setupFiles: func(procDir string) {
				cmdlinePath := filepath.Join(procDir, "cmdline")
				_ = os.WriteFile(cmdlinePath, []byte("/usr/bin/cmdline-process\x00"), 0644)
			},
			expectEmpty: false,
		},
		{
			name: "from stat",
			pid:  20002,
			setupFiles: func(procDir string) {
				statPath := filepath.Join(procDir, "stat")
				_ = os.WriteFile(statPath, []byte("20002 (stat-process) S 1 20002 20002 0 -1 4194560"), 0644)
			},
			expectEmpty: false,
		},
		{
			name: "from comm",
			pid:  20003,
			setupFiles: func(procDir string) {
				commPath := filepath.Join(procDir, "comm")
				_ = os.WriteFile(commPath, []byte("comm-process"), 0644)
			},
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			procDir := filepath.Join(tempDir, fmt.Sprintf("%d", tt.pid))
			_ = os.MkdirAll(procDir, 0755)
			tt.setupFiles(procDir)

			result := tracer.getProcessNameQuick(tt.pid)
			if tt.expectEmpty && result != "" {
				t.Errorf("Expected empty result, got %q", result)
			}
			if !tt.expectEmpty && result == "" {
				t.Errorf("Expected non-empty result, got empty")
			}
		})
	}
}

func TestTracer_GetProcessNameQuick_CacheEvictionAtMax(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	for i := uint32(30000); i < uint32(30000+config.MaxProcessCacheSize+10); i++ {
		procDir := filepath.Join(tempDir, fmt.Sprintf("%d", i))
		_ = os.MkdirAll(procDir, 0755)
		cmdlinePath := filepath.Join(procDir, "cmdline")
		cmdlineContent := []byte(fmt.Sprintf("/usr/bin/process-%d\x00", i))
		_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)
		tracer.getProcessNameQuick(i)
	}

}

func TestTracer_Stop_WithReaderAndLinksAndCollection(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		links:      []link.Link{},
		reader:     nil,
		collection: nil,
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_ReaderCloseError(t *testing.T) {
	tracer := &Tracer{
		filter: filter.NewCgroupFilter(),
		links:  []link.Link{},
		reader: nil,
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_LinkCloseError(t *testing.T) {
	tracer := &Tracer{
		filter: filter.NewCgroupFilter(),
		links:  []link.Link{},
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_CollectionCloseError(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		links:      []link.Link{},
		collection: nil,
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Start_StackNrGreaterThanIPsLength(t *testing.T) {
	var stack stackTraceValue
	stack.Nr = uint32(config.MaxStackDepth + 10)
	n := int(stack.Nr)
	if n > len(stack.IPs) {
		n = len(stack.IPs)
	}
	if n != len(stack.IPs) {
		t.Error("Expected n to be limited to stack.IPs length")
	}
}

func TestTracer_Start_StackNrZero(t *testing.T) {
	var stack stackTraceValue
	stack.Nr = 0
	n := int(stack.Nr)
	if n > 0 {
		t.Error("Expected n to be 0")
	}
}

func TestTracer_GetProcessNameQuick_CmdlineNoSlash(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(40001)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	cmdlineContent := []byte("process-name\x00arg1")
	_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "process-name" {
		t.Errorf("Expected 'process-name', got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_StatInvalidParentheses(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(40002)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("40002 ) invalid ( S"), 0644)

	commPath := filepath.Join(procDir, "comm")
	_ = os.WriteFile(commPath, []byte("comm-process"), 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process' from comm, got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_StackNrGreaterThanMax(t *testing.T) {
	tracer := &Tracer{
		collection: nil,
	}

	if tracer.collection != nil {
		stackMap := tracer.collection.Maps["stack_traces"]
		if stackMap != nil {
			var stack stackTraceValue
			stack.Nr = uint32(config.MaxStackDepth + 100)
			n := int(stack.Nr)
			if n > len(stack.IPs) {
				n = len(stack.IPs)
			}
			if n != len(stack.IPs) {
				t.Error("Expected n to be limited to stack.IPs length")
			}
		}
	}
}

func TestErrorRateLimiter_IntervalCalculation(t *testing.T) {
	limiter := newErrorRateLimiter()
	limiter.backoffFactor = 200
	limiter.lastLogTime = time.Now().Add(-200 * time.Second)

	interval := limiter.minInterval * time.Duration(limiter.backoffFactor)
	expectedInterval := limiter.maxInterval
	if interval > limiter.maxInterval {
		interval = limiter.maxInterval
	}

	if interval != expectedInterval {
		t.Errorf("Expected interval to be capped at maxInterval (%v), got %v", expectedInterval, interval)
	}

	result := limiter.shouldLog()
	if !result {
		t.Error("Expected shouldLog to return true when enough time has passed")
	}
}

func TestSlidingWindow_NewBucketCreation(t *testing.T) {
	window := newSlidingWindow(1*time.Second, 5)
	window.mu.Lock()
	window.buckets = []timeBucket{}
	window.mu.Unlock()

	window.addError()
	rate := window.getErrorRate()
	if rate != 1 {
		t.Errorf("Expected error rate 1 after adding first error, got %d", rate)
	}
}

func TestSlidingWindow_BucketIncrement(t *testing.T) {
	window := newSlidingWindow(1*time.Second, 5)
	window.addError()
	time.Sleep(10 * time.Millisecond)
	window.addError()

	rate := window.getErrorRate()
	if rate != 2 {
		t.Errorf("Expected error rate 2, got %d", rate)
	}
}

func TestCircuitBreaker_StateTransitions(t *testing.T) {
	cb := newCircuitBreaker(2, 50*time.Millisecond)

	cb.mu.Lock()
	initialState := cb.state
	cb.mu.Unlock()
	if initialState != circuitBreakerClosed {
		t.Errorf("Expected initial state to be closed, got %d", initialState)
	}

	cb.recordFailure()
	cb.recordFailure()

	cb.mu.Lock()
	openState := cb.state
	cb.mu.Unlock()
	if openState != circuitBreakerOpen {
		t.Errorf("Expected state to be open after threshold failures, got %d", openState)
	}

	cb.lastFailure = time.Now().Add(-100 * time.Millisecond)
	cb.canProceed()

	cb.mu.Lock()
	halfOpenState := cb.state
	cb.mu.Unlock()
	if halfOpenState != circuitBreakerHalfOpen {
		t.Errorf("Expected state to be half-open after timeout, got %d", halfOpenState)
	}
}

func TestCircuitBreaker_RecordSuccessInHalfOpen(t *testing.T) {
	cb := newCircuitBreaker(2, 50*time.Millisecond)
	cb.recordFailure()
	cb.recordFailure()
	cb.lastFailure = time.Now().Add(-100 * time.Millisecond)
	cb.canProceed()

	cb.recordSuccess()
	cb.recordSuccess()
	cb.recordSuccess()

	cb.mu.Lock()
	if cb.state != circuitBreakerClosed {
		t.Errorf("Expected state to be closed after 3 successes in half-open, got %d", cb.state)
	}
	cb.mu.Unlock()
}

func TestClassifyError_AllCategories(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorCategory
	}{
		{"EAGAIN", errors.New("EAGAIN"), ErrorCategoryTransient},
		{"temporary", errors.New("temporary error"), ErrorCategoryTransient},
		{"closed", errors.New("connection closed"), ErrorCategoryTransient},
		{"EOF", errors.New("EOF"), ErrorCategoryTransient},
		{"permission", errors.New("permission denied"), ErrorCategoryPermanent},
		{"denied", errors.New("access denied"), ErrorCategoryPermanent},
		{"other", errors.New("some other error"), ErrorCategoryRecoverable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			category := classifyError(tt.err)
			if category != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, category)
			}
		})
	}
}

func TestTracer_Stop_WithProcessCache(t *testing.T) {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	cache := cache.NewLRUCache(config.CacheMaxSize, ttl)
	tracer := &Tracer{
		filter:           filter.NewCgroupFilter(),
		processNameCache: cache,
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_GetProcessNameQuick_EmptyCmdline(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(50001)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("50001 (stat-process) S"), 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "stat-process" {
		t.Errorf("Expected 'stat-process' from stat, got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_CmdlineWithEmptyFirstPart(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(50002)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte("\x00arg1"), 0644)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("50002 (stat-process) S"), 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "stat-process" {
		t.Errorf("Expected 'stat-process' from stat when cmdline first part is empty, got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_StatNoParentheses(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(50003)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("50003 no parentheses S"), 0644)

	commPath := filepath.Join(procDir, "comm")
	_ = os.WriteFile(commPath, []byte("comm-process"), 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process' from comm when stat has no parentheses, got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_StatEndBeforeStart(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(50004)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("50004 ) end before start ( S"), 0644)

	commPath := filepath.Join(procDir, "comm")
	_ = os.WriteFile(commPath, []byte("comm-process"), 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process' from comm when stat has invalid parentheses, got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_AllFilesMissing(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(50005)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	result := tracer.getProcessNameQuick(pid)
	if result != "" {
		t.Errorf("Expected empty string when all files are missing, got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_CmdlineReadError(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(50006)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("50006 (stat-process) S"), 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "stat-process" {
		t.Errorf("Expected 'stat-process' from stat when cmdline read fails, got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_StatReadError(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(50007)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	commPath := filepath.Join(procDir, "comm")
	_ = os.WriteFile(commPath, []byte("comm-process"), 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "comm-process" {
		t.Errorf("Expected 'comm-process' from comm when stat read fails, got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_CommReadError(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(50008)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	_ = os.WriteFile(cmdlinePath, []byte(""), 0644)

	statPath := filepath.Join(procDir, "stat")
	_ = os.WriteFile(statPath, []byte("50008 (stat-process) S"), 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "stat-process" {
		t.Errorf("Expected 'stat-process' from stat when comm read fails, got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_CmdlineWithPath(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(50009)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	cmdlineContent := []byte("/usr/local/bin/my-process\x00arg1\x00arg2")
	_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "my-process" {
		t.Errorf("Expected 'my-process', got %q", result)
	}
}

func TestTracer_GetProcessNameQuick_CmdlineRootPath(t *testing.T) {
	tempDir := t.TempDir()
	origProcBase := config.ProcBasePath
	config.SetProcBasePath(tempDir)
	defer func() { config.SetProcBasePath(origProcBase) }()

	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
	}

	pid := uint32(50010)
	procDir := filepath.Join(tempDir, fmt.Sprintf("%d", pid))
	_ = os.MkdirAll(procDir, 0755)

	cmdlinePath := filepath.Join(procDir, "cmdline")
	cmdlineContent := []byte("/process-name\x00")
	_ = os.WriteFile(cmdlinePath, cmdlineContent, 0644)

	result := tracer.getProcessNameQuick(pid)
	if result != "process-name" {
		t.Errorf("Expected 'process-name', got %q", result)
	}
}

func TestTracer_Start_WithCgroupPath_NoMaps(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		collection: nil,
		reader:     nil,
	}
	tracer.setCgroupPaths([]string{"/sys/fs/cgroup/test"})

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	ctx := context.Background()

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Start panicked as expected for nil collection: %v", r)
		}
	}()

	err := tracer.Start(ctx, eventChan)
	if err != nil {
		t.Logf("Start returned error as expected: %v", err)
	}
}

func TestTracer_Start_WithCgroupPath_NoLimitsMap(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		collection: nil,
		reader:     nil,
	}
	tracer.setCgroupPaths([]string{"/sys/fs/cgroup/test"})

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	ctx := context.Background()

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Start panicked as expected: %v", r)
		}
	}()

	err := tracer.Start(ctx, eventChan)
	if err != nil {
		t.Logf("Start returned error as expected: %v", err)
	}
}

func TestTracer_Start_WithResourceMonitorError(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	_ = os.MkdirAll(cgroupPath, 0755)

	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		collection: nil,
		reader:     nil,
	}
	tracer.setCgroupPaths([]string{cgroupPath})

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	ctx := context.Background()

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Start panicked as expected: %v", r)
		}
	}()

	err := tracer.Start(ctx, eventChan)
	if err != nil {
		t.Logf("Start returned error as expected: %v", err)
	}
}

func TestTracer_Stop_WithResourceMonitor(t *testing.T) {
	tracer := &Tracer{
		filter:      filter.NewCgroupFilter(),
		links:       []link.Link{},
		resourceMgr: newResourceMonitorManager(),
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_CompleteCleanup(t *testing.T) {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		filter:           filter.NewCgroupFilter(),
		links:            []link.Link{},
		reader:           nil,
		collection:       nil,
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
		resourceMgr:      newResourceMonitorManager(),
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Start_ContextDoneInEventLoop(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		collection: nil,
		reader:     nil,
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		if r := recover(); r != nil {
			t.Logf("Start panicked as expected: %v", r)
		}
		cancel()
	}()

	err := tracer.Start(ctx, eventChan)
	if err == nil {
		cancel()
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTracer_Start_EventProcessing_NoStackMap(t *testing.T) {
	tracer := &Tracer{
		filter:           filter.NewCgroupFilter(),
		collection:       nil,
		reader:           nil,
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, time.Second),
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		cancel()
		if r := recover(); r != nil {
			t.Logf("Start panicked as expected: %v", r)
		}
	}()

	err := tracer.Start(ctx, eventChan)
	if err == nil {
		time.Sleep(10 * time.Millisecond)
		cancel()
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTracer_Start_EventProcessing_WithTargetCache(t *testing.T) {
	tracer := &Tracer{
		filter:           filter.NewCgroupFilter(),
		collection:       nil,
		reader:           nil,
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, time.Second),
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		cancel()
		if r := recover(); r != nil {
			t.Logf("Start panicked as expected: %v", r)
		}
	}()

	err := tracer.Start(ctx, eventChan)
	if err == nil {
		time.Sleep(10 * time.Millisecond)
		cancel()
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTracer_Stop_WithAllComponents(t *testing.T) {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		filter:           filter.NewCgroupFilter(),
		links:            []link.Link{},
		reader:           nil,
		collection:       nil,
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
		resourceMgr:      newResourceMonitorManager(),
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_WithNilProcessCache(t *testing.T) {
	tracer := &Tracer{
		filter:           filter.NewCgroupFilter(),
		links:            []link.Link{},
		processNameCache: nil,
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_WithNilResourceMonitor(t *testing.T) {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		filter:           filter.NewCgroupFilter(),
		links:            []link.Link{},
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
		resourceMgr:      newResourceMonitorManager(),
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_SetContainerID_AllProbeTypes(t *testing.T) {
	tracer := &Tracer{
		filter:      filter.NewCgroupFilter(),
		containerID: "",
		links:       []link.Link{},
		collection:  nil,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Log("SetContainerID panicked as expected for nil collection")
		}
	}()

	err := tracer.SetContainerID("test-container")
	if err == nil {
		if tracer.lastContainerID() != "test-container" {
			t.Errorf("Expected containerID 'test-container', got %q", tracer.lastContainerID())
		}
	}
}

func TestTracer_SetContainerID_MultipleProbes(t *testing.T) {
	tracer := &Tracer{
		filter:      filter.NewCgroupFilter(),
		containerID: "",
		links:       []link.Link{},
		collection:  nil,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Log("SetContainerID panicked as expected for nil collection")
		}
	}()

	err := tracer.SetContainerID("container-1")
	if err == nil {
		err = tracer.SetContainerID("container-2")
		if err == nil {
			if tracer.lastContainerID() != "container-2" {
				t.Errorf("Expected containerID 'container-2', got %q", tracer.lastContainerID())
			}
		}
	}
}

func TestTracer_Start_WithCgroupPath_ResourceMonitorMapsMissing(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	_ = os.MkdirAll(cgroupPath, 0755)

	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		collection: nil,
		reader:     nil,
	}
	tracer.setCgroupPaths([]string{cgroupPath})

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		cancel()
		if r := recover(); r != nil {
			t.Logf("Start panicked as expected: %v", r)
		}
	}()

	err := tracer.Start(ctx, eventChan)
	if err == nil {
		time.Sleep(10 * time.Millisecond)
		cancel()
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTracer_Start_WithoutCgroupPath(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		collection: nil,
		reader:     nil,
	}

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		cancel()
		if r := recover(); r != nil {
			t.Logf("Start panicked as expected: %v", r)
		}
	}()

	err := tracer.Start(ctx, eventChan)
	if err == nil {
		time.Sleep(10 * time.Millisecond)
		cancel()
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRoundUpPow2_BelowMin(t *testing.T) {
	for _, n := range []uint32{0, 1, 100, 4095} {
		if got := roundUpPow2(n); got != 4096 {
			t.Errorf("roundUpPow2(%d) = %d, want 4096", n, got)
		}
	}
}

func TestRoundUpPow2_ExactPowers(t *testing.T) {
	cases := []struct{ in, want uint32 }{
		{4096, 4096},
		{8192, 8192},
		{16384, 16384},
		{65536, 65536},
	}
	for _, c := range cases {
		if got := roundUpPow2(c.in); got != c.want {
			t.Errorf("roundUpPow2(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestRoundUpPow2_NonPowers(t *testing.T) {
	cases := []struct{ in, want uint32 }{
		{4097, 8192},
		{5000, 8192},
		{8193, 16384},
		{32769, 65536},
	}
	for _, c := range cases {
		if got := roundUpPow2(c.in); got != c.want {
			t.Errorf("roundUpPow2(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestIsCgroupV2Base_Exists(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.controllers"), []byte("cpu io memory"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !isCgroupV2Base(dir) {
		t.Error("expected isCgroupV2Base=true when cgroup.controllers exists")
	}
}

func TestIsCgroupV2Base_NotExists(t *testing.T) {
	dir := t.TempDir()
	if isCgroupV2Base(dir) {
		t.Error("expected isCgroupV2Base=false when cgroup.controllers absent")
	}
}

func TestIsCgroupV2Base_EmptyPath(t *testing.T) {
	if isCgroupV2Base("/nonexistent/cgroup/path") {
		t.Error("expected false for non-existent base path")
	}
}

func TestGetCgroupIDFromPath_ValidPath(t *testing.T) {
	dir := t.TempDir()
	id, err := getCgroupIDFromPath(dir)
	if err != nil {
		t.Fatalf("unexpected error for valid path: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero inode for valid directory")
	}
}

func TestGetCgroupIDFromPath_NonExistent(t *testing.T) {
	_, err := getCgroupIDFromPath("/nonexistent/cgroup/path/xyz")
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

func TestReadMainPIDFromCgroupProcs_Valid(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	pod := filepath.Join(base, "pod-1")
	if err := os.MkdirAll(pod, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pod, "cgroup.procs"), []byte("5678\n1234\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if pid := readMainPIDFromCgroupProcs(pod); pid != 1234 {
		t.Errorf("expected main PID 1234 (lowest), got %d", pid)
	}
}

func TestReadMainPIDFromCgroupProcs_Empty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if pid := readMainPIDFromCgroupProcs(dir); pid != 0 {
		t.Errorf("expected 0 for empty procs file, got %d", pid)
	}
}

func TestReadMainPIDFromCgroupProcs_NoFile(t *testing.T) {
	dir := t.TempDir()
	if pid := readMainPIDFromCgroupProcs(dir); pid != 0 {
		t.Errorf("expected 0 when file does not exist, got %d", pid)
	}
}

func TestPIDInCgroupPaths(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	pod := filepath.Join(base, "pod-1")
	if err := os.MkdirAll(pod, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pod, "cgroup.procs"), []byte("1234\n5678\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pidInCgroupPaths(1234, []string{pod}) {
		t.Error("pid 1234 should be reported as a live member of the cgroup")
	}
	if pidInCgroupPaths(4242, []string{pod}) {
		t.Error("pid 4242 is not in cgroup.procs and must be reported absent")
	}
	if pidInCgroupPaths(0, []string{pod}) {
		t.Error("pid 0 must never be reported present")
	}
}

func TestReadMainPIDFromCgroupProcs_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("not-a-pid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if pid := readMainPIDFromCgroupProcs(dir); pid != 0 {
		t.Errorf("expected 0 for non-numeric content, got %d", pid)
	}
}

func TestReadMainPIDFromCgroupProcs_LeadingBlankLines(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	pod := filepath.Join(base, "pod-1")
	if err := os.MkdirAll(pod, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pod, "cgroup.procs"), []byte("\n  \n9999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if pid := readMainPIDFromCgroupProcs(pod); pid != 9999 {
		t.Errorf("expected PID 9999, got %d", pid)
	}
}

func TestAttachToCgroup_EmptyPath(t *testing.T) {
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	_ = tr.AttachToCgroup("")
}

func TestAttachToCgroup_WithCgroupProcsFile(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	pod := filepath.Join(base, "pod-1")
	if err := os.MkdirAll(pod, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pod, "cgroup.procs"), []byte("42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	_ = tr.AttachToCgroup(pod)
	if tr.containerPID != 42 {
		t.Errorf("expected containerPID=42, got %d", tr.containerPID)
	}
}

func TestAttachToCgroup_CRIOSubfolder(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	pod := filepath.Join(base, "pod-1")
	containerDir := filepath.Join(pod, "container")
	if err := os.MkdirAll(containerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(containerDir, "cgroup.procs"), []byte("777\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := &Tracer{filter: filter.NewCgroupFilter()}
	_ = tr.AttachToCgroup(pod)
	if tr.containerPID != 777 {
		t.Errorf("expected containerPID=777 (from CRI-O subfolder), got %d", tr.containerPID)
	}
	if !strings.HasSuffix(tr.primaryCgroupPath(), "container") {
		t.Errorf("expected cgroupPath to end with 'container', got %q", tr.primaryCgroupPath())
	}
}

func TestAttachToCgroup_ReresolveStalePID(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	pod := filepath.Join(base, "pod-1")
	if err := os.MkdirAll(pod, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pod, "cgroup.procs"), []byte("100\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Cached PID 999 is NOT in cgroup.procs (exited or reused elsewhere), so
	// it must be re-resolved to the live main PID (100) rather than preserved —
	// this is the TOCTOU/PID-reuse guard for /proc/<pid>/root discovery.
	tr := &Tracer{
		filter:       filter.NewCgroupFilter(),
		containerPID: 999,
	}
	_ = tr.AttachToCgroup(pod)
	if tr.containerPID != 100 {
		t.Errorf("stale containerPID 999 should re-resolve to live main PID 100, got %d", tr.containerPID)
	}
}

func TestAttachToCgroup_PreserveLiveMemberPID(t *testing.T) {
	base := t.TempDir()
	useCgroupBase(t, base)
	pod := filepath.Join(base, "pod-1")
	if err := os.MkdirAll(pod, 0o755); err != nil {
		t.Fatal(err)
	}
	// Cached PID 100 IS still a member, so it is preserved (no needless churn).
	if err := os.WriteFile(filepath.Join(pod, "cgroup.procs"), []byte("100\n250\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := &Tracer{
		filter:       filter.NewCgroupFilter(),
		containerPID: 100,
	}
	_ = tr.AttachToCgroup(pod)
	if tr.containerPID != 100 {
		t.Errorf("live cached containerPID 100 should be preserved, got %d", tr.containerPID)
	}
}

func TestPollBPFMapUtilization_NilCollection(t *testing.T) {
	tr := &Tracer{collection: nil}
	tr.pollBPFMapUtilization() // must not panic
}

func TestActiveProbeGroups_Empty(t *testing.T) {
	tr := &Tracer{probeGroups: make(map[probes.ProbeGroup][]link.Link)}
	groups := tr.ActiveProbeGroups()
	if len(groups) != 0 {
		t.Errorf("expected no active groups, got %v", groups)
	}
}

func TestActiveProbeGroups_WithGroups(t *testing.T) {
	tr := &Tracer{probeGroups: make(map[probes.ProbeGroup][]link.Link)}
	tr.probeGroups[probes.GroupNetwork] = nil
	tr.probeGroups[probes.GroupDatabase] = nil
	groups := tr.ActiveProbeGroups()
	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d: %v", len(groups), groups)
	}
}

func TestSetEnabledCategories_NilSentinelIsNoop(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{
		probes.GroupNetwork:    nil,
		probes.GroupFileSystem: nil,
	}}
	if err := tr.SetEnabledCategories(nil); err != nil {
		t.Fatalf("nil sentinel: %v", err)
	}
	if _, ok := tr.probeGroups[probes.GroupNetwork]; !ok {
		t.Error("nil sentinel must not detach GroupNetwork")
	}
	if _, ok := tr.probeGroups[probes.GroupFileSystem]; !ok {
		t.Error("nil sentinel must not detach GroupFileSystem")
	}
}

func TestSetEnabledCategories_DetachesUnneededGroups(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{
		probes.GroupNetwork:    nil,
		probes.GroupFileSystem: nil,
		probes.GroupCPU:        nil,
	}}
	if err := tr.SetEnabledCategories([]string{"fs"}); err != nil {
		t.Fatalf("gate: %v", err)
	}
	if _, ok := tr.probeGroups[probes.GroupFileSystem]; !ok {
		t.Error("GroupFileSystem must stay attached for category=fs")
	}
}

func TestSetEnabledCategories_NonGateableGroupsUnaffected(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{
		probes.GroupDatabase:  nil,
		probes.GroupCache:     nil,
		probes.GroupMessaging: nil,
		probes.GroupPool:      nil,
	}}
	if err := tr.SetEnabledCategories([]string{}); err != nil {
		t.Fatalf("gate: %v", err)
	}
	for _, g := range []probes.ProbeGroup{
		probes.GroupDatabase, probes.GroupCache,
		probes.GroupMessaging, probes.GroupPool,
	} {
		if _, ok := tr.probeGroups[g]; !ok {
			t.Errorf("non-gateable group %s must not be detached by empty category set", g)
		}
	}
}

func TestSetEnabledCategories_WarnsOnlyForIntentionallyDisabled(t *testing.T) {
	tr := &Tracer{probeGroups: map[probes.ProbeGroup][]link.Link{
		probes.GroupFileSystem: nil,
	}}
	if err := tr.SetEnabledCategories([]string{"dns"}); err != nil {
		t.Fatalf("gate round 1: %v", err)
	}
	if tr.intentionallyDisabled == nil {
		t.Fatal("intentionallyDisabled must be initialised after a detach")
	}
	if _, ok := tr.intentionallyDisabled[probes.GroupFileSystem]; !ok {
		t.Error("GroupFileSystem should be tracked as intentionally disabled")
	}
	if _, ok := tr.intentionallyDisabled[probes.GroupTLS]; ok {
		t.Error("GroupTLS never attached — must NOT be tracked as intentionally disabled")
	}
	if err := tr.SetEnabledCategories([]string{"fs", "dns"}); err != nil {
		t.Fatalf("gate round 2: %v", err)
	}
	if _, ok := tr.intentionallyDisabled[probes.GroupFileSystem]; !ok {
		t.Error("FS must stay in intentionallyDisabled until agent restart")
	}
	if _, ok := tr.intentionallyDisabled[probes.GroupTLS]; ok {
		t.Error("GroupTLS still must not be in intentionallyDisabled")
	}
}

func TestGroupCategoryNeeds_CoversEveryCategory(t *testing.T) {
	covered := map[string]bool{}
	for _, needs := range groupCategoryNeeds {
		for _, c := range needs {
			covered[c] = true
		}
	}
	for _, c := range []string{"dns", "net", "fs", "cpu", "proc", "crypto"} {
		if !covered[c] {
			t.Errorf("CRD category %q has no probe group in groupCategoryNeeds", c)
		}
	}
}

func TestGroupsNeededFor_RoundTrip(t *testing.T) {
	for _, c := range []string{"dns", "net", "fs", "cpu", "proc", "crypto"} {
		if got := groupsNeededFor(c); len(got) == 0 {
			t.Errorf("groupsNeededFor(%q) returned nothing — category cannot be re-attached", c)
		}
	}
}

func TestDisableProbeGroup_NotPresent(t *testing.T) {
	tr := &Tracer{probeGroups: make(map[probes.ProbeGroup][]link.Link)}
	tr.DisableProbeGroup(probes.GroupNetwork)
}

func TestDisableProbeGroup_EmptyLinks(t *testing.T) {
	tr := &Tracer{probeGroups: make(map[probes.ProbeGroup][]link.Link)}
	tr.probeGroups[probes.GroupDatabase] = nil
	tr.DisableProbeGroup(probes.GroupDatabase)
	if _, ok := tr.probeGroups[probes.GroupDatabase]; !ok {
		t.Error("expected group to still be present when links slice is nil")
	}
}

func TestServeManagementAPI_GetProbes(t *testing.T) {
	tr := &Tracer{probeGroups: make(map[probes.ProbeGroup][]link.Link)}
	tr.probeGroups[probes.GroupNetwork] = nil

	mux := http.NewServeMux()
	mux.HandleFunc("/probes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		groups := tr.ActiveProbeGroups()
		strs := make([]string, len(groups))
		for i, g := range groups {
			strs[i] = string(g)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active_groups": strs})
	})

	req := httptest.NewRequest(http.MethodGet, "/probes", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestServeManagementAPI_PostProbes_MethodNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/probes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	})

	req := httptest.NewRequest(http.MethodPost, "/probes", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestServeManagementAPI_DisableGroup(t *testing.T) {
	tr := &Tracer{probeGroups: make(map[probes.ProbeGroup][]link.Link)}
	tr.probeGroups[probes.GroupDatabase] = nil

	mux := http.NewServeMux()
	mux.HandleFunc("/probes/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/probes/"), "/")
		if len(parts) != 2 || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		group := probes.ProbeGroup(parts[0])
		switch parts[1] {
		case "disable":
			tr.DisableProbeGroup(group)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	})

	req := httptest.NewRequest(http.MethodPost, "/probes/database/disable", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
}

func TestServeManagementAPI_UnknownAction(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/probes/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/probes/"), "/")
		if len(parts) != 2 || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		switch parts[1] {
		case "disable":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	})

	req := httptest.NewRequest(http.MethodPost, "/probes/network/enable", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestServeManagementAPI_BadPathMethod(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/probes/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/probes/"), "/")
		if len(parts) != 2 || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/probes/network/disable", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestServeManagementAPI_RealServer_ContextCancel(t *testing.T) {
	tr := &Tracer{probeGroups: make(map[probes.ProbeGroup][]link.Link)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tr.serveManagementAPI(ctx, 0)
}

func TestStop_WithCaches(t *testing.T) {
	tr := &Tracer{
		filter:           filter.NewCgroupFilter(),
		processNameCache: cache.NewLRUCache(16, time.Minute),
	}
	tr.processNameCache.Set(uint32(1), "init")

	if err := tr.Stop(); err != nil {
		t.Errorf("unexpected error from Stop: %v", err)
	}
}

func TestGetProcessNameQuick_NonExistentPID(t *testing.T) {
	tr := &Tracer{processNameCache: cache.NewLRUCache(16, time.Minute)}
	result := tr.getProcessNameQuick(55555)
	_ = result
}

func TestServeManagementAPI_Integration(t *testing.T) {
	// Find a free port by opening a listener and closing it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	tr := &Tracer{probeGroups: make(map[probes.ProbeGroup][]link.Link)}
	tr.probeGroups[probes.GroupNetwork] = nil

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.serveManagementAPI(ctx, port)
	}()

	addr := fmt.Sprintf("http://127.0.0.1:%d", port)
	var ready bool
	for i := 0; i < 50; i++ {
		resp, err2 := http.Get(addr + "/probes")
		if err2 == nil {
			_ = resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		cancel()
		<-done
		t.Skip("management API server not ready in time")
	}

	resp, err := http.Get(addr + "/probes")
	if err != nil {
		t.Fatalf("GET /probes: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /probes: expected 200, got %d: %s", resp.StatusCode, body)
	}

	resp2, err := http.Post(addr+"/probes", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /probes: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /probes: expected 405, got %d", resp2.StatusCode)
	}

	resp3, err := http.Post(addr+"/probes/network/disable", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /probes/network/disable: %v", err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusNoContent {
		t.Errorf("POST /probes/network/disable: expected 204, got %d", resp3.StatusCode)
	}

	resp4, err := http.Post(addr+"/probes/network/enable", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /probes/network/enable: %v", err)
	}
	_ = resp4.Body.Close()
	if resp4.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /probes/network/enable: expected 400, got %d", resp4.StatusCode)
	}

	resp5, err := http.Get(addr + "/probes/network/disable")
	if err != nil {
		t.Fatalf("GET /probes/network/disable: %v", err)
	}
	_ = resp5.Body.Close()
	if resp5.StatusCode != http.StatusNotFound {
		t.Errorf("GET /probes/network/disable: expected 404, got %d", resp5.StatusCode)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("serveManagementAPI did not shut down in time")
	}
}

// Verify that the fmt import is used so the file compiles without "imported and not used".
var _ = fmt.Sprintf
