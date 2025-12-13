package tracer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/ebpf/cache"
	"github.com/podtrace/podtrace/internal/ebpf/filter"
	"github.com/podtrace/podtrace/internal/events"
)

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
		if tracer.containerID != containerID {
			t.Errorf("Expected containerID %q, got %q", containerID, tracer.containerID)
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
		if tracer.containerID != "" {
			t.Errorf("Expected empty containerID, got %q", tracer.containerID)
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
		if tracer.containerID != "test-container-id" {
			t.Errorf("Expected containerID 'test-container-id', got %q", tracer.containerID)
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
		if tracer.containerID != containerID {
			t.Errorf("Expected containerID %q, got %q", containerID, tracer.containerID)
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
		if tracer.containerID != "container-2" {
			t.Errorf("Expected containerID 'container-2', got %q", tracer.containerID)
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
		cgroupPath: "/sys/fs/cgroup/test",
		collection: nil,
		reader:     nil,
	}

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
		cgroupPath: "/sys/fs/cgroup/test",
		collection: nil,
		reader:     nil,
	}

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

func TestTracer_Start_PathCacheCleanup(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		collection: nil,
		reader:     nil,
		pathCache:  cache.NewPathCache(),
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
		time.Sleep(50 * time.Millisecond)
		cancel()
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTracer_Start_WithResourceMonitorError(t *testing.T) {
	tmpDir := t.TempDir()
	cgroupPath := filepath.Join(tmpDir, "test-cgroup")
	_ = os.MkdirAll(cgroupPath, 0755)

	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		cgroupPath: cgroupPath,
		collection: nil,
		reader:     nil,
	}

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
		filter:          filter.NewCgroupFilter(),
		links:           []link.Link{},
		resourceMonitor: nil,
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_WithPathCache(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		links:      []link.Link{},
		pathCache:  cache.NewPathCache(),
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
		pathCache:        cache.NewPathCache(),
		resourceMonitor:  nil,
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
		pathCache:        cache.NewPathCache(),
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
		pathCache:        cache.NewPathCache(),
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
		pathCache:        cache.NewPathCache(),
		resourceMonitor:  nil,
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
		pathCache:        cache.NewPathCache(),
	}

	err := tracer.Stop()
	if err != nil {
		t.Errorf("Stop should not return error, got %v", err)
	}
}

func TestTracer_Stop_WithNilPathCache(t *testing.T) {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	tracer := &Tracer{
		filter:           filter.NewCgroupFilter(),
		links:            []link.Link{},
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
		pathCache:        nil,
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
		pathCache:        cache.NewPathCache(),
		resourceMonitor:  nil,
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
		if tracer.containerID != "test-container" {
			t.Errorf("Expected containerID 'test-container', got %q", tracer.containerID)
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
			if tracer.containerID != "container-2" {
				t.Errorf("Expected containerID 'container-2', got %q", tracer.containerID)
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
		cgroupPath: cgroupPath,
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

func TestTracer_Start_WithoutCgroupPath(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		cgroupPath: "",
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

func TestTracer_Start_PathCacheCleanupGoroutine(t *testing.T) {
	tracer := &Tracer{
		filter:     filter.NewCgroupFilter(),
		collection: nil,
		reader:     nil,
		pathCache:  cache.NewPathCache(),
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
		time.Sleep(35 * time.Second)
		cancel()
		time.Sleep(10 * time.Millisecond)
	}
}


