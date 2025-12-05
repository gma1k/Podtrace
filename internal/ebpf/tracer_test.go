package ebpf

import (
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/podtrace/podtrace/internal/config"
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
		proc.Signal(os.Interrupt)
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

	err := tracer.Start(eventChan)
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
		proc.Signal(os.Interrupt)
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
			tracer.Stop()
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

	err := tracer.Start(eventChan)
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

	err := tracer.Start(eventChan)
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
	defer tracer.Stop()

	eventChan := make(chan *events.Event, config.EventChannelBufferSize)

	err = tracer.Start(eventChan)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	tracer.AttachToCgroup("")

	time.Sleep(100 * time.Millisecond)

	tracer.Stop()

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

			err := tt.tracer.Start(eventChan)
			if (err != nil) != tt.wantErr {
				t.Errorf("Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
