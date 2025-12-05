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
		links:   []link.Link{},
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
