package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/spf13/cobra"
)

func TestRunPodtrace_InvalidPodName(t *testing.T) {
	origNamespace := namespace
	origContainerName := containerName
	origEventFilter := eventFilter
	origExportFormat := exportFormat
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	namespace = "default"
	containerName = ""
	eventFilter = ""
	exportFormat = ""
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		namespace = origNamespace
		containerName = origContainerName
		eventFilter = origEventFilter
		exportFormat = origExportFormat
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{""})
	if err == nil {
		t.Error("Expected error for invalid pod name")
	}
}

func TestRunPodtrace_InvalidNamespace(t *testing.T) {
	origNamespace := namespace
	origContainerName := containerName
	origEventFilter := eventFilter
	origExportFormat := exportFormat
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	namespace = ""
	containerName = ""
	eventFilter = ""
	exportFormat = ""
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		namespace = origNamespace
		containerName = origContainerName
		eventFilter = origEventFilter
		exportFormat = origExportFormat
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error for invalid namespace")
	}
}

func TestRunPodtrace_InvalidContainerName(t *testing.T) {
	origNamespace := namespace
	origContainerName := containerName
	origEventFilter := eventFilter
	origExportFormat := exportFormat
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	namespace = "default"
	containerName = "invalid-container-name!!!"
	eventFilter = ""
	exportFormat = ""
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		namespace = origNamespace
		containerName = origContainerName
		eventFilter = origEventFilter
		exportFormat = origExportFormat
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error for invalid container name")
	}
}

func TestRunPodtrace_InvalidExportFormat(t *testing.T) {
	origNamespace := namespace
	origContainerName := containerName
	origEventFilter := eventFilter
	origExportFormat := exportFormat
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	namespace = "default"
	containerName = ""
	eventFilter = ""
	exportFormat = "invalid-format"
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		namespace = origNamespace
		containerName = origContainerName
		eventFilter = origEventFilter
		exportFormat = origExportFormat
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error for invalid export format")
	}
}

func TestRunPodtrace_InvalidEventFilter(t *testing.T) {
	origNamespace := namespace
	origContainerName := containerName
	origEventFilter := eventFilter
	origExportFormat := exportFormat
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	namespace = "default"
	containerName = ""
	eventFilter = "invalid-filter"
	exportFormat = ""
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		namespace = origNamespace
		containerName = origContainerName
		eventFilter = origEventFilter
		exportFormat = origExportFormat
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error for invalid event filter")
	}
}

func TestRunPodtrace_InvalidErrorThreshold(t *testing.T) {
	origNamespace := namespace
	origContainerName := containerName
	origEventFilter := eventFilter
	origExportFormat := exportFormat
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	namespace = "default"
	containerName = ""
	eventFilter = ""
	exportFormat = ""
	errorRateThreshold = 150.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		namespace = origNamespace
		containerName = origContainerName
		eventFilter = origEventFilter
		exportFormat = origExportFormat
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error for invalid error threshold")
	}
}

func TestRunPodtrace_InvalidRTTThreshold(t *testing.T) {
	origNamespace := namespace
	origContainerName := containerName
	origEventFilter := eventFilter
	origExportFormat := exportFormat
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	namespace = "default"
	containerName = ""
	eventFilter = ""
	exportFormat = ""
	errorRateThreshold = 10.0
	rttSpikeThreshold = -10.0
	fsSlowThreshold = 10.0
	defer func() {
		namespace = origNamespace
		containerName = origContainerName
		eventFilter = origEventFilter
		exportFormat = origExportFormat
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error for invalid RTT threshold")
	}
}

func TestRunPodtrace_InvalidFSThreshold(t *testing.T) {
	origNamespace := namespace
	origContainerName := containerName
	origEventFilter := eventFilter
	origExportFormat := exportFormat
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	namespace = "default"
	containerName = ""
	eventFilter = ""
	exportFormat = ""
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = -10.0
	defer func() {
		namespace = origNamespace
		containerName = origContainerName
		eventFilter = origEventFilter
		exportFormat = origExportFormat
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error for invalid FS threshold")
	}
}

func TestRunPodtrace_ResolverError(t *testing.T) {
	origResolverFactory := resolverFactory
	defer func() { resolverFactory = origResolverFactory }()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return nil, errors.New("resolver error")
	}

	origNamespace := namespace
	namespace = "default"
	defer func() { namespace = origNamespace }()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error from resolver factory")
	}
}

func TestRunPodtrace_ResolvePodError(t *testing.T) {
	origResolverFactory := resolverFactory
	defer func() { resolverFactory = origResolverFactory }()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{
			resolvePodFunc: func(ctx context.Context, podName, namespace, containerName string) (*kubernetes.PodInfo, error) {
				return nil, errors.New("resolve pod error")
			},
		}, nil
	}

	origNamespace := namespace
	namespace = "default"
	defer func() { namespace = origNamespace }()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error from ResolvePod")
	}
}

func TestRunPodtrace_TracerError(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return nil, errors.New("tracer error")
	}

	origNamespace := namespace
	namespace = "default"
	defer func() { namespace = origNamespace }()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error from tracer factory")
	}
}

func TestRunPodtrace_AttachToCgroupError(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{
			attachToCgroupFunc: func(cgroupPath string) error {
				return errors.New("attach error")
			},
		}, nil
	}

	origNamespace := namespace
	namespace = "default"
	defer func() { namespace = origNamespace }()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error from AttachToCgroup")
	}
}

func TestRunPodtrace_SetContainerIDError(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{
			setContainerIDFunc: func(containerID string) error {
				return errors.New("set container ID error")
			},
		}, nil
	}

	origNamespace := namespace
	namespace = "default"
	defer func() { namespace = origNamespace }()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error from SetContainerID")
	}
}

func TestRunPodtrace_StartError(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{
			startFunc: func(eventChan chan<- *events.Event) error {
				return errors.New("start error")
			},
		}, nil
	}

	origNamespace := namespace
	origDiagnoseDuration := diagnoseDuration
	namespace = "default"
	diagnoseDuration = ""
	defer func() {
		namespace = origNamespace
		diagnoseDuration = origDiagnoseDuration
	}()

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("Expected error from Start")
	}
}

func TestRunPodtrace_WithMetrics(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}

	origNamespace := namespace
	origEnableMetrics := enableMetrics
	origDiagnoseDuration := diagnoseDuration
	namespace = "default"
	enableMetrics = true
	diagnoseDuration = "50ms"
	defer func() {
		namespace = origNamespace
		enableMetrics = origEnableMetrics
		diagnoseDuration = origDiagnoseDuration
	}()

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		err := runPodtrace(cmd, []string{"test-pod"})
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("runPodtrace completed with expected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("runPodtrace did not complete in time")
	}
}

func TestRunPodtrace_WithEventFilter(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}

	origNamespace := namespace
	origEventFilter := eventFilter
	origDiagnoseDuration := diagnoseDuration
	namespace = "default"
	eventFilter = "dns,net"
	diagnoseDuration = "50ms"
	defer func() {
		namespace = origNamespace
		eventFilter = origEventFilter
		diagnoseDuration = origDiagnoseDuration
	}()

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		err := runPodtrace(cmd, []string{"test-pod"})
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("runPodtrace completed with expected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("runPodtrace did not complete in time")
	}
}

