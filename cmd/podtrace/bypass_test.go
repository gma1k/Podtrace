package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/spf13/cobra"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// newBypassPodInfo returns PodInfo with empty CgroupPath, bypassing the cgroup
// safety check at main.go:221 (condition: podInfo.CgroupPath != "").
func newBypassPodInfo(podName, namespace, containerName string) *kubernetes.PodInfo {
	return &kubernetes.PodInfo{
		PodName:       podName,
		Namespace:     namespace,
		ContainerID:   "test-container-id",
		CgroupPath:    "/sys/fs/cgroup/kubepods.slice/cri-containerd-test-container-id.scope",
		ContainerName: containerName,
	}
}

// TestRunPodtrace_ShowVersion covers the showVersion=true early return (lines 108-111).
func TestRunPodtrace_ShowVersion(t *testing.T) {
	origShowVersion := showVersion
	defer func() { showVersion = origShowVersion }()
	showVersion = true

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{})
	if err != nil {
		t.Errorf("expected nil error for showVersion=true, got %v", err)
	}
}

// TestRunPodtrace_BypassCgroup_TracerError covers CheckRequirements + tracerFactory error
// (lines 241-249) by using empty CgroupPath to bypass the safety check.
func TestRunPodtrace_BypassCgroup_TracerError(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	origNamespace := namespace
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
		namespace = origNamespace
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{
			resolvePodFunc: func(ctx context.Context, podName, ns, cn string) (*kubernetes.PodInfo, error) {
				return newBypassPodInfo(podName, ns, cn), nil
			},
		}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return nil, errors.New("tracer-create-error")
	}
	namespace = "default"

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("expected error from tracerFactory")
	}
}

// TestRunPodtrace_BypassCgroup_AttachError covers the AttachToCgroup error path (lines 252-254).
func TestRunPodtrace_BypassCgroup_AttachError(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	origNamespace := namespace
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
		namespace = origNamespace
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{
			resolvePodFunc: func(ctx context.Context, podName, ns, cn string) (*kubernetes.PodInfo, error) {
				return newBypassPodInfo(podName, ns, cn), nil
			},
		}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{
			attachToCgroupFunc: func(cgroupPath string) error {
				return errors.New("attach-cgroup-error")
			},
		}, nil
	}
	namespace = "default"

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("expected error from AttachToCgroup")
	}
}

// TestRunPodtrace_BypassCgroup_SetContainerIDError covers SetContainerID error (lines 255-257).
func TestRunPodtrace_BypassCgroup_SetContainerIDError(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	origNamespace := namespace
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
		namespace = origNamespace
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{
			resolvePodFunc: func(ctx context.Context, podName, ns, cn string) (*kubernetes.PodInfo, error) {
				return newBypassPodInfo(podName, ns, cn), nil
			},
		}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{
			setContainerIDFunc: func(containerID string) error {
				return errors.New("set-container-id-error")
			},
		}, nil
	}
	namespace = "default"

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("expected error from SetContainerID")
	}
}

// TestRunPodtrace_BypassCgroup_StartError covers lines 259-387 (ctx, signals,
// enrichment, eventChan, goroutine setup, and tracer.Start error return).
func TestRunPodtrace_BypassCgroup_StartError(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	origNamespace := namespace
	origDiagnoseDuration := diagnoseDuration
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
		namespace = origNamespace
		diagnoseDuration = origDiagnoseDuration
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{
			resolvePodFunc: func(ctx context.Context, podName, ns, cn string) (*kubernetes.PodInfo, error) {
				return newBypassPodInfo(podName, ns, cn), nil
			},
		}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{
			startFunc: func(ctx context.Context, eventChan chan<- *events.Event) error {
				return errors.New("start-tracer-error")
			},
		}, nil
	}
	namespace = "default"
	diagnoseDuration = ""

	cmd := &cobra.Command{}
	err := runPodtrace(cmd, []string{"test-pod"})
	if err == nil {
		t.Error("expected error from tracer.Start")
	}
}

// TestRunPodtrace_BypassCgroup_DiagnoseMode covers the full success path through
// tracer.Start and runDiagnoseMode (lines 385-394).
func TestRunPodtrace_BypassCgroup_DiagnoseMode(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	origNamespace := namespace
	origDiagnoseDuration := diagnoseDuration
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
		namespace = origNamespace
		diagnoseDuration = origDiagnoseDuration
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{
			resolvePodFunc: func(ctx context.Context, podName, ns, cn string) (*kubernetes.PodInfo, error) {
				return newBypassPodInfo(podName, ns, cn), nil
			},
		}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}
	namespace = "default"
	diagnoseDuration = "50ms"

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		done <- runPodtrace(cmd, []string{"test-pod"})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runPodtrace: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("runPodtrace did not complete in time")
	}
}

// TestRunPodtrace_BypassCgroup_WithEventFilter covers the filteredChan and
// filterEvents goroutine paths (lines 365-368).
func TestRunPodtrace_BypassCgroup_WithEventFilter(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	origNamespace := namespace
	origDiagnoseDuration := diagnoseDuration
	origEventFilter := eventFilter
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
		namespace = origNamespace
		diagnoseDuration = origDiagnoseDuration
		eventFilter = origEventFilter
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{
			resolvePodFunc: func(ctx context.Context, podName, ns, cn string) (*kubernetes.PodInfo, error) {
				return newBypassPodInfo(podName, ns, cn), nil
			},
		}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}
	namespace = "default"
	diagnoseDuration = "50ms"
	eventFilter = "dns,net"

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		done <- runPodtrace(cmd, []string{"test-pod"})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runPodtrace: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("runPodtrace did not complete in time")
	}
}

// TestRunPodtrace_BypassCgroup_WithClientset covers the enrichment setup path
// (lines 272-287) when the resolver implements kubernetes.ClientsetProvider.
func TestRunPodtrace_BypassCgroup_WithClientset(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	origNamespace := namespace
	origDiagnoseDuration := diagnoseDuration
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
		namespace = origNamespace
		diagnoseDuration = origDiagnoseDuration
	}()

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockClientsetBypassResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}
	namespace = "default"
	diagnoseDuration = "50ms"

	done := make(chan error, 1)
	go func() {
		cmd := &cobra.Command{}
		done <- runPodtrace(cmd, []string{"test-pod"})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runPodtrace: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("runPodtrace did not complete in time")
	}
}

// mockClientsetBypassResolver implements both PodResolverInterface and ClientsetProvider,
// returning empty CgroupPath to bypass the cgroup safety check.
type mockClientsetBypassResolver struct{}

func (m *mockClientsetBypassResolver) ResolvePod(ctx context.Context, podName, namespace, containerName string) (*kubernetes.PodInfo, error) {
	return newBypassPodInfo(podName, namespace, containerName), nil
}

func (m *mockClientsetBypassResolver) GetClientset() k8s.Interface {
	return fake.NewSimpleClientset()
}

var _ kubernetes.PodResolverInterface = (*mockClientsetBypassResolver)(nil)
var _ kubernetes.ClientsetProvider = (*mockClientsetBypassResolver)(nil)
