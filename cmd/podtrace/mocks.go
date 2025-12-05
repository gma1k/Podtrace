package main

import (
	"context"

	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
)

type mockPodResolver struct {
	resolvePodFunc func(ctx context.Context, podName, namespace, containerName string) (*kubernetes.PodInfo, error)
}

func (m *mockPodResolver) ResolvePod(ctx context.Context, podName, namespace, containerName string) (*kubernetes.PodInfo, error) {
	if m.resolvePodFunc != nil {
		return m.resolvePodFunc(ctx, podName, namespace, containerName)
	}
	return &kubernetes.PodInfo{
		PodName:       podName,
		Namespace:     namespace,
		ContainerID:   "test-container-id",
		CgroupPath:    "/sys/fs/cgroup/test",
		ContainerName: containerName,
	}, nil
}

type mockTracer struct {
	attachToCgroupFunc func(cgroupPath string) error
	setContainerIDFunc  func(containerID string) error
	startFunc           func(eventChan chan<- *events.Event) error
	stopFunc            func() error
}

func (m *mockTracer) AttachToCgroup(cgroupPath string) error {
	if m.attachToCgroupFunc != nil {
		return m.attachToCgroupFunc(cgroupPath)
	}
	return nil
}

func (m *mockTracer) SetContainerID(containerID string) error {
	if m.setContainerIDFunc != nil {
		return m.setContainerIDFunc(containerID)
	}
	return nil
}

func (m *mockTracer) Start(eventChan chan<- *events.Event) error {
	if m.startFunc != nil {
		return m.startFunc(eventChan)
	}
	return nil
}

func (m *mockTracer) Stop() error {
	if m.stopFunc != nil {
		return m.stopFunc()
	}
	return nil
}

var _ ebpf.TracerInterface = (*mockTracer)(nil)
var _ kubernetes.PodResolverInterface = (*mockPodResolver)(nil)