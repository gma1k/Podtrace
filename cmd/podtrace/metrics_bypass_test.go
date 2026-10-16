package main

import (
	"context"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/spf13/cobra"
)

// TestRunPodtrace_EnableMetrics_DiagnoseMode covers the enableMetrics goroutines
// (lines 290-325 and 370-383) by setting enableMetrics=true with diagnoseDuration.
func TestRunPodtrace_EnableMetrics_DiagnoseMode(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	origNamespace := namespace
	origDiagnoseDuration := diagnoseDuration
	origEnableMetrics := enableMetrics
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
		namespace = origNamespace
		diagnoseDuration = origDiagnoseDuration
		enableMetrics = origEnableMetrics
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
	enableMetrics = true

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
	case <-time.After(5 * time.Second):
		t.Error("runPodtrace with enableMetrics did not complete in time")
	}
}

// TestRunPodtrace_EnableMetrics_WithEvent covers the eventChan receive path in the
// enableMetrics goroutine by sending an event via the tracer's Start function.
func TestRunPodtrace_EnableMetrics_WithEvent(t *testing.T) {
	origResolverFactory := resolverFactory
	origTracerFactory := tracerFactory
	origNamespace := namespace
	origDiagnoseDuration := diagnoseDuration
	origEnableMetrics := enableMetrics
	defer func() {
		resolverFactory = origResolverFactory
		tracerFactory = origTracerFactory
		namespace = origNamespace
		diagnoseDuration = origDiagnoseDuration
		enableMetrics = origEnableMetrics
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
				// Send one event to exercise the eventChan receive path.
				select {
				case eventChan <- &events.Event{Type: events.EventDNS, Target: "example.com"}:
				case <-ctx.Done():
				}
				return nil
			},
		}, nil
	}
	namespace = "default"
	diagnoseDuration = "100ms"
	enableMetrics = true

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
	case <-time.After(5 * time.Second):
		t.Error("runPodtrace with enableMetrics+event did not complete in time")
	}
}
