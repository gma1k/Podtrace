package main

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gma1k/podtrace/internal/ebpf"
	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
	"github.com/gma1k/podtrace/internal/metricsexporter"
)

func countMetricsServerStarts(t *testing.T) *int {
	t.Helper()
	starts := 0
	origStart, origMetrics := startMetricsServer, enableMetrics
	startMetricsServer = func() *metricsexporter.Server {
		starts++
		return &metricsexporter.Server{}
	}
	enableMetrics = true
	t.Cleanup(func() { startMetricsServer, enableMetrics = origStart, origMetrics })
	return &starts
}

func useResolverAndTracer(t *testing.T, resolver pkgkube.PodResolverInterface) {
	t.Helper()
	origResolver, origTracer, origNamespace := resolverFactory, tracerFactory, namespace
	resolverFactory = func() (pkgkube.PodResolverInterface, error) { return resolver, nil }
	tracerFactory = func() (ebpf.TracerInterface, error) { return nil, errors.New("no tracer in tests") }
	namespace = "default"
	t.Cleanup(func() { resolverFactory, tracerFactory, namespace = origResolver, origTracer, origNamespace })
}

func TestASpawnedTraceLeavesTheMetricsPortToItsPortForward(t *testing.T) {
	saveSpawnGlobals(t)
	saveNodespawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	localMode = false
	spawnImage = "ghcr.io/gma1k/podtrace:test"
	starts := countMetricsServerStarts(t)
	useResolverAndTracer(t, clusterResolver{})

	if err := runPodtrace(&cobra.Command{}, []string{"missing-pod"}); err == nil {
		t.Fatal("expected the spawn flow to fail on the missing pod")
	}
	if *starts != 0 {
		t.Fatalf("the workstation started its own metrics server %d time(s) on the spawn path", *starts)
	}
}

func TestALocalTraceStillServesMetrics(t *testing.T) {
	saveSpawnGlobals(t)
	localMode = true
	starts := countMetricsServerStarts(t)
	useResolverAndTracer(t, &mockPodResolver{
		resolvePodFunc: func(_ context.Context, podName, ns, cn string) (*pkgkube.PodInfo, error) {
			return newBypassPodInfo(podName, ns, cn), nil
		},
	})

	_ = runPodtrace(&cobra.Command{}, []string{"test-pod"})
	if *starts != 1 {
		t.Fatalf("a local trace started the metrics server %d time(s), want 1", *starts)
	}
}
