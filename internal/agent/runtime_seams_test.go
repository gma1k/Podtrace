package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/profiling"
)

type refusingListener struct{}

func (refusingListener) Accept() (net.Conn, error) { return nil, errors.New("accept refused") }
func (refusingListener) Close() error              { return nil }
func (refusingListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestAMetricsServerThatCannotServeReportsWhy(t *testing.T) {
	orig := listenMetrics
	listenMetrics = func(string, string) (net.Listener, error) { return refusingListener{}, nil }
	t.Cleanup(func() { listenMetrics = orig })

	err := serveMetrics(context.Background(), "127.0.0.1:0", NewMetrics(), logr.Discard())
	if err == nil {
		t.Error("serveMetrics returned nil although the listener refused every connection; " +
			"the agent would run with no /metrics and nothing saying so")
	}
}

func TestNodeNameIsEmptyWhenNothingNamesTheNode(t *testing.T) {
	t.Setenv("NODE_NAME", "")
	orig := hostname
	hostname = func() (string, error) { return "", errors.New("uts namespace unavailable") }
	t.Cleanup(func() { hostname = orig })

	if got := ResolveNodeName(); got != "" {
		t.Errorf("ResolveNodeName = %q, want empty when neither NODE_NAME nor the hostname is available", got)
	}
}

func TestExporterConstructionFailuresAreReturned(t *testing.T) {
	payload := &BundlePayload{Endpoint: "otel-collector.observability.svc:4318"}

	origTrace := newTraceExporter
	newTraceExporter = func(context.Context, otlptrace.Client) (*otlptrace.Exporter, error) {
		return nil, errors.New("client start failed")
	}
	if _, err := newOTLPEventExporter(CRKey{Name: "cr"}, payload); err == nil {
		t.Error("a span exporter that failed to start was not reported")
	}
	newTraceExporter = origTrace

	origResource := buildResource
	buildResource = func(context.Context, ...resource.Option) (*resource.Resource, error) {
		return nil, errors.New("schema conflict")
	}
	t.Cleanup(func() { buildResource = origResource })
	if _, err := newOTLPEventExporter(CRKey{Name: "cr"}, payload); err == nil {
		t.Error("a resource that failed to build was not reported")
	}
}

type sysless struct{ os.FileInfo }

func (sysless) Sys() any { return nil }

func TestACgroupWithoutStatDataHasNoID(t *testing.T) {
	st, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cgroupIDFromInfo("/sys/fs/cgroup/x", sysless{st}); err == nil {
		t.Error("an inode was invented for a stat result with no Stat_t")
	}
}

func TestContinuousProfilingJoinsTheExporters(t *testing.T) {
	orig := config.ContinuousProfilingEnabled
	config.ContinuousProfilingEnabled = true
	t.Cleanup(func() { config.ContinuousProfilingEnabled = orig })

	exporters, _, profiler, err := buildExporters(nil, NewMetrics(), nil, nil, logr.Discard())
	if err != nil {
		t.Fatalf("buildExporters: %v", err)
	}
	if profiler == nil {
		t.Fatal("no profiler was built with continuous profiling on")
	}
	found := false
	for _, e := range exporters {
		if p, ok := e.(*profiling.ContinuousProfiler); ok && p == profiler {
			found = true
		}
	}
	if !found {
		t.Error("the profiler was built but not added to the exporters, so it would never see a stack")
	}
	if got := profiler.Snapshot(context.Background()); got == nil {
		t.Error("a snapshot of an idle profiler returned nil rather than an empty list")
	}
}
