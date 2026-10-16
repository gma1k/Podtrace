package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/gma1k/podtrace/internal/config"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/profiling"
)

func schedEvent(namespace, workload string, pid uint32, addr uint64) *events.Event {
	return &events.Event{
		Type:  events.EventSchedSwitch,
		PID:   pid,
		Stack: []uint64{addr},
		K8s: &events.K8sMetadata{
			Namespace:    namespace,
			WorkloadName: workload,
		},
	}
}

func TestProfileEndpointRendersTheContinuousProfile(t *testing.T) {
	p := profiling.NewContinuousProfiler(nil, nil)
	if err := p.Export(context.Background(), []*events.Event{
		schedEvent("shop", "checkout", 1, 0xbeef),
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	rec := httptest.NewRecorder()
	profileHandler(p)(rec, httptest.NewRequest(http.MethodGet, "/profile", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("content type = %q", got)
	}

	var body struct {
		Profiles []profiling.WorkloadProfile `json:"profiles"`
		Dropped  uint64                      `json:"droppedSamples"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Profiles) != 1 {
		t.Fatalf("expected one workload profile, got %d", len(body.Profiles))
	}
	if body.Profiles[0].Workload != "checkout" {
		t.Errorf("workload = %q", body.Profiles[0].Workload)
	}
	if len(body.Profiles[0].Frames) != 1 || body.Profiles[0].Frames[0].Frame != "0xbeef" {
		t.Errorf("frames = %+v", body.Profiles[0].Frames)
	}
}

func TestProfileEndpointRendersAnEmptyProfileBeforeAnySamples(t *testing.T) {
	rec := httptest.NewRecorder()
	profileHandler(profiling.NewContinuousProfiler(nil, nil))(
		rec, httptest.NewRequest(http.MethodGet, "/profile", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := body["profiles"]; !ok {
		t.Errorf("no profiles key in %v", body)
	}
}

func TestServeMetricsRegistersTheProfileEndpointOnlyWithAProfiler(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := profiling.NewContinuousProfiler(nil, nil)
	done := make(chan error, 1)
	go func() { done <- serveMetrics(ctx, addr, NewMetrics(), p, nil, logr.Discard()) }()

	var resp *http.Response
	for range 50 {
		resp, err = http.Get("http://" + addr + "/profile")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /profile: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("/profile status = %d, want 200", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("serveMetrics returned %v on shutdown", err)
	}
}

func TestBuildExportersAddsTheProfilerOnlyWhenEnabled(t *testing.T) {
	_, _, profiler, err := buildExporters(NewRouter(newPerCRStats()), NewMetrics(), nil, nil, logr.Discard())
	if err != nil {
		t.Fatalf("buildExporters: %v", err)
	}
	if profiler != nil {
		t.Error("a continuous profiler was built while the feature is off by default; " +
			"it would consume every sched_switch stack nobody asked for")
	}

	t.Setenv("PODTRACE_CONTINUOUS_PROFILING_ENABLED", "true")
	config.ContinuousProfilingEnabled = true
	defer func() { config.ContinuousProfilingEnabled = false }()

	exporters, _, profiler, err := buildExporters(NewRouter(newPerCRStats()), NewMetrics(), nil, nil, logr.Discard())
	if err != nil {
		t.Fatalf("buildExporters: %v", err)
	}
	if profiler == nil {
		t.Fatal("no profiler was built with the feature on")
	}
	var wired bool
	for _, e := range exporters {
		if e.Name() == profiler.Name() {
			wired = true
		}
	}
	if !wired {
		t.Error("the profiler was built but never added to the exporter fan-out, so it " +
			"would never see an event")
	}
}
