package profiling

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/cache"
	"github.com/gma1k/podtrace/internal/events"
)

func TestGetProcessCPUTime_TooFewFieldsAfterParen(t *testing.T) {
	dir := t.TempDir()
	orig := config.ProcBasePath
	defer func() { config.ProcBasePath = orig }()
	config.ProcBasePath = dir

	pid := uint32(4321)
	_ = os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	_ = os.WriteFile(fmt.Sprintf("%s/%d/stat", dir, pid), []byte("4321 (test) S 1 2 3"), 0644)

	if got := getProcessCPUTime(pid); got.totalNS != 0 {
		t.Errorf("expected zero CPU time when fewer than 13 fields follow the comm, got %d", got.totalNS)
	}
}

func TestGetProcessCPUTime_CacheFallbackOnReadError(t *testing.T) {
	dir := t.TempDir()
	orig := config.ProcBasePath
	defer func() { config.ProcBasePath = orig }()
	defer cache.ResetCPUTimes()

	pid := uint32(31337)
	config.ProcBasePath = dir
	_ = os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	statContent := "31337 (test) S 1 1 1 0 -1 0 0 0 0 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	_ = os.WriteFile(fmt.Sprintf("%s/%d/stat", dir, pid), []byte(statContent), 0644)
	cache.SnapshotCPUTime(pid)

	config.ProcBasePath = t.TempDir()
	got := getProcessCPUTime(pid)
	if got.totalNS == 0 {
		t.Error("expected getProcessCPUTime to fall back to the cached snapshot when /proc read fails")
	}
}

func TestGenerateCPUUsageReport_BaselineDeltaApplied(t *testing.T) {
	dir := t.TempDir()
	orig := config.ProcBasePath
	defer func() { config.ProcBasePath = orig }()
	defer cache.ResetCPUTimes()
	config.ProcBasePath = dir

	pid := uint32(424242)
	_ = os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	statPath := fmt.Sprintf("%s/%d/stat", dir, pid)

	low := "424242 (worker) S 1 1 1 0 -1 0 0 0 0 0 100 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	_ = os.WriteFile(statPath, []byte(low), 0644)
	cache.SnapshotCPUTime(pid)

	high := "424242 (worker) S 1 1 1 0 -1 0 0 0 0 0 500 200 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	_ = os.WriteFile(statPath, []byte(high), 0644)

	report := GenerateCPUUsageReport([]*events.Event{
		{PID: pid, ProcessName: "worker", Type: events.EventSchedSwitch},
	}, 10*time.Second)

	if !contains(report, "Pod Processes") {
		t.Errorf("expected the delta-derived process to appear under Pod Processes, got:\n%s", report)
	}
	if !contains(report, "Total CPU usage") {
		t.Errorf("expected a total CPU usage line, got:\n%s", report)
	}
}

func TestGenerateCPUUsageReport_CapsCPUPercent(t *testing.T) {
	dir := t.TempDir()
	orig := config.ProcBasePath
	defer func() { config.ProcBasePath = orig }()
	defer cache.ResetCPUTimes()
	config.ProcBasePath = dir
	_ = os.WriteFile(dir+"/uptime", []byte("1.00 1.00\n"), 0644)

	pid := uint32(515151)
	_ = os.MkdirAll(fmt.Sprintf("%s/%d", dir, pid), 0755)
	huge := "515151 (busy) S 1 1 1 0 -1 0 0 0 0 0 100000000 100000000 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
	_ = os.WriteFile(fmt.Sprintf("%s/%d/stat", dir, pid), []byte(huge), 0644)

	report := GenerateCPUUsageReport([]*events.Event{
		{PID: pid, ProcessName: "busy", Type: events.EventSchedSwitch},
	}, time.Nanosecond)

	if !contains(report, "Pod Processes") {
		t.Errorf("expected the capped process to appear, got:\n%s", report)
	}
}

func TestAnalyzeTimeline_ZeroDurationClampsBucket(t *testing.T) {
	start := time.Now()
	evs := []*events.Event{{Timestamp: uint64(start.UnixNano())}}
	buckets := AnalyzeTimeline(evs, start, 0)
	if len(buckets) != config.TimelineBuckets {
		t.Fatalf("expected %d buckets even for zero duration, got %d", config.TimelineBuckets, len(buckets))
	}
}

func TestAnalyzeConnectionPattern_NonPositiveSpanFallsBackToDuration(t *testing.T) {
	start := time.Now()
	end := start.Add(-5 * time.Second)
	evs := []*events.Event{
		{Type: events.EventConnect, Timestamp: uint64(start.UnixNano()), Target: "a:80"},
		{Type: events.EventConnect, Timestamp: uint64(start.Add(time.Second).UnixNano()), Target: "b:80"},
	}
	cp := AnalyzeConnectionPattern(evs, start, end, 10*time.Second)
	if cp.Pattern == "" {
		t.Error("expected a non-empty pattern when span<=0 falls back to duration")
	}
}

func TestAnalyzeConnectionPattern_SpanShorterThanWindowClampsWindows(t *testing.T) {
	start := time.Now()
	end := start.Add(time.Nanosecond)
	evs := []*events.Event{
		{Type: events.EventConnect, Timestamp: uint64(start.UnixNano()), Target: "a:80"},
	}
	cp := AnalyzeConnectionPattern(evs, start, end, 100*time.Second)
	if cp.Pattern == "" {
		t.Error("expected a non-empty pattern when the span is shorter than one window")
	}
}

func TestAnalyzeConnectionPattern_SporadicPattern(t *testing.T) {
	start := time.Now()
	end := start.Add(16 * time.Second)
	duration := 40 * time.Second

	offsets := []time.Duration{
		0, time.Second,
		4 * time.Second, 5 * time.Second, 6 * time.Second,
		8 * time.Second, 9 * time.Second,
		12 * time.Second, 13 * time.Second, 14 * time.Second,
	}
	var evs []*events.Event
	for _, off := range offsets {
		evs = append(evs, &events.Event{
			Type:      events.EventConnect,
			Timestamp: uint64(start.Add(off).UnixNano()),
			Target:    "example.com:80",
		})
	}

	cp := AnalyzeConnectionPattern(evs, start, end, duration)
	if cp.Pattern != "sporadic" {
		t.Errorf("Pattern = %q, want sporadic for a moderately-varying window distribution", cp.Pattern)
	}
}
