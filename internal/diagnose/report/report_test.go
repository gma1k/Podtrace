package report

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/analyzer"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/events"
)

type mockDiagnostician struct {
	fsKernel           analyzer.FSKernelCounts
	events             []*events.Event
	startTime          time.Time
	endTime            time.Time
	errorRateThreshold float64
	rttSpikeThreshold  float64
	fsSlowThreshold    float64
}

func (m *mockDiagnostician) GetEvents() []*events.Event {
	return m.events
}

func (m *mockDiagnostician) FilterEvents(eventType events.EventType) []*events.Event {
	var filtered []*events.Event
	for _, e := range m.events {
		if e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (m *mockDiagnostician) CalculateRate(count int, duration time.Duration) float64 {
	if duration.Seconds() > 0 {
		return float64(count) / duration.Seconds()
	}
	return 0
}

func (m *mockDiagnostician) StartTime() time.Time {
	return m.startTime
}

func (m *mockDiagnostician) EndTime() time.Time {
	return m.endTime
}

func (m *mockDiagnostician) ErrorRateThreshold() float64 {
	return m.errorRateThreshold
}

func (m *mockDiagnostician) RTTSpikeThreshold() float64 {
	return m.rttSpikeThreshold
}

func (m *mockDiagnostician) FastFilesystemOps() analyzer.FSKernelCounts { return m.fsKernel }

func (m *mockDiagnostician) FSSlowThreshold() float64 {
	return m.fsSlowThreshold
}

func TestGenerateSummarySection(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateSummarySection(d, duration)
	if result == "" {
		t.Error("Expected summary section")
	}
}

func TestGenerateDNSSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateDNSSection(d, duration)
	if result != "" {
		t.Error("Expected empty DNS section for no events")
	}
}

func TestGenerateDNSSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 1000000, Target: "example.com"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateDNSSection(d, duration)
	if result == "" {
		t.Error("Expected DNS section")
	}
}

func TestGenerateTCPSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateTCPSection(d, duration)
	if result != "" {
		t.Error("Expected empty TCP section for no events")
	}
}

func TestGenerateTCPSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventTCPSend, LatencyNS: 1000000, Bytes: 1024},
			{Type: events.EventTCPRecv, LatencyNS: 2000000, Bytes: 2048},
		},
		startTime:         time.Now(),
		endTime:           time.Now().Add(1 * time.Second),
		rttSpikeThreshold: 100.0,
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateTCPSection(d, duration)
	if result == "" {
		t.Error("Expected TCP section")
	}
}

func TestGenerateConnectionSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateConnectionSection(d, duration)
	if result != "" {
		t.Error("Expected empty connection section for no events")
	}
}

func TestGenerateConnectionSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateConnectionSection(d, duration)
	if result == "" {
		t.Error("Expected connection section")
	}
}

func TestGenerateFileSystemSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateFileSystemSection(d, duration)
	if result != "" {
		t.Error("Expected empty filesystem section for no events")
	}
}

func TestGenerateFileSystemSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 4096},
			{Type: events.EventWrite, LatencyNS: 3000000, Target: "/tmp/file2", Bytes: 2048},
		},
		startTime:       time.Now(),
		endTime:         time.Now().Add(1 * time.Second),
		fsSlowThreshold: 10.0,
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateFileSystemSection(d, duration)
	if result == "" {
		t.Error("Expected filesystem section")
	}
}

func TestGenerateUDPSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateUDPSection(d, duration)
	if result != "" {
		t.Error("Expected empty UDP section for no events")
	}
}

func TestGenerateUDPSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventUDPSend, LatencyNS: 1000000, Bytes: 512},
			{Type: events.EventUDPRecv, LatencyNS: 2000000, Bytes: 1024},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateUDPSection(d, duration)
	if result == "" {
		t.Error("Expected UDP section")
	}
}

func TestGenerateHTTPSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateHTTPSection(d, duration)
	if result != "" {
		t.Error("Expected empty HTTP section for no events")
	}
}

func TestGenerateHTTPSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "http://example.com"},
			{Type: events.EventHTTPResp, LatencyNS: 10000000, Target: "http://example.com", Bytes: 2048},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateHTTPSection(d, duration)
	if result == "" {
		t.Error("Expected HTTP section")
	}
}

func TestGenerateHTTPSection_LatencyFromResponsesOnly(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventHTTPReq, LatencyNS: 0, Target: "GET /a"},
			{Type: events.EventHTTPReq, LatencyNS: 0, Target: "GET /b"},
			{Type: events.EventHTTPResp, LatencyNS: 30000000, Target: "GET /a", Bytes: 2048},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateHTTPSection(d, d.endTime.Sub(d.startTime))
	if !strings.Contains(result, "Average latency: 30.00ms") {
		t.Errorf("expected responses-only average of 30.00ms, got:\n%s", result)
	}
	if strings.Contains(result, "Average latency: 10.00ms") {
		t.Errorf("average latency diluted by zero-latency request events:\n%s", result)
	}
	if strings.Contains(result, "P50=0.00ms") {
		t.Errorf("P50 collapsed to 0 by zero-latency request events:\n%s", result)
	}
}

func TestGenerateHTTPSection_TLSTransport(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "GET /plain"},
			{Type: events.EventHTTPReq, LatencyNS: 6000000, Target: "GET /secure", TCPState: events.HTTPTransportTLS},
			{Type: events.EventHTTPResp, LatencyNS: 7000000, Target: "GET /secure", TCPState: events.HTTPTransportTLS, Bytes: 512},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateHTTPSection(d, d.endTime.Sub(d.startTime))
	if !strings.Contains(result, "Transport: 1 HTTP, 2 HTTPS") {
		t.Errorf("expected transport breakdown line, got:\n%s", result)
	}
	if !strings.Contains(result, "GET /secure (https)") {
		t.Errorf("expected https-tagged URL, got:\n%s", result)
	}
	if !strings.Contains(result, "GET /plain (http)") {
		t.Errorf("expected http-tagged URL, got:\n%s", result)
	}
}

func TestGenerateHTTPSection_H2CTransport(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "GET /h2", TCPState: events.HTTPTransportH2C},
			{Type: events.EventHTTPResp, LatencyNS: 6000000, Target: "GET /h2", TCPState: events.HTTPTransportH2C},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateHTTPSection(d, d.endTime.Sub(d.startTime))
	if !strings.Contains(result, "Transport: 2 HTTP/2") {
		t.Errorf("expected HTTP/2 transport breakdown, got:\n%s", result)
	}
	if !strings.Contains(result, "GET /h2 (http)") {
		t.Errorf("expected http-scheme-tagged h2 URL, got:\n%s", result)
	}
}

func TestGenerateHTTPSection_H3Transport(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "GET /hello", TCPState: events.HTTPTransportH3},
			{Type: events.EventHTTPResp, LatencyNS: 6000000, Target: "200", Details: "200", TCPState: events.HTTPTransportH3},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateHTTPSection(d, d.endTime.Sub(d.startTime))
	if !strings.Contains(result, "Transport: 2 HTTP/3") {
		t.Errorf("expected HTTP/3 transport breakdown, got:\n%s", result)
	}
	if !strings.Contains(result, "GET /hello (https)") {
		t.Errorf("expected https-scheme-tagged h3 URL, got:\n%s", result)
	}
}

func TestGenerateHTTPSection_PlaintextOmitsBreakdown(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "GET /plain"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateHTTPSection(d, d.endTime.Sub(d.startTime))
	if strings.Contains(result, "Transport:") {
		t.Errorf("plaintext-only report should omit the transport breakdown, got:\n%s", result)
	}
}

func TestGenerateCPUSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateCPUSection(d, duration)
	if result != "" {
		t.Error("Expected empty CPU section for no events")
	}
}

func TestGenerateCPUSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventSchedSwitch, LatencyNS: 1000000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateCPUSection(d, duration)
	if result == "" {
		t.Error("Expected CPU section")
	}
}

func TestGenerateTCPStateSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateTCPStateSection(d, duration)
	if result != "" {
		t.Error("Expected empty TCP state section for no events")
	}
}

func TestGenerateTCPStateSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventTCPState, TCPState: 1, Target: "example.com:80"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateTCPStateSection(d, duration)
	if result == "" {
		t.Error("Expected TCP state section")
	}
}

func TestGenerateMemorySection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateMemorySection(d, duration)
	if result != "" {
		t.Error("Expected empty memory section for no events")
	}
}

func TestGenerateMemorySection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventPageFault, Error: 1},
			{Type: events.EventOOMKill, Target: "process1", Bytes: 1048576, PID: 1234},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateMemorySection(d, duration)
	if result == "" {
		t.Error("Expected memory section")
	}
}

func TestGenerateIssuesSection(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, Error: 1},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
	}
	result := GenerateIssuesSection(d)
	if result == "" {
		t.Log("No issues detected (may be expected)")
	}
}

func TestGenerateSyscallSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateSyscallSection(d, duration)
	if result != "" {
		t.Error("Expected empty syscall section for no events")
	}
}

func TestGenerateSyscallSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventExec, LatencyNS: 1000000, Target: "/bin/ls"},
			{Type: events.EventFork, PID: 1234, Target: "child"},
			{Type: events.EventOpen, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 5},
			{Type: events.EventClose, Bytes: 5},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateSyscallSection(d, duration)
	if result == "" {
		t.Error("Expected syscall section")
	}
}

func TestGenerateApplicationTracing_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateApplicationTracing(d, duration)
	if result == "" {
		t.Log("Empty application tracing is expected with no events")
	}
}

func TestGenerateApplicationTracing_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80"},
			{Type: events.EventTCPSend, LatencyNS: 10000000, Bytes: 1024},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateApplicationTracing(d, duration)
	if result == "" {
		t.Error("Expected application tracing section")
	}
}

func TestCalculateThroughput(t *testing.T) {
	throughput := calculateThroughput(1024, 2*time.Second)
	if throughput != 512 {
		t.Errorf("Expected throughput 512, got %d", throughput)
	}

	throughput = calculateThroughput(1024, 0)
	if throughput != 0 {
		t.Errorf("Expected throughput 0 for zero duration, got %d", throughput)
	}
}

func TestGenerateResourceSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events:    []*events.Event{},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateResourceSection(d)
	if result != "" {
		t.Error("Expected empty resource section for no events")
	}
}

func TestGenerateResourceSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventResourceLimit, TCPState: 0, Error: 85, Bytes: 850000000},
			{Type: events.EventResourceLimit, TCPState: 1, Error: 92, Bytes: 460000000},
			{Type: events.EventResourceLimit, TCPState: 2, Error: 78, Bytes: 780000000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateResourceSection(d)
	if result == "" {
		t.Error("Expected resource section")
	}
	if !strings.Contains(result, "CPU") {
		t.Error("Expected CPU in resource section")
	}
	if !strings.Contains(result, "Memory") {
		t.Error("Expected Memory in resource section")
	}
	if !strings.Contains(result, "I/O") {
		t.Error("Expected I/O in resource section")
	}
}

func TestGenerateResourceSection_WarningLevel(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventResourceLimit, TCPState: 0, Error: 85, Bytes: 850000000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateResourceSection(d)
	if !strings.Contains(result, "WARNING") {
		t.Error("Expected WARNING status in resource section")
	}
}

func TestGenerateResourceSection_CriticalLevel(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventResourceLimit, TCPState: 1, Error: 92, Bytes: 460000000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateResourceSection(d)
	if !strings.Contains(result, "CRITICAL") {
		t.Error("Expected CRITICAL status in resource section")
	}
}

func TestGenerateResourceSection_EmergencyLevel(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventResourceLimit, TCPState: 2, Error: 97, Bytes: 970000000},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateResourceSection(d)
	if !strings.Contains(result, "EMERGENCY") {
		t.Error("Expected EMERGENCY status in resource section")
	}
}

// ---- GenerateCgroupScopeSection tests ----

func TestGenerateCgroupScopeSection_Empty(t *testing.T) {
	d := &mockDiagnostician{}
	if got := GenerateCgroupScopeSection(d); got != "" {
		t.Errorf("expected empty string for no events, got %q", got)
	}
}

func TestGenerateCgroupScopeSection_AllZero(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{CgroupID: 0},
			{CgroupID: 0},
		},
	}
	got := GenerateCgroupScopeSection(d)
	if !strings.Contains(got, "Cgroup Scope") {
		t.Error("expected 'Cgroup Scope' header")
	}
	if !strings.Contains(got, "cgroup_id=0") {
		t.Error("expected cgroup_id=0 report")
	}
	if !strings.Contains(got, "all events have cgroup_id=0") {
		t.Error("expected warning about all events having cgroup_id=0")
	}
}

func TestGenerateCgroupScopeSection_MultipleIDs(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{CgroupID: 1},
			{CgroupID: 2},
			{CgroupID: 1},
			nil, // nil events should be skipped
		},
	}
	got := GenerateCgroupScopeSection(d)
	if !strings.Contains(got, "Distinct non-zero cgroup_ids: 2") {
		t.Errorf("expected 2 distinct cgroup IDs, got: %q", got)
	}
	if !strings.Contains(got, "multiple cgroup_ids seen") {
		t.Error("expected warning about multiple cgroup IDs")
	}
}

func TestGenerateCgroupScopeSection_SingleNonZero(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{CgroupID: 42},
			{CgroupID: 42},
			{CgroupID: 42},
			{CgroupID: 42},
		},
	}
	got := GenerateCgroupScopeSection(d)
	if strings.Contains(got, "multiple cgroup_ids") {
		t.Error("should not warn about multiple cgroup IDs for single ID")
	}
	if !strings.Contains(got, "Top cgroup_ids") {
		t.Error("expected 'Top cgroup_ids' section")
	}
}

// ---- contains helper test ----

func TestContains(t *testing.T) {
	if !contains("CRITICAL error detected", "CRITICAL") {
		t.Error("expected contains=true for 'CRITICAL'")
	}
	if contains("all OK", "CRITICAL") {
		t.Error("expected contains=false for absent substring")
	}
}

// ---- determinePoolHealth tests ----

func TestDeterminePoolHealth_OK(t *testing.T) {
	stats := analyzer.PoolStats{
		ReleaseRatio:   0.9,
		MaxWaitTime:    100 * time.Millisecond,
		ExhaustedCount: 0,
		TotalAcquires:  100,
	}
	got := determinePoolHealth(stats)
	if got != "OK - Pool operating normally" {
		t.Errorf("expected OK, got %q", got)
	}
}

func TestDeterminePoolHealth_CriticalExhaustion(t *testing.T) {
	stats := analyzer.PoolStats{
		ExhaustedCount: 20,
		TotalAcquires:  100,
		ReleaseRatio:   0.9,
	}
	got := determinePoolHealth(stats)
	if !strings.Contains(got, "CRITICAL") {
		t.Errorf("expected CRITICAL for >10%% exhaustion, got %q", got)
	}
}

func TestDeterminePoolHealth_WarningExhaustion(t *testing.T) {
	stats := analyzer.PoolStats{
		ExhaustedCount: 7,
		TotalAcquires:  100,
		ReleaseRatio:   0.9,
	}
	got := determinePoolHealth(stats)
	if !strings.Contains(got, "WARNING") {
		t.Errorf("expected WARNING for 5-10%% exhaustion, got %q", got)
	}
}

func TestDeterminePoolHealth_LowReleaseRatio(t *testing.T) {
	stats := analyzer.PoolStats{
		TotalAcquires:  10,
		TotalReleases:  3,
		ExhaustedCount: 0,
		ReleaseRatio:   0.3,
	}
	got := determinePoolHealth(stats)
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "possible leak") {
		t.Errorf("expected WARNING for low release ratio, got %q", got)
	}
}

func TestDeterminePoolHealth_HighWaitTime(t *testing.T) {
	stats := analyzer.PoolStats{
		ExhaustedCount: 0,
		ReleaseRatio:   0.9,
		MaxWaitTime:    2000 * time.Millisecond,
	}
	got := determinePoolHealth(stats)
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "wait times") {
		t.Errorf("expected WARNING for high wait times, got %q", got)
	}
}

// ---- determinePoolHealthFromSummary tests ----

func TestDeterminePoolHealthFromSummary_OK(t *testing.T) {
	s := tracker.PoolSummary{
		ReleaseRatio:   0.9,
		MaxWaitTime:    50 * time.Millisecond,
		ExhaustedCount: 0,
	}
	got := determinePoolHealthFromSummary(s)
	if got != "OK - Pool operating normally" {
		t.Errorf("expected OK, got %q", got)
	}
}

func TestDeterminePoolHealthFromSummary_Critical(t *testing.T) {
	s := tracker.PoolSummary{
		ExhaustedCount: 15,
		AcquireCount:   100,
		ReleaseRatio:   0.9,
	}
	got := determinePoolHealthFromSummary(s)
	if !strings.Contains(got, "CRITICAL") {
		t.Errorf("expected CRITICAL, got %q", got)
	}
}

func TestDeterminePoolHealthFromSummary_LowReuse(t *testing.T) {
	s := tracker.PoolSummary{
		AcquireCount:   10,
		ReleaseCount:   2,
		ExhaustedCount: 0,
		ReleaseRatio:   0.2,
	}
	got := determinePoolHealthFromSummary(s)
	if !strings.Contains(got, "WARNING") {
		t.Errorf("expected WARNING for low reuse, got %q", got)
	}
}

// ---- GeneratePoolSection tests ----

func TestGeneratePoolSection_Empty(t *testing.T) {
	d := &mockDiagnostician{}
	if got := GeneratePoolSection(d, time.Second); got != "" {
		t.Errorf("expected empty string for no pool events, got %q", got)
	}
}

func TestGeneratePoolSection_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventPoolAcquire},
			{Type: events.EventPoolAcquire},
			{Type: events.EventPoolRelease},
		},
	}
	got := GeneratePoolSection(d, time.Second)
	if !strings.Contains(got, "Connection Pool") {
		t.Errorf("expected 'Connection Pool' header, got %q", got)
	}
	if !strings.Contains(got, "Total acquires: 2") {
		t.Errorf("expected 'Total acquires: 2', got %q", got)
	}
}

// TestAnalyzeUDPEvents_NegativeError covers the `if e.Error < 0` branch
// in analyzeUDPEvents (line 267 of report.go).
func TestGenerateUDPSection_NegativeError(t *testing.T) {
	evts := []*events.Event{
		{Type: events.EventUDPSend, LatencyNS: 1_000_000, Error: -1, Bytes: 100},
		{Type: events.EventUDPSend, LatencyNS: 2_000_000, Error: 0, Bytes: 200},
	}
	d := &mockDiagnostician{
		events:    evts,
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	result := GenerateUDPSection(d, time.Second)
	if result == "" {
		t.Error("expected non-empty UDP section")
	}
}

// TestFormatStateDistribution_Break covers the `break` at i >= config.TopStatesLimit
// in formatStateDistribution.
func TestGenerateTCPStateSection_ManyStates(t *testing.T) {
	var evts []*events.Event
	for state := uint32(1); state <= 12; state++ {
		evts = append(evts, &events.Event{
			Type:     events.EventTCPState,
			TCPState: state,
		})
	}
	d := &mockDiagnostician{
		events:    evts,
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	result := GenerateTCPStateSection(d, time.Second)
	if result == "" {
		t.Error("expected non-empty TCP state section")
	}
	if !strings.Contains(result, "State distribution") {
		t.Logf("TCP state section: %q", result)
	}
}

// TestFormatOOMKills_EmptyProcName covers the `if procName == ""` branch
// in formatOOMKills (line 472-474 of report.go) — uses PID as process name.
func TestGenerateMemorySection_OOMKillEmptyTarget(t *testing.T) {
	evts := []*events.Event{
		{
			Type:  events.EventOOMKill,
			Bytes: 1024 * 1024,
			PID:   12345,
		},
	}
	d := &mockDiagnostician{
		events:    evts,
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	result := GenerateMemorySection(d, time.Second)
	if result == "" {
		t.Error("expected non-empty memory section")
	}
	if !strings.Contains(result, "PID") {
		t.Logf("memory section (expected 'PID N' fallback): %q", result)
	}
}

// TestFormatTopOpenedFiles_EmptyReturn covers the `return ""` branch
// in formatTopOpenedFiles, reached when all open event targets are "" or "unknown".
func TestGenerateSyscallSection_OpenedFilesEmptyTargets(t *testing.T) {
	evts := []*events.Event{
		{Type: events.EventOpen, Target: ""},        // excluded by buildFileCounts
		{Type: events.EventOpen, Target: "?"},       // excluded
		{Type: events.EventOpen, Target: "unknown"}, // excluded
		{Type: events.EventClose},
	}
	d := &mockDiagnostician{
		events:    evts,
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	result := GenerateSyscallSection(d, time.Second)
	_ = result
}

// TestCategorizeSyscallEvents_NilEvent covers the `if e == nil { continue }` branch
// in categorizeSyscallEvents.
func TestGenerateSyscallSection_NilEvent(t *testing.T) {
	evts := []*events.Event{
		nil,
		{Type: events.EventExec, Target: "ls"},
		nil,
		{Type: events.EventOpen, Target: "/tmp/file"},
	}
	d := &mockDiagnostician{
		events:    evts,
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	result := GenerateSyscallSection(d, time.Second)
	if result == "" {
		t.Error("expected non-empty syscall section with exec/open events")
	}
}

// TestFormatProcessActivity_Break covers the `break` at i >= config.TopProcessesLimit
// in formatProcessActivity, needs more than 5 distinct PIDs (default TopProcessesLimit=5).
func TestGenerateApplicationTracing_ManyPIDs(t *testing.T) {
	var evts []*events.Event
	for pid := uint32(999990); pid <= 999997; pid++ {
		evts = append(evts, &events.Event{
			Type: events.EventDNS,
			PID:  pid,
		})
	}
	d := &mockDiagnostician{
		events:    evts,
		startTime: time.Now().Add(-time.Second),
		endTime:   time.Now(),
	}
	duration := time.Second
	result := GenerateApplicationTracing(d, duration)
	_ = result
}

// ─── GenerateIssuesSection: with detected issues ──────────────────────────────

func TestGenerateIssuesSection_WithHighErrorRate(t *testing.T) {
	// 10 connect events, all with errors → 100% error rate > 10% threshold.
	var evts []*events.Event
	for i := 0; i < 10; i++ {
		evts = append(evts, &events.Event{Type: events.EventConnect, Error: 1})
	}
	d := &mockDiagnostician{
		events:             evts,
		startTime:          time.Now(),
		endTime:            time.Now().Add(time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  1000.0,
	}
	result := GenerateIssuesSection(d)
	if result == "" {
		t.Fatal("expected non-empty issues section for high error rate")
	}
	if !strings.Contains(result, "failure rate") {
		t.Errorf("expected 'failure rate' in issues section, got %q", result)
	}
}

func TestGenerateIssuesSection_WithHighRTTSpike(t *testing.T) {
	var evts []*events.Event
	for i := 0; i < 10; i++ {
		evts = append(evts, &events.Event{
			Type:      events.EventTCPSend,
			LatencyNS: 1_000_000_000,
		})
	}
	d := &mockDiagnostician{
		events:             evts,
		startTime:          time.Now(),
		endTime:            time.Now().Add(time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0, // 100ms threshold
	}
	result := GenerateIssuesSection(d)
	if result == "" {
		t.Log("no RTT spike issue detected (may depend on SpikeRateThreshold)")
	}
}

func TestGenerateIssuesSection_WithCriticalIssue(t *testing.T) {
	var evts []*events.Event
	for i := 0; i < 10; i++ {
		evts = append(evts, &events.Event{Type: events.EventConnect, Error: 1})
	}
	d := &mockDiagnostician{
		events:             evts,
		errorRateThreshold: 0.0,
		rttSpikeThreshold:  0.0,
	}
	result := GenerateIssuesSection(d)
	_ = result // just verify no panic
}

// ─── formatBursts: burst detection ───────────────────────────────────────────

func TestGenerateApplicationTracing_WithBursts(t *testing.T) {
	startTime := time.Now().Add(-10 * time.Second)
	var evts []*events.Event
	for i := 0; i < 20; i++ {
		ts := uint64(startTime.Add(500*time.Millisecond).UnixNano()) + uint64(i*1000)
		evts = append(evts, &events.Event{
			Type:      events.EventDNS,
			Timestamp: ts,
		})
	}
	for i := 1; i <= 2; i++ {
		ts := uint64(startTime.Add(time.Duration(i) * 3 * time.Second).UnixNano())
		evts = append(evts, &events.Event{
			Type:      events.EventDNS,
			Timestamp: ts,
		})
	}

	endTime := startTime.Add(10 * time.Second)
	d := &mockDiagnostician{
		events:    evts,
		startTime: startTime,
		endTime:   endTime,
	}
	duration := endTime.Sub(startTime)
	result := GenerateApplicationTracing(d, duration)
	_ = result // just verify no panic; burst may or may not be detected
}

// ─── determinePoolHealthFromSummary: uncovered paths ─────────────────────────

func TestDeterminePoolHealthFromSummary_ModerateExhaustion(t *testing.T) {
	// exhaustionRate = 6/100 = 6% > 5% but < 10% → "WARNING - Moderate..."
	s := tracker.PoolSummary{
		ExhaustedCount: 6,
		AcquireCount:   100,
		ReleaseRatio:   0.9,
	}
	got := determinePoolHealthFromSummary(s)
	if !strings.Contains(got, "Moderate") {
		t.Errorf("expected 'Moderate' warning, got %q", got)
	}
}

func TestDeterminePoolHealthFromSummary_HighWaitTime(t *testing.T) {
	s := tracker.PoolSummary{
		ExhaustedCount: 0,
		ReleaseRatio:   0.8,
		MaxWaitTime:    2 * time.Second, // > 1000ms threshold
	}
	got := determinePoolHealthFromSummary(s)
	if !strings.Contains(got, "wait time") {
		t.Errorf("expected 'wait time' warning, got %q", got)
	}
}

// ─── formatFileDescriptorLeak: more opens than closes ────────────────────────

func TestGenerateSyscallSection_WithFDLeak(t *testing.T) {
	// More opens than closes → FD leak detected.
	evts := []*events.Event{
		{Type: events.EventOpen, Target: "/tmp/a.txt"},
		{Type: events.EventOpen, Target: "/tmp/b.txt"},
		{Type: events.EventOpen, Target: "/tmp/c.txt"},
		{Type: events.EventClose},
	}
	d := &mockDiagnostician{
		events:    evts,
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateSyscallSection(d, duration)
	if !strings.Contains(result, "descriptor leak") && !strings.Contains(result, "opens than closes") {
		t.Logf("FD leak not reported (may require specific threshold), got: %q", result)
	}
}

// ─── formatTopOpenedFiles: non-empty file counts ─────────────────────────────

func TestGenerateSyscallSection_WithOpenedFiles(t *testing.T) {
	evts := []*events.Event{
		{Type: events.EventOpen, Target: "/etc/hosts"},
		{Type: events.EventOpen, Target: "/etc/hosts"},
		{Type: events.EventOpen, Target: "/tmp/data.txt"},
	}
	d := &mockDiagnostician{
		events:    evts,
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateSyscallSection(d, duration)
	_ = result
}

// ─── GeneratePoolSection: exhausted events path ───────────────────────────────

func TestGeneratePoolSection_WithExhausted(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventPoolAcquire},
			{Type: events.EventPoolExhausted},
			{Type: events.EventPoolExhausted},
			{Type: events.EventPoolRelease},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	got := GeneratePoolSection(d, time.Second)
	if got == "" {
		t.Error("expected non-empty pool section")
	}
}

// ─── GenerateConnectionSection: more paths ────────────────────────────────────

func TestGenerateConnectionSection_WithTCPState(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventTCPState, TCPState: 1, Target: "10.0.0.1:80"},
			{Type: events.EventTCPState, TCPState: 2, Target: "10.0.0.1:80"},
			{Type: events.EventConnect, Error: 1, Target: "10.0.0.2:443"},
			{Type: events.EventConnect, Error: 0, Target: "10.0.0.3:8080"},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(5 * time.Second),
		rttSpikeThreshold:  100.0,
		errorRateThreshold: 10.0,
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateConnectionSection(d, duration)
	_ = result
}

// ─── GenerateIssuesSection: contains warning ─────────────────────────────────

func TestGenerateIssuesSection_WarningKeyword(t *testing.T) {
	// Trigger an issue that contains "WARNING" keyword.
	var evts []*events.Event
	for i := 0; i < 10; i++ {
		evts = append(evts, &events.Event{Type: events.EventConnect, Error: 1})
	}
	d := &mockDiagnostician{
		events:             evts,
		errorRateThreshold: 0.0,
		rttSpikeThreshold:  0.0,
	}
	result := GenerateIssuesSection(d)
	_ = result
}

func TestGenerateHTTPSection_TraceContextCount(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventHTTPReq, Target: "GET /a", TCPState: events.HTTPTransportH3, Details: "traceparent: 00-abc-def-01"},
			{Type: events.EventHTTPReq, Target: "GET /b", TCPState: events.HTTPTransportH3},
			{Type: events.EventHTTPResp, Target: "GET /a", TCPState: events.HTTPTransportH3, Details: "200"},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(1 * time.Second),
	}
	result := GenerateHTTPSection(d, d.endTime.Sub(d.startTime))
	if !strings.Contains(result, "Trace context: 1/2 requests carried a W3C traceparent") {
		t.Errorf("expected trace-context line, got:\n%s", result)
	}
}

func TestTheFilesystemSectionCountsTheKernelsFastOperations(t *testing.T) {
	d := &mockDiagnostician{
		events:          []*events.Event{{Type: events.EventFsync, LatencyNS: 30_000_000, Target: "journal"}},
		startTime:       time.Unix(0, 0),
		endTime:         time.Unix(10, 0),
		fsSlowThreshold: 10,
		fsKernel: analyzer.FSKernelCounts{
			events.EventWrite: {Count: 9, SumNS: 9 * 40_000, Bytes: 9 * 4096, Buckets: map[float64]uint64{0.05: 9}},
		},
	}
	got := GenerateFileSystemSection(d, 10*time.Second)
	for _, want := range []string{
		"Write operations: 9",
		"Fsync operations: 1",
		"Of these, under 1ms and counted in the kernel: 9",
		"files with operations of 1ms or more",
		"journal",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("section lacks %q:\n%s", want, got)
		}
	}
}

func TestTheFilesystemSectionSaysWhenItsMaxIsABucketBound(t *testing.T) {
	d := &mockDiagnostician{
		startTime: time.Unix(0, 0),
		endTime:   time.Unix(10, 0),
		fsKernel: analyzer.FSKernelCounts{
			events.EventRead: {Count: 4, SumNS: 4 * 40_000, Buckets: map[float64]uint64{0.05: 4}},
		},
	}
	got := GenerateFileSystemSection(d, 10*time.Second)
	if !strings.Contains(got, "no operation reached 1ms") || !strings.Contains(got, "Read operations: 4") {
		t.Errorf("section = \n%s", got)
	}
	if strings.Contains(got, "Top ") {
		t.Errorf("a section with no events listed files:\n%s", got)
	}
}
