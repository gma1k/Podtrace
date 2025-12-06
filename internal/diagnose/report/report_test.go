package report

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

type mockDiagnostician struct {
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
		events: []*events.Event{},
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
		events: []*events.Event{},
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
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		rttSpikeThreshold:  100.0,
	}
	duration := d.endTime.Sub(d.startTime)
	result := GenerateTCPSection(d, duration)
	if result == "" {
		t.Error("Expected TCP section")
	}
}

func TestGenerateConnectionSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
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
		events: []*events.Event{},
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
		startTime:        time.Now(),
		endTime:          time.Now().Add(1 * time.Second),
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
		events: []*events.Event{},
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
		events: []*events.Event{},
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

func TestGenerateCPUSection_Empty(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{},
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
		events: []*events.Event{},
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
		events: []*events.Event{},
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
		events: []*events.Event{},
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
		events: []*events.Event{},
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

