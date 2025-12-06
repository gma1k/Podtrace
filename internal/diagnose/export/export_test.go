package export

import (
	"bytes"
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

func TestExportJSON_EmptyEvents(t *testing.T) {
	d := &mockDiagnostician{
		events:             []*events.Event{},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.Summary == nil {
		t.Error("Expected summary in export data")
	}
	if data.Summary["total_events"].(int) != 0 {
		t.Error("Expected 0 total events")
	}
}

func TestExportJSON_WithDNSEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 1000000, Target: "example.com"},
			{Type: events.EventDNS, LatencyNS: 2000000, Target: "example.com", Error: 1},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.DNS == nil {
		t.Error("Expected DNS data")
	}
	if data.DNS["total_lookups"].(int) != 2 {
		t.Error("Expected 2 DNS lookups")
	}
}

func TestExportJSON_WithTCPEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventTCPSend, LatencyNS: 1000000, Bytes: 1024},
			{Type: events.EventTCPRecv, LatencyNS: 2000000, Bytes: 2048},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.TCP == nil {
		t.Error("Expected TCP data")
	}
}

func TestExportJSON_WithConnectionEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80"},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.Connections == nil {
		t.Error("Expected Connections data")
	}
}

func TestExportJSON_WithFSEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 4096},
			{Type: events.EventWrite, LatencyNS: 3000000, Target: "/tmp/file2", Bytes: 2048},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.FileSystem == nil {
		t.Error("Expected FileSystem data")
	}
}

func TestExportJSON_WithCPUEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventSchedSwitch, LatencyNS: 1000000},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	data := ExportJSON(d)
	if data.CPU == nil {
		t.Error("Expected CPU data")
	}
}

func TestExportCSV_EmptyEvents(t *testing.T) {
	d := &mockDiagnostician{
		events:             []*events.Event{},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	var buf bytes.Buffer
	err := ExportCSV(d, &buf)
	if err != nil {
		t.Errorf("ExportCSV should not return error, got %v", err)
	}
	if buf.Len() == 0 {
		t.Error("Expected CSV header")
	}
}

func TestExportCSV_WithEvents(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 1000000, Target: "example.com", PID: 1234, ProcessName: "test", Timestamp: 1000, Error: 0},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	var buf bytes.Buffer
	err := ExportCSV(d, &buf)
	if err != nil {
		t.Errorf("ExportCSV should not return error, got %v", err)
	}
	if buf.Len() == 0 {
		t.Error("Expected CSV output")
	}
}

func TestExportCSV_NilEvent(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			nil,
			{Type: events.EventDNS, LatencyNS: 1000000, Target: "example.com", PID: 1234, ProcessName: "test", Timestamp: 1000},
		},
		startTime:          time.Now(),
		endTime:            time.Now().Add(1 * time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  100.0,
		fsSlowThreshold:    10.0,
	}

	var buf bytes.Buffer
	err := ExportCSV(d, &buf)
	if err != nil {
		t.Errorf("ExportCSV should not return error with nil event, got %v", err)
	}
}

func TestCalculateRate(t *testing.T) {
	rate := calculateRate(100, 10*time.Second)
	if rate != 10.0 {
		t.Errorf("Expected rate 10.0, got %.2f", rate)
	}

	rate = calculateRate(0, 10*time.Second)
	if rate != 0.0 {
		t.Errorf("Expected rate 0.0, got %.2f", rate)
	}

	rate = calculateRate(100, 0)
	if rate != 0.0 {
		t.Errorf("Expected rate 0.0 for zero duration, got %.2f", rate)
	}
}

