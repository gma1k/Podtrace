package diagnose

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestNewDiagnostician(t *testing.T) {
	d := NewDiagnostician()

	if d == nil {
		t.Fatal("NewDiagnostician returned nil")
	}

	events := d.GetEvents()
	if len(events) != 0 {
		t.Errorf("Expected empty events, got %d", len(events))
	}

	if d.errorRateThreshold != 10.0 {
		t.Errorf("Expected error rate threshold 10.0, got %.2f", d.errorRateThreshold)
	}

	if d.rttSpikeThreshold != 100.0 {
		t.Errorf("Expected RTT spike threshold 100.0, got %.2f", d.rttSpikeThreshold)
	}
}

func TestNewDiagnosticianWithThresholds(t *testing.T) {
	d := NewDiagnosticianWithThresholds(5.0, 50.0, 5.0)

	if d.errorRateThreshold != 5.0 {
		t.Errorf("Expected error rate threshold 5.0, got %.2f", d.errorRateThreshold)
	}

	if d.rttSpikeThreshold != 50.0 {
		t.Errorf("Expected RTT spike threshold 50.0, got %.2f", d.rttSpikeThreshold)
	}

	if d.fsSlowThreshold != 5.0 {
		t.Errorf("Expected FS slow threshold 5.0, got %.2f", d.fsSlowThreshold)
	}
}

func TestAddEvent(t *testing.T) {
	d := NewDiagnostician()

	event1 := &events.Event{Type: events.EventDNS, PID: 1}
	event2 := &events.Event{Type: events.EventConnect, PID: 2}

	d.AddEvent(event1)
	events := d.GetEvents()
	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}

	d.AddEvent(event2)
	events = d.GetEvents()
	if len(events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(events))
	}
}

func TestFinish(t *testing.T) {
	d := NewDiagnostician()
	startTime := d.startTime

	time.Sleep(10 * time.Millisecond)
	d.Finish()

	if d.endTime.Before(startTime) {
		t.Error("End time should be after start time")
	}

	if d.endTime.IsZero() {
		t.Error("End time should be set")
	}
}

func TestGenerateReport_NoEvents(t *testing.T) {
	d := NewDiagnostician()
	d.Finish()

	report := d.GenerateReport()

	if report == "" {
		t.Error("Report should not be empty even with no events")
	}

	if !strings.Contains(report, "No events collected") {
		t.Errorf("Report should indicate no events, got: %s", report)
	}
}

func TestGenerateReport_WithEvents(t *testing.T) {
	d := NewDiagnostician()

	d.AddEvent(&events.Event{
		Type:      events.EventDNS,
		LatencyNS: 5000000,
		Target:    "example.com",
		Error:     0,
	})

	d.AddEvent(&events.Event{
		Type:      events.EventConnect,
		LatencyNS: 10000000,
		Target:    "example.com:80",
		Error:     0,
	})

	d.Finish()

	report := d.GenerateReport()

	if report == "" {
		t.Error("Report should not be empty")
	}

	if !strings.Contains(report, "Diagnostic Report") {
		t.Errorf("Report should contain 'Diagnostic Report', got: %s", report[:100])
	}
}

func TestFilterEvents(t *testing.T) {
	d := NewDiagnostician()

	d.AddEvent(&events.Event{Type: events.EventDNS})
	d.AddEvent(&events.Event{Type: events.EventConnect})
	d.AddEvent(&events.Event{Type: events.EventDNS})
	d.AddEvent(&events.Event{Type: events.EventTCPSend})

	dnsEvents := d.filterEvents(events.EventDNS)
	if len(dnsEvents) != 2 {
		t.Errorf("Expected 2 DNS events, got %d", len(dnsEvents))
	}

	connectEvents := d.filterEvents(events.EventConnect)
	if len(connectEvents) != 1 {
		t.Errorf("Expected 1 Connect event, got %d", len(connectEvents))
	}
}

func TestExportJSON(t *testing.T) {
	d := NewDiagnostician()

	d.AddEvent(&events.Event{
		Type:      events.EventDNS,
		LatencyNS: 5000000,
		Target:    "example.com",
		Error:     0,
	})

	d.Finish()

	data := d.ExportJSON()

	if data.Summary == nil {
		t.Error("ExportJSON should return summary")
	}

	if data.Summary["total_events"] != 1 {
		t.Errorf("Expected 1 total event, got %v", data.Summary["total_events"])
	}

	if data.DNS == nil {
		t.Error("ExportJSON should include DNS data when DNS events are present")
	}
}

func TestExportJSON_Empty(t *testing.T) {
	d := NewDiagnostician()
	d.Finish()

	data := d.ExportJSON()

	if data.Summary == nil {
		t.Error("ExportJSON should return summary even with no events")
	}

	if data.Summary["total_events"] != 0 {
		t.Errorf("Expected 0 total events, got %v", data.Summary["total_events"])
	}
}

func TestExportCSV(t *testing.T) {
	d := NewDiagnostician()

	d.AddEvent(&events.Event{
		Type:        events.EventDNS,
		PID:         1234,
		ProcessName: "test",
		LatencyNS:   5000000,
		Error:       0,
		Target:      "example.com",
	})

	d.Finish()

	var buf []byte
	writer := &testWriter{data: &buf}
	err := d.ExportCSV(writer)

	if err != nil {
		t.Errorf("ExportCSV should not return error, got %v", err)
	}

	if len(buf) == 0 {
		t.Error("ExportCSV should write data")
	}
}

func BenchmarkAddEvent(b *testing.B) {
	d := NewDiagnostician()
	event := &events.Event{Type: events.EventDNS}

	// Pre-allocate to avoid allocation overhead during benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.AddEvent(event)
	}
}

func BenchmarkGenerateReport(b *testing.B) {
	d := NewDiagnostician()
	// Pre-allocate eventSlice to avoid allocation during benchmark
	eventSlice := make([]*events.Event, 1000)
	for i := range eventSlice {
		eventSlice[i] = &events.Event{
			Type:      events.EventDNS,
			LatencyNS: uint64(i * 1000000),
			Target:    "example.com",
		}
	}
	for _, e := range eventSlice {
		d.AddEvent(e)
	}
	d.Finish()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.GenerateReport()
	}
}

func BenchmarkFilterEvents(b *testing.B) {
	d := NewDiagnostician()
	// Pre-allocate events to avoid allocation overhead
	eventTypes := []events.EventType{events.EventDNS, events.EventConnect}
	for i := 0; i < 1000; i++ {
		d.AddEvent(&events.Event{Type: eventTypes[i%2]})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.filterEvents(events.EventDNS)
	}
}

func BenchmarkExportJSON(b *testing.B) {
	d := NewDiagnostician()
	// Pre-allocate eventSlice to avoid variable shadowing
	eventSlice := make([]*events.Event, 100)
	for i := range eventSlice {
		eventSlice[i] = &events.Event{
			Type:      events.EventDNS,
			LatencyNS: uint64(i * 1000000),
			Target:    "example.com",
		}
	}
	for _, e := range eventSlice {
		d.AddEvent(e)
	}
	d.Finish()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.ExportJSON()
	}
}

// Helper functions
type testWriter struct {
	data *[]byte
}

func (w *testWriter) Write(p []byte) (n int, err error) {
	*w.data = append(*w.data, p...)
	return len(p), nil
}

func TestDiagnostician_CalculateRate(t *testing.T) {
	d := NewDiagnostician()

	tests := []struct {
		name     string
		count    int
		duration time.Duration
		expected float64
	}{
		{"zero duration", 10, 0, 0},
		{"1 second", 10, 1 * time.Second, 10.0},
		{"2 seconds", 20, 2 * time.Second, 10.0},
		{"half second", 5, 500 * time.Millisecond, 10.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.calculateRate(tt.count, tt.duration)
			if result != tt.expected {
				t.Errorf("Expected %.2f, got %.2f", tt.expected, result)
			}
		})
	}
}

func TestDiagnostician_GenerateSummarySection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS})
	d.AddEvent(&events.Event{Type: events.EventConnect})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateSummarySection(duration)

	if !strings.Contains(result, "Diagnostic Report") {
		t.Error("Expected summary to contain 'Diagnostic Report'")
	}
	if !strings.Contains(result, "Total events") {
		t.Error("Expected summary to contain 'Total events'")
	}
}

func TestDiagnostician_GenerateDNSSection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com", Error: 0})
	d.AddEvent(&events.Event{Type: events.EventDNS, LatencyNS: 10000000, Target: "test.com", Error: 0})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateDNSSection(duration)

	if !strings.Contains(result, "DNS Statistics") {
		t.Error("Expected DNS section to contain 'DNS Statistics'")
	}
}

func TestDiagnostician_GenerateDNSSection_Empty(t *testing.T) {
	d := NewDiagnostician()
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateDNSSection(duration)

	if result != "" {
		t.Error("Expected empty DNS section for no DNS events")
	}
}

func TestDiagnostician_GenerateTCPSection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventTCPSend, LatencyNS: 5000000, Bytes: 1024})
	d.AddEvent(&events.Event{Type: events.EventTCPRecv, LatencyNS: 10000000, Bytes: 2048})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateTCPSection(duration)

	if !strings.Contains(result, "TCP Statistics") {
		t.Error("Expected TCP section to contain 'TCP Statistics'")
	}
}

func TestDiagnostician_GenerateConnectionSection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80", Error: 0})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateConnectionSection(duration)

	if !strings.Contains(result, "Connection Statistics") {
		t.Error("Expected connection section to contain 'Connection Statistics'")
	}
}

func TestDiagnostician_GenerateFileSystemSection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 4096})
	d.AddEvent(&events.Event{Type: events.EventWrite, LatencyNS: 3000000, Target: "/tmp/file2", Bytes: 2048})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateFileSystemSection(duration)

	if !strings.Contains(result, "File System Statistics") {
		t.Error("Expected FS section to contain 'File System Statistics'")
	}
}

func TestDiagnostician_GenerateUDPSection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventUDPSend, LatencyNS: 1000000, Bytes: 512})
	d.AddEvent(&events.Event{Type: events.EventUDPRecv, LatencyNS: 2000000, Bytes: 1024})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateUDPSection(duration)

	if !strings.Contains(result, "UDP Statistics") {
		t.Error("Expected UDP section to contain 'UDP Statistics'")
	}
}

func TestDiagnostician_GenerateHTTPSection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "http://example.com"})
	d.AddEvent(&events.Event{Type: events.EventHTTPResp, LatencyNS: 10000000, Target: "http://example.com", Bytes: 2048})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateHTTPSection(duration)

	if !strings.Contains(result, "HTTP Statistics") {
		t.Error("Expected HTTP section to contain 'HTTP Statistics'")
	}
}

func TestDiagnostician_GenerateCPUSection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventSchedSwitch, LatencyNS: 1000000})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateCPUSection(duration)

	if !strings.Contains(result, "CPU Statistics") {
		t.Error("Expected CPU section to contain 'CPU Statistics'")
	}
}

func TestDiagnostician_GenerateTCPStateSection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventTCPState, TCPState: 1, Target: "example.com:80"})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateTCPStateSection(duration)

	if !strings.Contains(result, "TCP Connection State Tracking") {
		t.Error("Expected TCP state section to contain 'TCP Connection State Tracking'")
	}
}

func TestDiagnostician_GenerateMemorySection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventPageFault, Error: 1})
	d.AddEvent(&events.Event{Type: events.EventOOMKill, Target: "process", Bytes: 1048576})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateMemorySection(duration)

	if !strings.Contains(result, "Memory Statistics") {
		t.Error("Expected memory section to contain 'Memory Statistics'")
	}
}

func TestDiagnostician_GenerateIssuesSection(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS, Error: 1})
	d.Finish()

	result := d.generateIssuesSection()
	if result == "" {
		t.Log("No issues detected (may be expected)")
	}
}

func TestDiagnostician_ExportCSV_Empty(t *testing.T) {
	d := NewDiagnostician()
	d.Finish()

	var buf bytes.Buffer
	err := d.ExportCSV(&buf)

	if err != nil {
		t.Errorf("ExportCSV should not return error, got %v", err)
	}

	if buf.Len() == 0 {
		t.Error("ExportCSV should write header even for empty events")
	}
}

func TestDiagnostician_ExportCSV_WithEvents(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{
		Type:        events.EventDNS,
		PID:         1234,
		ProcessName: "test",
		LatencyNS:   5000000,
		Error:       0,
		Target:      "example.com",
	})
	d.Finish()

	var buf bytes.Buffer
	err := d.ExportCSV(&buf)

	if err != nil {
		t.Errorf("ExportCSV should not return error, got %v", err)
	}

	if buf.Len() == 0 {
		t.Error("ExportCSV should write data")
	}

	if !strings.Contains(buf.String(), "timestamp") {
		t.Error("Expected CSV to contain header")
	}
}

func TestDiagnostician_ExportJSON_WithAllEventTypes(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"})
	d.AddEvent(&events.Event{Type: events.EventTCPSend, LatencyNS: 10000000, Bytes: 1024})
	d.AddEvent(&events.Event{Type: events.EventTCPRecv, LatencyNS: 15000000, Bytes: 2048})
	d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 2000000, Target: "example.com:80"})
	d.AddEvent(&events.Event{Type: events.EventRead, LatencyNS: 3000000, Target: "/tmp/file", Bytes: 4096})
	d.AddEvent(&events.Event{Type: events.EventWrite, LatencyNS: 4000000, Target: "/tmp/file2", Bytes: 2048})
	d.AddEvent(&events.Event{Type: events.EventFsync, LatencyNS: 5000000, Target: "/tmp/file3"})
	d.AddEvent(&events.Event{Type: events.EventSchedSwitch, LatencyNS: 1000000})
	d.Finish()

	data := d.ExportJSON()

	if data.Summary == nil {
		t.Error("Expected summary in JSON export")
	}

	if data.Summary["total_events"] != 8 {
		t.Errorf("Expected 8 events, got %v", data.Summary["total_events"])
	}
}
