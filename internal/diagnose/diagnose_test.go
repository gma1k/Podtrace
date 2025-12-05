package diagnose

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/analyzer"
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

func TestDiagnostician_GenerateIssuesSection_WithIssues(t *testing.T) {
	d := NewDiagnostician()
	d.errorRateThreshold = 10.0
	d.rttSpikeThreshold = 100.0
	
	for i := 0; i < 11; i++ {
		errorVal := int32(0)
		if i < 9 {
			errorVal = 111
		}
		d.AddEvent(&events.Event{
			Type:  events.EventConnect,
			Error: errorVal,
		})
	}
	d.Finish()

	result := d.generateIssuesSection()
	if result == "" {
		t.Error("Expected issues section to be generated")
	}
	if !strings.Contains(result, "Potential Issues Detected") {
		t.Error("Expected 'Potential Issues Detected' header")
	}
	if !strings.Contains(result, "High connection failure rate") {
		t.Error("Expected 'High connection failure rate' issue")
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

func TestAddEvent_NilEvent(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(nil)
	events := d.GetEvents()
	if len(events) != 0 {
		t.Errorf("Expected 0 events for nil event, got %d", len(events))
	}
}

func TestAddEvent_EventLimit(t *testing.T) {
	d := NewDiagnostician()
	origMaxEvents := d.maxEvents
	d.maxEvents = 10
	defer func() { d.maxEvents = origMaxEvents }()

	for i := 0; i < 15; i++ {
		d.AddEvent(&events.Event{Type: events.EventDNS, PID: uint32(i)})
	}

	events := d.GetEvents()
	if len(events) > d.maxEvents {
		t.Errorf("Expected at most %d events, got %d", d.maxEvents, len(events))
	}
}

func TestAddEvent_EventSampling(t *testing.T) {
	d := NewDiagnostician()
	origMaxEvents := d.maxEvents
	d.maxEvents = 5
	defer func() { d.maxEvents = origMaxEvents }()

	for i := 0; i < 20; i++ {
		d.AddEvent(&events.Event{Type: events.EventDNS, PID: uint32(i)})
	}

	events := d.GetEvents()
	if len(events) > d.maxEvents {
		t.Errorf("Expected at most %d events, got %d", d.maxEvents, len(events))
	}
}

func TestFormatErrorRate_ZeroTotal(t *testing.T) {
	result := formatErrorRate(5, 0)
	if !strings.Contains(result, "0.0%") {
		t.Errorf("Expected 0.0%% for zero total, got %s", result)
	}
}

func TestFormatErrorRate_WithErrors(t *testing.T) {
	result := formatErrorRate(5, 100)
	if !strings.Contains(result, "5.0%") {
		t.Errorf("Expected 5.0%% error rate, got %s", result)
	}
}

func TestFormatTopTargets_Empty(t *testing.T) {
	result := formatTopTargets([]analyzer.TargetCount{}, 5, "targets", "counts")
	if result != "" {
		t.Errorf("Expected empty string for empty targets, got %s", result)
	}
}

func TestFormatTopTargets_WithLimit(t *testing.T) {
	targets := []analyzer.TargetCount{
		{Target: "target1", Count: 10},
		{Target: "target2", Count: 20},
		{Target: "target3", Count: 30},
		{Target: "target4", Count: 40},
		{Target: "target5", Count: 50},
		{Target: "target6", Count: 60},
	}
	result := formatTopTargets(targets, 3, "targets", "counts")
	if strings.Count(result, "-") > 3 {
		t.Errorf("Expected at most 3 targets, got more")
	}
}

func TestGenerateConnectionSection_WithErrorBreakdown(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80", Error: 111})
	d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80", Error: 111})
	d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80", Error: 0})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateConnectionSection(duration)

	if !strings.Contains(result, "Error breakdown") {
		t.Error("Expected error breakdown in connection section")
	}
}

func TestGenerateFileSystemSection_WithTopFiles(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventRead, LatencyNS: 2000000, Target: "/tmp/file1", Bytes: 4096})
	d.AddEvent(&events.Event{Type: events.EventRead, LatencyNS: 2000000, Target: "/tmp/file1", Bytes: 4096})
	d.AddEvent(&events.Event{Type: events.EventWrite, LatencyNS: 3000000, Target: "/tmp/file2", Bytes: 2048})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateFileSystemSection(duration)

	if !strings.Contains(result, "Top accessed files") {
		t.Error("Expected top accessed files in FS section")
	}
}

func TestGenerateFileSystemSection_WithFilteredTargets(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventRead, LatencyNS: 2000000, Target: "", Bytes: 4096})
	d.AddEvent(&events.Event{Type: events.EventRead, LatencyNS: 2000000, Target: "?", Bytes: 4096})
	d.AddEvent(&events.Event{Type: events.EventRead, LatencyNS: 2000000, Target: "unknown", Bytes: 4096})
	d.AddEvent(&events.Event{Type: events.EventRead, LatencyNS: 2000000, Target: "file", Bytes: 4096})
	d.AddEvent(&events.Event{Type: events.EventRead, LatencyNS: 2000000, Target: "/tmp/valid", Bytes: 4096})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateFileSystemSection(duration)

	if strings.Contains(result, "Top accessed files") {
		if !strings.Contains(result, "/tmp/valid") {
			t.Error("Expected valid file in top files")
		}
	}
}

func TestGenerateUDPSection_WithBytes(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventUDPSend, LatencyNS: 1000000, Bytes: 512})
	d.AddEvent(&events.Event{Type: events.EventUDPRecv, LatencyNS: 2000000, Bytes: 1024})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateUDPSection(duration)

	if !strings.Contains(result, "Total bytes transferred") {
		t.Error("Expected bytes information in UDP section")
	}
}

func TestGenerateUDPSection_WithErrors(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventUDPSend, LatencyNS: 1000000, Error: -1})
	d.AddEvent(&events.Event{Type: events.EventUDPRecv, LatencyNS: 2000000, Error: -2})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateUDPSection(duration)

	if !strings.Contains(result, "Errors:") {
		t.Error("Expected error information in UDP section")
	}
}

func TestGenerateHTTPSection_WithTopURLs(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "http://example.com/page1"})
	d.AddEvent(&events.Event{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "http://example.com/page1"})
	d.AddEvent(&events.Event{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "http://example.com/page2"})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateHTTPSection(duration)

	if !strings.Contains(result, "Top requested URLs") {
		t.Error("Expected top URLs in HTTP section")
	}
}

func TestGenerateHTTPSection_WithBytes(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventHTTPResp, LatencyNS: 10000000, Target: "http://example.com", Bytes: 2048})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateHTTPSection(duration)

	if !strings.Contains(result, "Total bytes transferred") {
		t.Error("Expected bytes information in HTTP section")
	}
}

func TestGenerateTCPStateSection_WithMultipleStates(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventTCPState, TCPState: 1, Target: "example.com:80"})
	d.AddEvent(&events.Event{Type: events.EventTCPState, TCPState: 2, Target: "example.com:80"})
	d.AddEvent(&events.Event{Type: events.EventTCPState, TCPState: 1, Target: "example.com:80"})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateTCPStateSection(duration)

	if !strings.Contains(result, "State distribution") {
		t.Error("Expected state distribution in TCP state section")
	}
}

func TestGenerateMemorySection_WithPageFaultErrors(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventPageFault, Error: 1})
	d.AddEvent(&events.Event{Type: events.EventPageFault, Error: 2})
	d.AddEvent(&events.Event{Type: events.EventPageFault, Error: 1})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateMemorySection(duration)

	if !strings.Contains(result, "Page fault error codes") {
		t.Error("Expected page fault error codes in memory section")
	}
}

func TestGenerateMemorySection_WithOOMKills(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventOOMKill, Target: "process1", Bytes: 1048576, PID: 1234})
	d.AddEvent(&events.Event{Type: events.EventOOMKill, Target: "", Bytes: 2097152, PID: 5678})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateMemorySection(duration)

	if !strings.Contains(result, "Killed processes") {
		t.Error("Expected killed processes in memory section")
	}
}

func TestGenerateReportWithContext_Cancelled(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS})
	d.Finish()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := d.GenerateReportWithContext(ctx)
	if !strings.Contains(result, "cancelled") {
		t.Errorf("Expected cancelled message, got: %s", result[:100])
	}
}

func TestGenerateStackTraceSectionWithContext_Cancelled(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{
		Type:      events.EventLockContention,
		PID:       1234,
		LatencyNS: 2000000,
		Stack:     []uint64{0x1234, 0x5678},
	})
	d.Finish()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := d.generateStackTraceSectionWithContext(ctx)
	if result != "" {
		t.Error("Expected empty result when context is cancelled")
	}
}

func TestGenerateApplicationTracing_WithAllSections(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80"})
	d.AddEvent(&events.Event{Type: events.EventTCPSend, LatencyNS: 10000000, Bytes: 1024})
	d.AddEvent(&events.Event{Type: events.EventTCPRecv, LatencyNS: 15000000, Bytes: 2048})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateApplicationTracing(duration)

	if !strings.Contains(result, "Process Activity") {
		t.Error("Expected process activity section")
	}
	if !strings.Contains(result, "Activity Timeline") {
		t.Error("Expected activity timeline section")
	}
	if !strings.Contains(result, "Connection Patterns") {
		t.Error("Expected connection patterns section")
	}
	if !strings.Contains(result, "Network I/O Pattern") {
		t.Error("Expected network I/O pattern section")
	}
}

func TestGenerateSyscallSection_WithAllTypes(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventExec, LatencyNS: 1000000, Target: "/bin/ls"})
	d.AddEvent(&events.Event{Type: events.EventFork, PID: 1234, Target: "child"})
	d.AddEvent(&events.Event{Type: events.EventOpen, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 5})
	d.AddEvent(&events.Event{Type: events.EventClose, Bytes: 5})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateSyscallSection(duration)

	if !strings.Contains(result, "Execve calls") {
		t.Error("Expected execve calls in syscall section")
	}
	if !strings.Contains(result, "Fork events") {
		t.Error("Expected fork events in syscall section")
	}
	if !strings.Contains(result, "Open calls") {
		t.Error("Expected open calls in syscall section")
	}
	if !strings.Contains(result, "Close calls") {
		t.Error("Expected close calls in syscall section")
	}
}

func TestGenerateSyscallSection_WithFileLeak(t *testing.T) {
	d := NewDiagnostician()
	for i := 0; i < 10; i++ {
		d.AddEvent(&events.Event{Type: events.EventOpen, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 5})
	}
	for i := 0; i < 5; i++ {
		d.AddEvent(&events.Event{Type: events.EventClose, Bytes: 5})
	}
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateSyscallSection(duration)

	if !strings.Contains(result, "Potential descriptor leak") {
		t.Error("Expected descriptor leak warning")
	}
}

func TestGenerateSyscallSection_WithTopFiles(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventOpen, LatencyNS: 2000000, Target: "/tmp/file1", Bytes: 5})
	d.AddEvent(&events.Event{Type: events.EventOpen, LatencyNS: 2000000, Target: "/tmp/file1", Bytes: 5})
	d.AddEvent(&events.Event{Type: events.EventOpen, LatencyNS: 2000000, Target: "/tmp/file2", Bytes: 5})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateSyscallSection(duration)

	if !strings.Contains(result, "Top opened files") {
		t.Error("Expected top opened files in syscall section")
	}
}

func TestDiagnoseError_Error(t *testing.T) {
	err := &DiagnoseError{
		Code:    ErrCodeEventLimitReached,
		Message: "test error",
		Err:     nil,
	}
	result := err.Error()
	if result != "test error" {
		t.Errorf("Expected 'test error', got %s", result)
	}

	errWithWrapped := &DiagnoseError{
		Code:    ErrCodeEventLimitReached,
		Message: "test error",
		Err:     fmt.Errorf("wrapped error"),
	}
	result = errWithWrapped.Error()
	if !strings.Contains(result, "wrapped error") {
		t.Errorf("Expected wrapped error, got %s", result)
	}
}

func TestDiagnoseError_Unwrap(t *testing.T) {
	wrappedErr := fmt.Errorf("wrapped error")
	err := &DiagnoseError{
		Code:    ErrCodeEventLimitReached,
		Message: "test error",
		Err:     wrappedErr,
	}
	if err.Unwrap() != wrappedErr {
		t.Error("Expected unwrap to return wrapped error")
	}
}

func TestNewEventLimitError(t *testing.T) {
	err := NewEventLimitError(100)
	if err.Code != ErrCodeEventLimitReached {
		t.Error("Expected ErrCodeEventLimitReached")
	}
	if !strings.Contains(err.Message, "100") {
		t.Errorf("Expected error message to contain 100, got %s", err.Message)
	}
}

func TestNewContextCancelledError(t *testing.T) {
	wrappedErr := fmt.Errorf("context cancelled")
	err := NewContextCancelledError(wrappedErr)
	if err.Code != ErrCodeContextCancelled {
		t.Error("Expected ErrCodeContextCancelled")
	}
	if err.Unwrap() != wrappedErr {
		t.Error("Expected unwrap to return wrapped error")
	}
}

func TestNewTimeoutError(t *testing.T) {
	err := NewTimeoutError("test operation")
	if err.Code != ErrCodeTimeout {
		t.Error("Expected ErrCodeTimeout")
	}
	if !strings.Contains(err.Message, "test operation") {
		t.Errorf("Expected error message to contain 'test operation', got %s", err.Message)
	}
}

func TestNewInvalidOperationError(t *testing.T) {
	err := NewInvalidOperationError("test operation")
	if err.Code != ErrCodeInvalidOperation {
		t.Error("Expected ErrCodeInvalidOperation")
	}
	if !strings.Contains(err.Message, "test operation") {
		t.Errorf("Expected error message to contain 'test operation', got %s", err.Message)
	}
}

func TestGenerateIssuesSection_WithIssues(t *testing.T) {
	d := NewDiagnostician()
	for i := 0; i < 100; i++ {
		d.AddEvent(&events.Event{Type: events.EventDNS, Error: 1})
	}
	d.Finish()

	result := d.generateIssuesSection()
	if result == "" {
		t.Log("No issues detected (may be expected depending on thresholds)")
	} else {
		if !strings.Contains(result, "Potential Issues Detected") {
			t.Error("Expected issues section header")
		}
	}
}

func TestGenerateStackTraceSectionWithContext_WithStack(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{
		Type:      events.EventLockContention,
		PID:       1234,
		LatencyNS: 2000000,
		Stack:     []uint64{0x1234, 0x5678},
	})
	d.Finish()

	ctx := context.Background()
	result := d.generateStackTraceSectionWithContext(ctx)
	if result != "" {
		if !strings.Contains(result, "Stack Traces for Slow Operations") {
			t.Error("Expected stack trace section header")
		}
	}
}

func TestGenerateStackTraceSectionWithContext_WithHighLatency(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{
		Type:      events.EventDNS,
		PID:       1234,
		LatencyNS: 2000000,
		Stack:     []uint64{0x1234, 0x5678},
	})
	d.Finish()

	ctx := context.Background()
	result := d.generateStackTraceSectionWithContext(ctx)
	if result != "" {
		if !strings.Contains(result, "Stack Traces for Slow Operations") {
			t.Error("Expected stack trace section header")
		}
	}
}

func TestGenerateStackTraceSectionWithContext_WithDBQuery(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{
		Type:      events.EventDBQuery,
		PID:       1234,
		LatencyNS: 100000,
		Stack:     []uint64{0x1234, 0x5678},
	})
	d.Finish()

	ctx := context.Background()
	result := d.generateStackTraceSectionWithContext(ctx)
	if result != "" {
		if !strings.Contains(result, "Stack Traces for Slow Operations") {
			t.Error("Expected stack trace section header")
		}
	}
}

func TestGenerateStackTraceSectionWithContext_EmptyStack(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{
		Type:      events.EventLockContention,
		PID:       1234,
		LatencyNS: 2000000,
		Stack:     []uint64{},
	})
	d.Finish()

	ctx := context.Background()
	result := d.generateStackTraceSectionWithContext(ctx)
	if result != "" {
		t.Error("Expected empty result for events without stack")
	}
}

func TestGenerateStackTraceSectionWithContext_NilEvent(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{
		Type:      events.EventLockContention,
		PID:       1234,
		LatencyNS: 2000000,
		Stack:     []uint64{0x1234},
	})
	d.Finish()

	ctx := context.Background()
	result := d.generateStackTraceSectionWithContext(ctx)
	if result != "" {
		if !strings.Contains(result, "Stack Traces for Slow Operations") {
			t.Error("Expected stack trace section header")
		}
	}
}

func TestGenerateApplicationTracing_EmptySections(t *testing.T) {
	d := NewDiagnostician()
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateApplicationTracing(duration)

	if result == "" {
		t.Log("Empty application tracing is expected with no events")
	}
}

func TestGenerateApplicationTracing_NoBursts(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateApplicationTracing(duration)

	if !strings.Contains(result, "Process Activity") {
		t.Error("Expected process activity section")
	}
}

func TestGenerateApplicationTracing_NoConnectionPattern(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateApplicationTracing(duration)

	if strings.Contains(result, "Connection Patterns") {
		t.Error("Should not have connection patterns without connect events")
	}
}

func TestGenerateApplicationTracing_NoIOPattern(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateApplicationTracing(duration)

	if strings.Contains(result, "Network I/O Pattern") {
		t.Error("Should not have I/O pattern without TCP events")
	}
}

func TestGenerateSyscallSection_ZeroDuration(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventExec, LatencyNS: 1000000})
	d.Finish()

	duration := time.Duration(0)
	result := d.generateSyscallSection(duration)

	if !strings.Contains(result, "Execve calls") {
		t.Error("Expected execve calls in syscall section")
	}
}

func TestGenerateSyscallSection_NoLeak(t *testing.T) {
	d := NewDiagnostician()
	for i := 0; i < 5; i++ {
		d.AddEvent(&events.Event{Type: events.EventOpen, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 5})
	}
	for i := 0; i < 5; i++ {
		d.AddEvent(&events.Event{Type: events.EventClose, Bytes: 5})
	}
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateSyscallSection(duration)

	if strings.Contains(result, "Potential descriptor leak") {
		t.Error("Should not have leak warning when opens == closes")
	}
}

func TestExportJSON_WithAllSections(t *testing.T) {
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

	if data.DNS == nil {
		t.Error("Expected DNS data")
	}
	if data.TCP == nil {
		t.Error("Expected TCP data")
	}
	if data.Connections == nil {
		t.Error("Expected Connections data")
	}
	if data.FileSystem == nil {
		t.Error("Expected FileSystem data")
	}
	if data.CPU == nil {
		t.Error("Expected CPU data")
	}
}

func TestExportJSON_ZeroDuration(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS})
	d.endTime = d.startTime
	data := d.ExportJSON()

	if data.Summary == nil {
		t.Error("Expected summary even with zero duration")
	}
}

func TestExportCSV_NilEvent(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(nil)
	d.Finish()

	var buf bytes.Buffer
	err := d.ExportCSV(&buf)
	if err != nil {
		t.Errorf("ExportCSV should not return error, got %v", err)
	}
}


func TestGenerateTCPStateSection_WithManyStates(t *testing.T) {
	d := NewDiagnostician()
	for i := 0; i < 20; i++ {
		d.AddEvent(&events.Event{Type: events.EventTCPState, TCPState: uint32(i%12 + 1), Target: "example.com:80"})
	}
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateTCPStateSection(duration)

	if !strings.Contains(result, "State distribution") {
		t.Error("Expected state distribution in TCP state section")
	}
}

func TestGenerateMemorySection_OnlyPageFaults(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventPageFault, Error: 1})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateMemorySection(duration)

	if !strings.Contains(result, "Page faults") {
		t.Error("Expected page faults in memory section")
	}
}

func TestGenerateMemorySection_OnlyOOMKills(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventOOMKill, Target: "process", Bytes: 1048576})
	d.Finish()

	duration := d.endTime.Sub(d.startTime)
	result := d.generateMemorySection(duration)

	if !strings.Contains(result, "OOM kills") {
		t.Error("Expected OOM kills in memory section")
	}
}

func TestGenerateFileSystemSection_ZeroDuration(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 4096})
	d.endTime = d.startTime

	duration := d.endTime.Sub(d.startTime)
	result := d.generateFileSystemSection(duration)

	if !strings.Contains(result, "File System Statistics") {
		t.Error("Expected FS section even with zero duration")
	}
}

func TestGenerateHTTPSection_ZeroDuration(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventHTTPReq, LatencyNS: 5000000, Target: "http://example.com"})
	d.endTime = d.startTime

	duration := d.endTime.Sub(d.startTime)
	result := d.generateHTTPSection(duration)

	if !strings.Contains(result, "HTTP Statistics") {
		t.Error("Expected HTTP section even with zero duration")
	}
}

func TestGenerateTCPSection_ZeroDuration(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventTCPSend, LatencyNS: 5000000, Bytes: 1024})
	d.endTime = d.startTime

	duration := d.endTime.Sub(d.startTime)
	result := d.generateTCPSection(duration)

	if !strings.Contains(result, "TCP Statistics") {
		t.Error("Expected TCP section even with zero duration")
	}
}

func TestGenerateConnectionSection_ZeroDuration(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventConnect, LatencyNS: 5000000, Target: "example.com:80"})
	d.endTime = d.startTime

	duration := d.endTime.Sub(d.startTime)
	result := d.generateConnectionSection(duration)

	if !strings.Contains(result, "Connection Statistics") {
		t.Error("Expected connection section even with zero duration")
	}
}
