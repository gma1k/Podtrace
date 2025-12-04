package diagnose

import (
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

	if len(d.events) != 0 {
		t.Errorf("Expected empty events, got %d", len(d.events))
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
	if len(d.events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(d.events))
	}

	d.AddEvent(event2)
	if len(d.events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(d.events))
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
