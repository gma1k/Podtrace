//go:build integration
// +build integration

package test

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose"
	"github.com/podtrace/podtrace/internal/events"
)

func TestDiagnostician_RealWorldScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	d := diagnose.NewDiagnostician()

	eventTypes := []events.EventType{
		events.EventDNS,
		events.EventConnect,
		events.EventTCPSend,
		events.EventTCPRecv,
		events.EventRead,
		events.EventWrite,
	}

	for i := 0; i < 100; i++ {
		eventType := eventTypes[i%len(eventTypes)]
		event := &events.Event{
			Type:      eventType,
			PID:       uint32(1000 + i%10),
			LatencyNS: uint64((i + 1) * 1000000), // 1ms to 100ms
			Target:    "example.com",
			Error:     0,
		}

		if i%10 == 0 {
			event.Error = 111
		}

		d.AddEvent(event)
	}

	d.Finish()

	report := d.GenerateReport()
	if report == "" {
		t.Error("Report should not be empty")
	}

	sections := []string{
		"Summary",
		"DNS Statistics",
		"TCP Statistics",
		"Connection Statistics",
	}

	for _, section := range sections {
		if !contains(report, section) {
			t.Errorf("Report should contain section '%s'", section)
		}
	}
}

func TestDiagnostician_ExportFormats(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	d := diagnose.NewDiagnostician()

	for i := 0; i < 50; i++ {
		d.AddEvent(&events.Event{
			Type:      events.EventDNS,
			LatencyNS: uint64(i * 1000000),
			Target:    "example.com",
		})
	}

	d.Finish()

	jsonData := d.ExportJSON()
	if jsonData.Summary == nil {
		t.Error("JSON export should include summary")
	}

	var csvBuf []byte
	writer := &testWriter{data: &csvBuf}
	err := d.ExportCSV(writer)
	if err != nil {
		t.Errorf("CSV export should not fail: %v", err)
	}
	if len(csvBuf) == 0 {
		t.Error("CSV export should produce output")
	}
}

func TestDiagnostician_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	d := diagnose.NewDiagnostician()

	start := time.Now()
	for i := 0; i < 10000; i++ {
		d.AddEvent(&events.Event{
			Type:      events.EventDNS,
			LatencyNS: uint64(i * 1000000),
			Target:    "example.com",
		})
	}
	addDuration := time.Since(start)

	if addDuration > 1*time.Second {
		t.Errorf("Adding 10000 events took too long: %v", addDuration)
	}

	d.Finish()

	start = time.Now()
	_ = d.GenerateReport()
	reportDuration := time.Since(start)

	if reportDuration > 5*time.Second {
		t.Errorf("Generating report took too long: %v", reportDuration)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}

type testWriter struct {
	data *[]byte
}

func (w *testWriter) Write(p []byte) (n int, err error) {
	*w.data = append(*w.data, p...)
	return len(p), nil
}
