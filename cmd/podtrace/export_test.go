package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/diagnose"
	"github.com/podtrace/podtrace/internal/events"
)

func TestExportReport_JSON(t *testing.T) {
	d := diagnose.NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"})
	d.Finish()

	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := exportReport("test report", "json", d)
	w.Close()
	os.Stdout = originalStdout

	if err == nil {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		t.Logf("JSON export test completed, output length: %d", buf.Len())
	}
}

func TestExportReport_CSV(t *testing.T) {
	d := diagnose.NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"})
	d.Finish()

	var buf bytes.Buffer
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := exportReport("test report", "csv", d)
	w.Close()
	os.Stdout = originalStdout

	if err == nil {
		io.Copy(&buf, r)
		t.Logf("CSV export test completed, output length: %d", buf.Len())
	}
}

func TestExportReport_InvalidFormat(t *testing.T) {
	d := diagnose.NewDiagnostician()
	err := exportReport("test report", "invalid", d)

	if err == nil {
		t.Error("Expected error for invalid format")
	}

	if err != nil && !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("Expected error message to contain 'unsupported', got: %v", err)
	}
}

func TestExportReport_FormatVariations(t *testing.T) {
	d := diagnose.NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"})
	d.Finish()

	tests := []struct {
		name        string
		format      string
		expectError bool
	}{
		{"uppercase JSON", "JSON", false},
		{"uppercase CSV", "CSV", false},
		{"mixed case", "Json", false},
		{"with spaces", " json ", false},
		{"invalid format", "xml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := exportReport("test report", tt.format, d)
			w.Close()
			os.Stdout = originalStdout

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.expectError {
				io.Copy(io.Discard, r)
			}
		})
	}
}
