package main

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestRunNormalMode_WithEvents(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires signal handling")
	}

	eventChan := make(chan *events.Event, 10)
	done := make(chan error, 1)

	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	go func() {
		eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
		time.Sleep(50 * time.Millisecond)
		proc, _ := os.FindProcess(os.Getpid())
		_ = proc.Signal(os.Interrupt)
	}()

	go func() {
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := runNormalMode(context.Background(), eventChan)

		_ = w.Close()
		os.Stdout = originalStdout
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runNormalMode returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("runNormalMode did not complete in time")
	}
}

func TestRunNormalMode_Interrupt(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires signal handling")
	}

	eventChan := make(chan *events.Event, 10)
	done := make(chan error, 1)

	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	go func() {
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		go func() {
			time.Sleep(100 * time.Millisecond)
			proc, _ := os.FindProcess(os.Getpid())
			_ = proc.Signal(os.Interrupt)
		}()

		err := runNormalMode(context.Background(), eventChan)

		_ = w.Close()
		os.Stdout = originalStdout
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runNormalMode returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("runNormalMode did not complete in time")
	}
}

func TestRunNormalMode_TickerBeforeInterrupt(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires signal handling")
	}

	eventChan := make(chan *events.Event, 10)
	done := make(chan error, 1)

	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	go func() {
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		go func() {
			time.Sleep(300 * time.Millisecond)
			proc, _ := os.FindProcess(os.Getpid())
			_ = proc.Signal(os.Interrupt)
		}()

		err := runNormalMode(context.Background(), eventChan)

		_ = w.Close()
		os.Stdout = originalStdout
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runNormalMode returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("runNormalMode did not complete in time")
	}
}

func TestRunNormalMode_HasPrintedReport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires signal handling")
	}

	eventChan := make(chan *events.Event, 10)
	done := make(chan error, 1)

	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	go func() {
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		go func() {
			time.Sleep(200 * time.Millisecond)
			proc, _ := os.FindProcess(os.Getpid())
			_ = proc.Signal(os.Interrupt)
		}()

		err := runNormalMode(context.Background(), eventChan)

		_ = w.Close()
		os.Stdout = originalStdout
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runNormalMode returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("runNormalMode did not complete in time")
	}
}

func TestRunNormalMode_NoEvents(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires signal handling")
	}

	eventChan := make(chan *events.Event, 10)
	done := make(chan error, 1)

	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	go func() {
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		go func() {
			time.Sleep(50 * time.Millisecond)
			proc, _ := os.FindProcess(os.Getpid())
			_ = proc.Signal(os.Interrupt)
		}()

		err := runNormalMode(context.Background(), eventChan)

		_ = w.Close()
		os.Stdout = originalStdout
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runNormalMode returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("runNormalMode did not complete in time")
	}
}

func TestRunNormalMode_WithTicker(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires signal handling")
	}

	eventChan := make(chan *events.Event, 10)
	done := make(chan error, 1)

	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
	}()

	go func() {
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		go func() {
			eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
			time.Sleep(50 * time.Millisecond)
			proc, _ := os.FindProcess(os.Getpid())
			_ = proc.Signal(os.Interrupt)
		}()

		err := runNormalMode(context.Background(), eventChan)

		_ = w.Close()
		os.Stdout = originalStdout
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runNormalMode returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("runNormalMode did not complete in time")
	}
}

func TestRunDiagnoseMode_Timeout(t *testing.T) {
	eventChan := make(chan *events.Event, 10)
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	origExportFormat := exportFormat
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	exportFormat = ""
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
		exportFormat = origExportFormat
	}()

	go func() {
		eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
	}()

	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "100ms", "/test/cgroup")
	_ = w.Close()
	os.Stdout = originalStdout
	_, _ = io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("runDiagnoseMode returned error: %v", err)
	}
}

func TestRunDiagnoseMode_WithExport(t *testing.T) {
	eventChan := make(chan *events.Event, 10)
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	origExportFormat := exportFormat
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	exportFormat = "json"
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
		exportFormat = origExportFormat
	}()

	go func() {
		eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
	}()

	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "100ms", "/test/cgroup")
	_ = w.Close()
	os.Stdout = originalStdout
	_, _ = io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("runDiagnoseMode returned error: %v", err)
	}
}

func TestRunDiagnoseMode_InvalidDuration(t *testing.T) {
	eventChan := make(chan *events.Event, 10)

	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

		err := runDiagnoseMode(context.Background(), eventChan, "invalid", "/test/cgroup")
		_ = w.Close()
		os.Stdout = originalStdout
	_, _ = io.Copy(io.Discard, r)

	if err == nil {
		t.Error("Expected error for invalid duration")
	}
}

func TestRunDiagnoseMode_WithExportFormat(t *testing.T) {
	eventChan := make(chan *events.Event, 10)
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	origExportFormat := exportFormat
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	exportFormat = "json"
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
		exportFormat = origExportFormat
	}()

	go func() {
		eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
	}()

	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "100ms", "/test/cgroup")
	_ = w.Close()
	os.Stdout = originalStdout
	_, _ = io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("runDiagnoseMode returned error: %v", err)
	}
}

func TestRunDiagnoseMode_WithExportFormatCSV(t *testing.T) {
	eventChan := make(chan *events.Event, 10)
	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	origExportFormat := exportFormat
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	exportFormat = "csv"
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
		exportFormat = origExportFormat
	}()

	go func() {
		eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
	}()

	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "100ms", "/test/cgroup")
	_ = w.Close()
	os.Stdout = originalStdout
	_, _ = io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("runDiagnoseMode returned error: %v", err)
	}
}

func TestRunDiagnoseMode_Interrupt(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires signal handling")
	}

	eventChan := make(chan *events.Event, 10)
	done := make(chan error, 1)

	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	origExportFormat := exportFormat
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	exportFormat = ""
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
		exportFormat = origExportFormat
	}()

	go func() {
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		go func() {
			time.Sleep(50 * time.Millisecond)
			proc, _ := os.FindProcess(os.Getpid())
			_ = proc.Signal(os.Interrupt)
		}()

		err := runDiagnoseMode(context.Background(), eventChan, "10s", "/test/cgroup")

		_ = w.Close()
		os.Stdout = originalStdout
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runDiagnoseMode returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("runDiagnoseMode did not complete in time")
	}
}

func TestRunDiagnoseMode_InterruptWithExport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires signal handling")
	}

	eventChan := make(chan *events.Event, 10)
	done := make(chan error, 1)

	origErrorRateThreshold := errorRateThreshold
	origRTTThreshold := rttSpikeThreshold
	origFSThreshold := fsSlowThreshold
	origExportFormat := exportFormat
	errorRateThreshold = 10.0
	rttSpikeThreshold = 100.0
	fsSlowThreshold = 10.0
	exportFormat = "json"
	defer func() {
		errorRateThreshold = origErrorRateThreshold
		rttSpikeThreshold = origRTTThreshold
		fsSlowThreshold = origFSThreshold
		exportFormat = origExportFormat
	}()

	go func() {
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		go func() {
			time.Sleep(50 * time.Millisecond)
			proc, _ := os.FindProcess(os.Getpid())
			_ = proc.Signal(os.Interrupt)
		}()

		err := runDiagnoseMode(context.Background(), eventChan, "10s", "/test/cgroup")

		_ = w.Close()
		os.Stdout = originalStdout
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runDiagnoseMode returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("runDiagnoseMode did not complete in time")
	}
}
