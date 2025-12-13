package main

import (
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/tracing"
	"k8s.io/client-go/kubernetes/fake"
)

var stdoutMutex sync.Mutex

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

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	go func() {
		stdoutMutex.Lock()
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := runNormalMode(ctx, eventChan, nil, nil, nil, nil, false)

		_ = w.Close()
		os.Stdout = originalStdout
		stdoutMutex.Unlock()
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
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
		stdoutMutex.Lock()
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		err := runNormalMode(ctx, eventChan, nil, nil, nil, nil, false)

		_ = w.Close()
		os.Stdout = originalStdout
		stdoutMutex.Unlock()
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
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
		stdoutMutex.Lock()
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(300 * time.Millisecond)
			cancel()
		}()

		err := runNormalMode(ctx, eventChan, nil, nil, nil, nil, false)

		_ = w.Close()
		os.Stdout = originalStdout
		stdoutMutex.Unlock()
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
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
		stdoutMutex.Lock()
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(200 * time.Millisecond)
			cancel()
		}()

		err := runNormalMode(ctx, eventChan, nil, nil, nil, nil, false)

		_ = w.Close()
		os.Stdout = originalStdout
		stdoutMutex.Unlock()
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
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
		stdoutMutex.Lock()
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := runNormalMode(ctx, eventChan, nil, nil, nil, nil, false)

		_ = w.Close()
		os.Stdout = originalStdout
		stdoutMutex.Unlock()
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
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
		stdoutMutex.Lock()
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := runNormalMode(ctx, eventChan, nil, nil, nil, nil, false)

		_ = w.Close()
		os.Stdout = originalStdout
		stdoutMutex.Unlock()
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
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

	stdoutMutex.Lock()
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "100ms", nil, nil, nil, nil, false)
	_ = w.Close()
	os.Stdout = originalStdout
	stdoutMutex.Unlock()
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

	stdoutMutex.Lock()
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "100ms", nil, nil, nil, nil, false)
	_ = w.Close()
	os.Stdout = originalStdout
	stdoutMutex.Unlock()
	_, _ = io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("runDiagnoseMode returned error: %v", err)
	}
}

func TestRunDiagnoseMode_InvalidDuration(t *testing.T) {
	eventChan := make(chan *events.Event, 10)

	stdoutMutex.Lock()
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "invalid", nil, nil, nil, nil, false)
	_ = w.Close()
	os.Stdout = originalStdout
	stdoutMutex.Unlock()
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

	stdoutMutex.Lock()
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "100ms", nil, nil, nil, nil, false)
	_ = w.Close()
	os.Stdout = originalStdout
	stdoutMutex.Unlock()
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

	stdoutMutex.Lock()
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "100ms", nil, nil, nil, nil, false)
	_ = w.Close()
	os.Stdout = originalStdout
	stdoutMutex.Unlock()
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
		stdoutMutex.Lock()
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := runDiagnoseMode(ctx, eventChan, "10s", nil, nil, nil, nil, false)

		_ = w.Close()
		os.Stdout = originalStdout
		stdoutMutex.Unlock()
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
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
		stdoutMutex.Lock()
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		err := runDiagnoseMode(ctx, eventChan, "10s", nil, nil, nil, nil, false)

		_ = w.Close()
		os.Stdout = originalStdout
		stdoutMutex.Unlock()
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Errorf("runDiagnoseMode returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("runDiagnoseMode did not complete in time")
	}
}

func TestRunNormalMode_WithEnricher(t *testing.T) {
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

	podInfo := &kubernetes.PodInfo{
		PodName:   "test-pod",
		Namespace: "default",
	}

	clientset := fake.NewSimpleClientset()
	enricher := kubernetes.NewContextEnricher(clientset, podInfo)

	go func() {
		stdoutMutex.Lock()
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		err := runNormalMode(ctx, eventChan, podInfo, enricher, nil, nil, false)

		_ = w.Close()
		os.Stdout = originalStdout
		stdoutMutex.Unlock()
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Errorf("runNormalMode returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("runNormalMode did not complete in time")
	}
}

func TestRunNormalMode_WithTracing(t *testing.T) {
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

	tracingManager, _ := tracing.NewManager()

	go func() {
		stdoutMutex.Lock()
		originalStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		err := runNormalMode(ctx, eventChan, nil, nil, nil, tracingManager, true)

		_ = w.Close()
		os.Stdout = originalStdout
		stdoutMutex.Unlock()
		_, _ = io.Copy(io.Discard, r)

		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Errorf("runNormalMode returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("runNormalMode did not complete in time")
	}
}

func TestRunDiagnoseMode_WithEnricher(t *testing.T) {
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

	podInfo := &kubernetes.PodInfo{
		PodName:   "test-pod",
		Namespace: "default",
	}

	clientset := fake.NewSimpleClientset()
	enricher := kubernetes.NewContextEnricher(clientset, podInfo)

	go func() {
		eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
	}()

	stdoutMutex.Lock()
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "100ms", podInfo, enricher, nil, nil, false)
	_ = w.Close()
	os.Stdout = originalStdout
	stdoutMutex.Unlock()
	_, _ = io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("runDiagnoseMode returned error: %v", err)
	}
}

func TestRunDiagnoseMode_WithTracing(t *testing.T) {
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

	tracingManager, _ := tracing.NewManager()

	go func() {
		eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
	}()

	stdoutMutex.Lock()
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "100ms", nil, nil, nil, tracingManager, true)
	_ = w.Close()
	os.Stdout = originalStdout
	stdoutMutex.Unlock()
	_, _ = io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("runDiagnoseMode returned error: %v", err)
	}
}

func TestRunDiagnoseMode_BatchProcessing(t *testing.T) {
	eventChan := make(chan *events.Event, 100)

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
		for i := 0; i < 200; i++ {
			eventChan <- &events.Event{Type: events.EventDNS, LatencyNS: 5000000, Target: "example.com"}
		}
	}()

	stdoutMutex.Lock()
	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagnoseMode(context.Background(), eventChan, "200ms", nil, nil, nil, nil, false)
	_ = w.Close()
	os.Stdout = originalStdout
	stdoutMutex.Unlock()
	_, _ = io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("runDiagnoseMode returned error: %v", err)
	}
}
