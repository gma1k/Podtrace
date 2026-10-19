package tracing

import (
	"strings"
	"sync"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

const statusTraceID = "aabbccddeeff00112233445566778899"

func TestExportStatusCountsDeliveredBatches(t *testing.T) {
	srv, _ := recordingServer(t, "")
	m := managerWithOnly(t, func() { config.ZipkinEndpoint = srv.URL })
	trackSpan(m, statusTraceID, "1122334455667788")

	m.Flush()

	got := m.ExportStatus()
	if len(got) != 1 || got[0].Exporter != "zipkin" || got[0].SucceededBatches != 1 || got[0].FailedBatches != 0 || got[0].LastError != "" {
		t.Fatalf("ExportStatus = %+v, want one delivered zipkin batch", got)
	}
}

func TestExportStatusRecordsFailuresWithARedactedError(t *testing.T) {
	srv, _ := recordingServer(t, statusTraceID)
	m := managerWithOnly(t, func() { config.ZipkinEndpoint = srv.URL + "/api/v2/spans?token=SECRETVALUE" })
	trackSpan(m, statusTraceID, "1122334455667788")

	m.Flush()
	m.Flush()

	got := m.ExportStatus()
	if len(got) != 1 || got[0].SucceededBatches != 0 || got[0].FailedBatches != 2 {
		t.Fatalf("ExportStatus = %+v, want two failed batches and none delivered", got)
	}
	if got[0].LastError == "" {
		t.Fatal("LastError is empty for a failed exporter")
	}
	if strings.Contains(got[0].LastError, "SECRETVALUE") {
		t.Fatalf("LastError leaks the endpoint query: %q", got[0].LastError)
	}
}

func TestExportStatusIsEmptyBeforeAnyExport(t *testing.T) {
	srv, _ := recordingServer(t, "")
	m := managerWithOnly(t, func() { config.ZipkinEndpoint = srv.URL })

	m.Flush()

	if got := m.ExportStatus(); len(got) != 0 {
		t.Fatalf("ExportStatus = %+v, want empty when nothing was exported", got)
	}
}

func TestExportStatusOfADisabledManagerIsNil(t *testing.T) {
	m := &Manager{enabled: false}
	m.Flush()
	if got := m.ExportStatus(); got != nil {
		t.Fatalf("ExportStatus = %+v, want nil", got)
	}
}

func TestConcurrentFlushesSendEachSpanOnce(t *testing.T) {
	srv, log := recordingServer(t, "")
	m := managerWithOnly(t, func() { config.ZipkinEndpoint = srv.URL })
	trackSpan(m, statusTraceID, "1122334455667788")

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Flush()
		}()
	}
	wg.Wait()

	if got := log.count(statusTraceID); got != 1 {
		t.Fatalf("span posted %d times by concurrent flushes, want 1", got)
	}
}
