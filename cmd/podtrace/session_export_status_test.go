package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/tracing"
)

func withSessionExportStatus(t *testing.T, fn func() []tracing.ExporterStatus) {
	t.Helper()
	saved := sessionExportStatus
	t.Cleanup(func() { sessionExportStatus = saved })
	sessionExportStatus = fn
}

func TestCollectSessionExportsWithoutTracingIsEmpty(t *testing.T) {
	withSessionExportStatus(t, nil)
	if got := collectSessionExports(); got != nil {
		t.Fatalf("collectSessionExports = %+v, want nil", got)
	}
}

func TestCollectSessionExportsCopiesEveryExporter(t *testing.T) {
	withSessionExportStatus(t, func() []tracing.ExporterStatus {
		return []tracing.ExporterStatus{
			{Exporter: "otlp", FailedBatches: 8, LastError: "dial tcp: lookup recv: no such host"},
			{Exporter: "zipkin", SucceededBatches: 3},
		}
	})
	got := collectSessionExports()
	want := []SessionExportStatus{
		{Exporter: "otlp", Failed: 8, LastError: "dial tcp: lookup recv: no such host"},
		{Exporter: "zipkin", Succeeded: 3},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("collectSessionExports = %+v, want %+v", got, want)
	}
}

func TestCollectSessionExportsTruncatesLongErrors(t *testing.T) {
	withSessionExportStatus(t, func() []tracing.ExporterStatus {
		return []tracing.ExporterStatus{{Exporter: "otlp", FailedBatches: 1, LastError: strings.Repeat("é", 400)}}
	})
	got := collectSessionExports()
	if len(got) != 1 || len(got[0].LastError) > maxExportErrorBytes+3 {
		t.Fatalf("LastError not truncated: %d bytes", len(got[0].LastError))
	}
	if !strings.HasSuffix(got[0].LastError, "...") {
		t.Fatalf("truncated LastError lacks the ellipsis: %q", got[0].LastError)
	}
	if !json.Valid([]byte(`"`+got[0].LastError+`"`)) || strings.ContainsRune(got[0].LastError, '�') {
		t.Fatalf("truncation split a multi-byte rune: %q", got[0].LastError)
	}
}

func TestTerminationMessageWithEveryExporterFailingFitsTheLimit(t *testing.T) {
	long := strings.Repeat("x", 2000)
	withSessionExportStatus(t, func() []tracing.ExporterStatus {
		var out []tracing.ExporterStatus
		for _, name := range []string{"datadog", "jaeger", "otlp", "splunk", "zipkin"} {
			out = append(out, tracing.ExporterStatus{Exporter: name, FailedBatches: 1 << 40, LastError: long})
		}
		return out
	})
	summary := SessionSummary{TotalEvents: 1 << 40, Node: strings.Repeat("n", 253), Exports: collectSessionExports()}
	dir := t.TempDir()
	if err := writeTerminationMessage(filepath.Join(dir, "termination-log"), summary); err != nil {
		t.Fatalf("writeTerminationMessage: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	data, err := root.ReadFile("termination-log")
	if err != nil {
		t.Fatal(err)
	}
	var decoded SessionSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("termination message is not valid JSON: %v", err)
	}
	if len(decoded.Exports) != 5 {
		t.Fatalf("decoded %d exporters, want 5", len(decoded.Exports))
	}
}

type recordingExportSource struct {
	calls []string
}

func (r *recordingExportSource) Flush() {
	r.calls = append(r.calls, "flush")
}

func (r *recordingExportSource) ExportStatus() []tracing.ExporterStatus {
	r.calls = append(r.calls, "status")
	return []tracing.ExporterStatus{{Exporter: "otlp", SucceededBatches: 2}}
}

func TestFlushingExportStatusFlushesBeforeReadingStatus(t *testing.T) {
	src := &recordingExportSource{}

	got := flushingExportStatus(src)()

	if len(src.calls) != 2 || src.calls[0] != "flush" || src.calls[1] != "status" {
		t.Errorf("calls = %v, want [flush status]", src.calls)
	}
	if len(got) != 1 || got[0].Exporter != "otlp" || got[0].SucceededBatches != 2 {
		t.Errorf("status = %+v, want the source's otlp record", got)
	}
}
