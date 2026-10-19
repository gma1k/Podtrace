package exporter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/netguard"
)

func TestOTLPMetadataRefusalIsNotRetried(t *testing.T) {
	t.Setenv("PODTRACE_OTLP_INSECURE", "1")
	exp, err := NewOTLPExporter("http://169.254.169.254:9", 1.0)
	if err != nil {
		t.Fatal(err)
	}
	err = exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")})
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Fatalf("error does not wrap netguard.ErrBlocked: %v", err)
	}
	var partial *PartialExportError
	if !errors.As(err, &partial) {
		t.Fatalf("expected a PartialExportError, got %T: %v", err, err)
	}
	if partial.Retry(goodTraceID) {
		t.Fatal("a trace refused by the egress guard must not be offered again")
	}
}

func TestOTLPRedirectRefusalIsNotRetried(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/v1/traces", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(collector.Close)

	exp, err := NewOTLPExporter(collector.URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	err = exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")})
	var partial *PartialExportError
	if !errors.As(err, &partial) {
		t.Fatalf("expected a PartialExportError, got %T: %v", err, err)
	}
	if partial.Retry(goodTraceID) {
		t.Fatal("a trace whose collector redirected must not be offered again")
	}
}

func TestOTLPConnectionRefusedIsRetried(t *testing.T) {
	exp, err := NewOTLPExporter("http://127.0.0.1:1", 1.0)
	if err != nil {
		t.Fatal(err)
	}
	err = exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")})
	var partial *PartialExportError
	if !errors.As(err, &partial) {
		t.Fatalf("expected a PartialExportError, got %T: %v", err, err)
	}
	if !partial.Retry(goodTraceID) {
		t.Fatal("a transient connection failure must keep the trace for retry")
	}
}
