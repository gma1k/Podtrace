package exporter

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
)

const (
	goodTraceID = "aabbccddeeff00112233445566778899"
	badTraceID  = "99887766554433221100ffeeddccbbaa"
)

func traceWithIDs(traceID, spanID string) *tracker.Trace {
	return &tracker.Trace{
		TraceID: traceID,
		Spans: []*tracker.Span{{
			TraceID:   traceID,
			SpanID:    spanID,
			Operation: "op",
			StartTime: time.Now(),
			Duration:  time.Millisecond,
		}},
	}
}

func asPartial(t *testing.T, err error) *PartialExportError {
	t.Helper()
	var partial *PartialExportError
	if !errors.As(err, &partial) {
		t.Fatalf("error %v is not a *PartialExportError", err)
	}
	return partial
}

func failingFor(traceID string, status int) (*httptest.Server, *atomic.Int32) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), traceID) {
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	return srv, &posts
}

func TestOTLPDropsAnUnexportableSpanWithoutRetryingItsTrace(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	exp, err := NewOTLPExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}

	err = exp.ExportTraces([]*tracker.Trace{
		traceWithIDs(goodTraceID, "1122334455667788"),
		traceWithIDs("not-hex", "1122334455667788"),
	})
	if err == nil {
		t.Fatal("the unexportable span must still be reported")
	}
	partial := asPartial(t, err)
	if partial.Retry(goodTraceID) || partial.Retry("not-hex") {
		t.Fatalf("no trace may be retried: delivered and permanently invalid traces would be re-sent every tick; failed=%v", partial.FailedTraces)
	}
	if posts.Load() != 1 {
		t.Fatalf("collector received %d posts, want 1", posts.Load())
	}
}

func TestOTLPRetriesEveryShippedTraceWhenTheCollectorFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	exp, err := NewOTLPExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}

	partial := asPartial(t, exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")}))
	if !partial.Retry(goodTraceID) {
		t.Fatal("a trace the collector refused transiently must be retried")
	}
}

func TestZipkinRetriesOnlyTheTraceThatFailedTransiently(t *testing.T) {
	srv, _ := failingFor(badTraceID, http.StatusServiceUnavailable)
	t.Cleanup(srv.Close)
	exp, err := NewZipkinExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}

	partial := asPartial(t, exp.ExportTraces([]*tracker.Trace{
		traceWithIDs(goodTraceID, "1122334455667788"),
		traceWithIDs(badTraceID, "8877665544332211"),
	}))
	if partial.Retry(goodTraceID) {
		t.Error("the delivered trace must not be re-sent")
	}
	if !partial.Retry(badTraceID) {
		t.Error("the transiently failed trace must be retried")
	}
}

func TestDataDogDoesNotRetryATraceTheAgentRejects(t *testing.T) {
	srv, _ := failingFor("", http.StatusBadRequest)
	t.Cleanup(srv.Close)
	exp, err := NewDataDogExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatal(err)
	}

	partial := asPartial(t, exp.ExportTraces([]*tracker.Trace{traceWithIDs(badTraceID, "aabbccddeeff0011")}))
	if partial.Retry(badTraceID) {
		t.Error("a 400 will be returned for the same payload forever; the trace must not be retried")
	}
}

func TestSplunkRetriesTheTracesOfAFailedBatch(t *testing.T) {
	srv, _ := failingFor(badTraceID, http.StatusBadGateway)
	t.Cleanup(srv.Close)
	exp, err := NewSplunkExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatal(err)
	}

	partial := asPartial(t, exp.ExportTraces([]*tracker.Trace{
		traceWithIDs(goodTraceID, "1122334455667788"),
		traceWithIDs(badTraceID, "8877665544332211"),
	}))
	if !partial.Retry(goodTraceID) || !partial.Retry(badTraceID) {
		t.Errorf("both traces shared the failed batch and must be retried; failed=%v", partial.FailedTraces)
	}
}

func TestStatusErrorClassifiesRetryableStatuses(t *testing.T) {
	cases := map[int]bool{
		http.StatusBadRequest:          true,
		http.StatusUnauthorized:        true,
		http.StatusNotFound:            true,
		http.StatusRequestTimeout:      false,
		http.StatusTooManyRequests:     false,
		http.StatusInternalServerError: false,
		http.StatusServiceUnavailable:  false,
	}
	for code, wantPermanent := range cases {
		if got := isPermanent(statusError(code)); got != wantPermanent {
			t.Errorf("status %d: permanent=%v, want %v", code, got, wantPermanent)
		}
	}
}
