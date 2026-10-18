package exporter

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
)

func TestOTLPExporterSendsTheConfiguredHeaders(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	orig := config.OTLPHeaders
	config.OTLPHeaders = map[string]string{"Authorization": "Bearer s3cr3t", "X-Tenant": "team-a"}
	t.Cleanup(func() { config.OTLPHeaders = orig })

	exporter, err := NewOTLPExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(t.Context()) })
	if err := exporter.ExportTraces([]*tracker.Trace{newTestTrace()}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if got.Get("Authorization") != "Bearer s3cr3t" || got.Get("X-Tenant") != "team-a" {
		t.Fatalf("collector received headers %v", got)
	}
}
