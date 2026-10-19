package exporter

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
)

func TestOTLPRefusesToFollowARedirect(t *testing.T) {
	var stolen atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stolen.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(attacker.Close)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/v1/traces", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(collector.Close)

	exp, err := NewOTLPExporter(collector.URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")}); err == nil {
		t.Fatal("export through a redirect must fail")
	}
	if stolen.Load() != 0 {
		t.Fatalf("redirect target received %d requests carrying the exporter headers", stolen.Load())
	}
}

func TestJaegerRefusesToFollowARedirect(t *testing.T) {
	var stolen atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stolen.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(attacker.Close)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/v1/traces", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(collector.Close)

	exp, err := NewJaegerExporter(collector.URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	_ = exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")})
	if stolen.Load() != 0 {
		t.Fatalf("redirect target received %d requests", stolen.Load())
	}
}

func TestOTLPRefusesToDialTheMetadataAddress(t *testing.T) {
	t.Setenv("PODTRACE_OTLP_INSECURE", "1")
	exp, err := NewOTLPExporter("http://169.254.169.254:9", 1.0)
	if err != nil {
		t.Fatal(err)
	}
	err = exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")})
	if err == nil || !strings.Contains(err.Error(), "netguard") {
		t.Fatalf("expected the SSRF dial guard to refuse the connection, got %v", err)
	}
}

func TestOTLPTrustsTheCAFromTheStandardEnvironment(t *testing.T) {
	var posts atomic.Int32
	collector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: collector.Certificate().Raw})
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", caPath)

	exp, err := NewOTLPExporter(collector.URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")}); err != nil {
		t.Fatalf("export to a collector signed by the configured CA failed: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("collector received %d posts, want 1", posts.Load())
	}
}

func TestOTLPRejectsAnUnreadableCAFile(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := NewOTLPExporter("https://collector.example:4318", 1.0); err == nil {
		t.Fatal("a configured but unreadable CA must fail exporter creation")
	}
}

func TestOTLPTLSConfigFromEnvironmentPrefersTheTracesVariable(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	good := filepath.Join(dir, "good.pem")
	if err := os.WriteFile(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", filepath.Join(dir, "missing.pem"))
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", good)

	cfg, err := otlpTLSConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	if cfg == nil || !cfg.RootCAs.Equal(pool) {
		t.Fatal("the traces-specific CA must win over the generic one")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", cfg.MinVersion)
	}
}
