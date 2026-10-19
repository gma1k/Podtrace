package exporter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
)

func writeClientKeyPair(t *testing.T, commonName string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func writeCollectorCA(t *testing.T, collector *httptest.Server) string {
	t.Helper()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: collector.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath
}

func TestOTLPPresentsTheClientCertificateFromTheStandardEnvironment(t *testing.T) {
	var presented atomic.Value
	collector := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) > 0 {
			presented.Store(r.TLS.PeerCertificates[0].Subject.CommonName)
		}
		w.WriteHeader(http.StatusOK)
	}))
	collector.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	collector.StartTLS()
	t.Cleanup(collector.Close)
	certPath, keyPath := writeClientKeyPair(t, "podtrace-agent")
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", writeCollectorCA(t, collector))
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", certPath)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY", keyPath)

	exp, err := NewOTLPExporter(collector.URL, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")}); err != nil {
		t.Fatalf("export to a collector requiring a client certificate failed: %v", err)
	}
	if got, _ := presented.Load().(string); got != "podtrace-agent" {
		t.Fatalf("collector saw client certificate %q, want podtrace-agent", got)
	}
}

func TestOTLPClientCertificateAloneNeedsNoCA(t *testing.T) {
	certPath, keyPath := writeClientKeyPair(t, "podtrace-agent")
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", certPath)
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_KEY", keyPath)

	cfg, err := otlpTLSConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("want exactly one client certificate, got %+v", cfg)
	}
	if cfg.RootCAs != nil {
		t.Error("no CA was configured, so the system roots must stay in effect")
	}
}

func TestOTLPRejectsAMismatchedClientKeyPair(t *testing.T) {
	certPath, _ := writeClientKeyPair(t, "first")
	_, otherKeyPath := writeClientKeyPair(t, "second")
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", certPath)
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_KEY", otherKeyPath)

	_, err := NewOTLPExporter("https://collector.example:4318", 1.0)
	if err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Fatalf("a key that does not match the certificate must fail exporter creation, got %v", err)
	}
}

func TestOTLPRejectsACAFileWithoutCertificates(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", caPath)

	_, err := otlpTLSConfigFromEnv()
	if err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Fatalf("a CA file holding no certificate must be refused, got %v", err)
	}
}
