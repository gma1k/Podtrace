package exporter

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mountLikeKubernetesSecret(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	payload := filepath.Join(dir, "..2026_10_19_12_00_00.000000001")
	if err := os.Mkdir(payload, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(payload, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Base(payload), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	for name := range files {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func readFileInItsDirectory(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestReadTLSFileFollowsAKubernetesSecretMount(t *testing.T) {
	dir := mountLikeKubernetesSecret(t, map[string][]byte{"ca.crt": []byte("pem-bytes")})

	data, err := readTLSFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("readTLSFile: %v", err)
	}
	if string(data) != "pem-bytes" {
		t.Fatalf("read %q, want pem-bytes", data)
	}
}

func TestReadTLSFileRejectsARelativePath(t *testing.T) {
	if _, err := readTLSFile("ca.pem"); err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("err = %v, want a must-be-absolute refusal", err)
	}
}

func TestReadTLSFileRejectsASymlinkOutOfItsDirectory(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(outside, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "ca.pem")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	if data, err := readTLSFile(link); err == nil {
		t.Fatalf("followed a symlink out of its directory and read %q", data)
	}
}

func TestReadTLSFileRejectsARelativeSymlinkClimbingOut(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "secret.key"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "certs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "ca.pem")
	if err := os.Symlink("../secret.key", link); err != nil {
		t.Fatal(err)
	}

	if data, err := readTLSFile(link); err == nil {
		t.Fatalf("followed ../ out of its directory and read %q", data)
	}
}

func TestReadTLSFileRejectsADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "ca.pem"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readTLSFile(filepath.Join(dir, "ca.pem")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err = %v, want a not-a-regular-file refusal", err)
	}
}

func TestReadTLSFileRejectsAnOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, make([]byte, maxTLSFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTLSFile(path); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want a size refusal", err)
	}
}

func TestReadTLSFileAcceptsAFileAtTheSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, make([]byte, maxTLSFileBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readTLSFile(path)
	if err != nil || len(data) != maxTLSFileBytes {
		t.Fatalf("read %d bytes, err %v; want exactly the limit", len(data), err)
	}
}

func TestReadTLSFileReportsAMissingDirectory(t *testing.T) {
	if _, err := readTLSFile(filepath.Join(t.TempDir(), "absent", "ca.pem")); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}

func TestOTLPLoadsTheCAAndClientKeyPairFromSecretMounts(t *testing.T) {
	collector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)
	caPEM := readFileInItsDirectory(t, writeCollectorCA(t, collector))
	certPath, keyPath := writeClientKeyPair(t, "podtrace-agent")
	certPEM := readFileInItsDirectory(t, certPath)
	keyPEM := readFileInItsDirectory(t, keyPath)
	dir := mountLikeKubernetesSecret(t, map[string][]byte{"ca.crt": caPEM, "tls.crt": certPEM, "tls.key": keyPEM})
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", filepath.Join(dir, "ca.crt"))
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", filepath.Join(dir, "tls.crt"))
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_KEY", filepath.Join(dir, "tls.key"))

	cfg, err := otlpTLSConfigFromEnv()
	if err != nil {
		t.Fatalf("otlpTLSConfigFromEnv: %v", err)
	}
	if cfg == nil || cfg.RootCAs == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("TLS config = %+v, want the CA pool and one client certificate", cfg)
	}
}

func TestOTLPRefusesAClientKeyOutsideItsDirectory(t *testing.T) {
	certPath, keyPath := writeClientKeyPair(t, "podtrace-agent")
	dir := t.TempDir()
	link := filepath.Join(dir, "tls.key")
	if err := os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", certPath)
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_KEY", link)

	if _, err := otlpTLSConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "load OTLP client certificate") {
		t.Fatalf("err = %v, want the client key read refused", err)
	}
}

func TestOTLPRefusesAClientCertificateOutsideItsDirectory(t *testing.T) {
	certPath, keyPath := writeClientKeyPair(t, "podtrace-agent")
	dir := t.TempDir()
	link := filepath.Join(dir, "tls.crt")
	if err := os.Symlink(certPath, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", link)
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_KEY", keyPath)

	if _, err := otlpTLSConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "load OTLP client certificate") {
		t.Fatalf("err = %v, want the client certificate read refused", err)
	}
}

type failingFile struct {
	statErr error
	readErr error
}

func (f failingFile) Stat() (fs.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}
	return regularFileInfo{}, nil
}

func (f failingFile) Read([]byte) (int, error) { return 0, f.readErr }

func (failingFile) Close() error { return nil }

type regularFileInfo struct{}

func (regularFileInfo) Name() string       { return "ca.pem" }
func (regularFileInfo) Size() int64        { return 0 }
func (regularFileInfo) Mode() fs.FileMode  { return 0o600 }
func (regularFileInfo) ModTime() time.Time { return time.Time{} }
func (regularFileInfo) IsDir() bool        { return false }
func (regularFileInfo) Sys() any           { return nil }

func TestReadBoundedRegularReportsAStatFailure(t *testing.T) {
	statErr := errors.New("stat failed")
	if _, err := readBoundedRegular(failingFile{statErr: statErr}, "/certs/ca.pem"); !errors.Is(err, statErr) {
		t.Fatalf("err = %v, want the stat failure", err)
	}
}

func TestReadBoundedRegularReportsAReadFailure(t *testing.T) {
	readErr := errors.New("input/output error")
	if _, err := readBoundedRegular(failingFile{readErr: readErr}, "/certs/ca.pem"); !errors.Is(err, readErr) {
		t.Fatalf("err = %v, want the read failure", err)
	}
}
