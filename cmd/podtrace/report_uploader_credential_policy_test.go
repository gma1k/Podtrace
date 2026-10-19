package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/reportsink/objectstore"
)

func writeCredentialsDir(t *testing.T, creds map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for k, v := range creds {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(envObjectStoreCredentialsDir, dir)
}

func TestUploadToObjectStore_RefusesTenantEndpointWithoutStaticCredentials(t *testing.T) {
	writeCredentialsDir(t, map[string]string{"endpoint": "https://attacker.example"})
	t.Setenv(objectstore.EnvAllowAmbientCredentials, "true")
	t.Setenv(objectstore.EnvEndpointAllowlist, "")

	err := uploadToObjectStore(context.Background(), reportUploaderOptions{
		ReportToSpec: "azblob://acct/reports/",
	}, []byte("report body"))
	if err == nil || !strings.Contains(err.Error(), "attacker.example") {
		t.Fatalf("expected the tenant endpoint to be refused, got %v", err)
	}
}

func TestUploadToObjectStore_AmbientCredentialsDeniedWithoutOperatorPolicy(t *testing.T) {
	t.Setenv(envObjectStoreCredentialsDir, "")
	t.Setenv(objectstore.EnvAllowAmbientCredentials, "")

	err := uploadToObjectStore(context.Background(), reportUploaderOptions{
		ReportToSpec: "s3://other-tenant-bucket/key",
	}, []byte("report body"))
	if !errors.Is(err, objectstore.ErrAmbientCredentialsDenied) {
		t.Fatalf("expected ErrAmbientCredentialsDenied, got %v", err)
	}
}

func TestUploadToObjectStore_StaticKeysWithCustomEndpointStillUpload(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	writeCredentialsDir(t, map[string]string{
		"access_key_id":     "AKIATEST",
		"secret_access_key": "secret",
		"endpoint":          srv.URL,
		"force_path_style":  "true",
	})
	t.Setenv(objectstore.EnvAllowAmbientCredentials, "")
	orig := keyHintStateFile
	keyHintStateFile = filepath.Join(t.TempDir(), "hint")
	t.Cleanup(func() { keyHintStateFile = orig })

	err := uploadToObjectStore(context.Background(), reportUploaderOptions{
		ReportToSpec: "s3://bucket/reports/fixed.txt",
	}, []byte("report body"))
	if err != nil {
		t.Fatalf("upload with static keys: %v", err)
	}
	if gotPath != "/bucket/reports/fixed.txt" {
		t.Fatalf("path = %q, want /bucket/reports/fixed.txt", gotPath)
	}
}
