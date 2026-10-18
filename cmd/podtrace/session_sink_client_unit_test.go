package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

func useEmptyKubeconfig(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := kubeconfigPath
	kubeconfigPath = path
	t.Cleanup(func() { kubeconfigPath = orig })
}

func TestBuildInClusterClient_NoInClusterNoKubeconfig(t *testing.T) {
	useEmptyKubeconfig(t)

	_, err := buildInClusterClient()
	if err == nil || !strings.Contains(err.Error(), "load kubeconfig") {
		t.Fatalf("expected a kubeconfig error, got %v", err)
	}
}

func TestBuildInClusterClient_BadKubeconfig(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(bad, []byte("::not valid yaml::"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", bad)

	_, err := buildInClusterClient()
	if err == nil || !strings.Contains(err.Error(), "load kubeconfig") {
		t.Fatalf("expected load-kubeconfig error, got %v", err)
	}
}

func TestBuildInClusterClient_ValidKubeconfig(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	const content = `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user:
    token: test-token
`
	if err := os.WriteFile(kubeconfig, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)

	client, err := buildInClusterClient()
	if err != nil {
		t.Fatalf("valid kubeconfig should build a client, got %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil client")
	}
}

func TestUploadReport_ObjectStoreWritesHandoffFile(t *testing.T) {
	dir := t.TempDir()
	orig := objectStoreReportFile
	objectStoreReportFile = filepath.Join(dir, "report.txt")
	t.Cleanup(func() { objectStoreReportFile = orig })

	if err := uploadReport(context.Background(), "s3://bucket/key", "hello report"); err != nil {
		t.Fatalf("object-store handoff should succeed, got %v", err)
	}
	raw, err := os.ReadFile(objectStoreReportFile)
	if err != nil {
		t.Fatalf("handoff file not written: %v", err)
	}
	if string(raw) != "hello report" {
		t.Errorf("handoff content = %q, want %q", raw, "hello report")
	}
}

func TestUploadReport_ParseSpecError(t *testing.T) {
	err := uploadReport(context.Background(), "not-a-valid-spec", "text")
	if err == nil || !strings.Contains(err.Error(), "report-to must be kind/namespace/name") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestUploadReport_ClientBuildError(t *testing.T) {
	useEmptyKubeconfig(t)

	err := uploadReport(context.Background(), "configmap/ns/name", "text")
	if err == nil || !strings.Contains(err.Error(), "build kubernetes client") {
		t.Fatalf("expected client-build error, got %v", err)
	}
}

func TestUploadReport_ConfigMapUpsertError(t *testing.T) {

	t.Setenv("KUBECONFIG", writeUnreachableKubeconfig(t))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := uploadReport(ctx, "configmap/ns/name", "text")
	if err == nil || !strings.Contains(err.Error(), "upsert report ConfigMap") {
		t.Fatalf("expected ConfigMap upsert error against unreachable API, got %v", err)
	}
}

func TestUploadReport_UnsupportedKind(t *testing.T) {

	t.Setenv("KUBECONFIG", writeUnreachableKubeconfig(t))

	err := uploadReport(context.Background(), "widget/ns/name", "text")
	if err == nil || !strings.Contains(err.Error(), "unsupported report-to kind") {
		t.Fatalf("expected unsupported-kind error, got %v", err)
	}
}

func TestWriteSummaryFile_WriteError(t *testing.T) {
	t.Setenv(config.EnvArtifactBaseDir, "")

	badPath := filepath.Join(t.TempDir(), "missing-subdir", "summary.json")

	err := writeSummaryFile(badPath, SessionSummary{TotalEvents: 1})
	if err == nil {
		t.Fatal("expected write error for a nonexistent parent directory, got nil")
	}
}
