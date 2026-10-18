package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func writeSessionMounts(t *testing.T, bundleYAML string, credentialFiles map[string]string) string {
	t.Helper()
	exporterDir, credentialDir := t.TempDir(), t.TempDir()
	path := filepath.Join(exporterDir, "bundle.yaml")
	if err := os.WriteFile(path, []byte(bundleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, value := range credentialFiles {
		if err := os.WriteFile(filepath.Join(credentialDir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PODTRACE_EXPORTER_CREDENTIAL", "")
	t.Setenv("PODTRACE_EXPORTER_CREDENTIAL_FILE", filepath.Join(credentialDir, bundle.CredentialKey))
	return path
}

func TestASessionSendsEveryOTLPHeaderTheAgentWould(t *testing.T) {
	defer resetTracingConfig()
	path := writeSessionMounts(t, `
type: otlp
endpoint: otel.observability:4318
headers:
  X-Tenant: team-a
headerName: Authorization
`, map[string]string{
		bundle.CredentialKey:                       "Bearer s3cr3t",
		bundle.SecretHeaderKeyPrefix + "X-Api-Key": "k-123",
	})

	if err := applyExporterFromFile(path); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"X-Tenant": "team-a", "Authorization": "Bearer s3cr3t", "X-Api-Key": "k-123"}
	if !reflect.DeepEqual(config.OTLPHeaders, want) {
		t.Fatalf("OTLPHeaders = %v, want %v", config.OTLPHeaders, want)
	}
}

func TestASessionKeepsTLSUnlessTheExporterIsInsecure(t *testing.T) {
	defer resetTracingConfig()
	cases := map[string]struct {
		payload bundle.Payload
		want    string
	}{
		"scheme-less, secure":   {bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel:4318"}, "https://otel:4318"},
		"scheme-less, insecure": {bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel:4318", Insecure: true}, "http://otel:4318"},
		"explicit scheme kept":  {bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "http://otel:4318"}, "http://otel:4318"},
	}
	for name, tc := range cases {
		if err := applyPayloadToConfig(&tc.payload); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if config.OTLPEndpoint != tc.want {
			t.Errorf("%s: OTLPEndpoint = %q, want %q", name, config.OTLPEndpoint, tc.want)
		}
	}
}

func TestASecretBackedHeaderWithoutItsCredentialFailsLoudly(t *testing.T) {
	defer resetTracingConfig()
	err := applyPayloadToConfig(&bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel:4318", HeaderName: "Authorization"})
	if err == nil || !strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("expected a missing-credential error naming the header, got %v", err)
	}
}

func TestAnUnsendableHeaderFailsLoudly(t *testing.T) {
	defer resetTracingConfig()
	err := applyPayloadToConfig(&bundle.Payload{
		Type: bundle.TypeOTLP, Endpoint: "otel:4318",
		Headers: map[string]string{"X-Bad": "line\r\nInjected: yes"},
	})
	if err == nil {
		t.Fatal("a header value carrying CRLF must be rejected")
	}
}

func TestApplyingABundleClearsHeadersFromAnEarlierOne(t *testing.T) {
	defer resetTracingConfig()
	config.OTLPHeaders = map[string]string{"Authorization": "stale"}
	if err := applyPayloadToConfig(&bundle.Payload{Type: bundle.TypeZipkin, Endpoint: "http://zipkin:9411"}); err != nil {
		t.Fatal(err)
	}
	if config.OTLPHeaders != nil {
		t.Fatalf("OTLPHeaders = %v, want cleared", config.OTLPHeaders)
	}
}
