package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func TestApplyPayloadToConfig_OTLP(t *testing.T) {
	defer resetTracingConfig()
	mustApplyPayload(t, &bundle.Payload{
		Type:     bundle.TypeOTLP,
		Endpoint: "otel:4318",
		Sample:   ptrFloat(0.25),
	})
	if config.OTLPEndpoint != "https://otel:4318" {
		t.Errorf("OTLPEndpoint=%q", config.OTLPEndpoint)
	}
	if config.TracingSampleRate != 0.25 {
		t.Errorf("SampleRate=%v", config.TracingSampleRate)
	}
}

func TestApplyPayloadToConfig_OTLP_ClearsOtherExporters(t *testing.T) {
	defer resetTracingConfig()
	config.JaegerEndpoint = "http://localhost:14268/api/traces"
	config.ZipkinEndpoint = "http://localhost:9411/api/v2/spans"
	config.SplunkEndpoint = "http://localhost:8088/services/collector"
	config.DataDogEndpoint = "http://localhost:8126/v0.4/traces"

	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel:4318"})

	if config.OTLPEndpoint != "https://otel:4318" {
		t.Errorf("OTLPEndpoint=%q, want https://otel:4318", config.OTLPEndpoint)
	}
	for name, got := range map[string]string{
		"Jaeger": config.JaegerEndpoint, "Zipkin": config.ZipkinEndpoint,
		"Splunk": config.SplunkEndpoint, "DataDog": config.DataDogEndpoint,
	} {
		if got != "" {
			t.Errorf("%sEndpoint=%q, want cleared (single-exporter bundle)", name, got)
		}
	}
}

func TestApplyPayloadToConfig_DataDogCredentialSetsToken(t *testing.T) {
	defer resetTracingConfig()
	mustApplyPayload(t, &bundle.Payload{
		Type:       bundle.TypeDataDog,
		Endpoint:   "ddtrace:8126",
		Credential: []byte("dd-api-key"),
	})
	if config.DataDogEndpoint != "ddtrace:8126" {
		t.Errorf("DataDogEndpoint=%q", config.DataDogEndpoint)
	}
	if config.DataDogAPIKey != "dd-api-key" {
		t.Errorf("DataDogAPIKey lost")
	}
}

func TestApplyPayloadToConfig_SplunkCredentialSetsToken(t *testing.T) {
	defer resetTracingConfig()
	mustApplyPayload(t, &bundle.Payload{
		Type:       bundle.TypeSplunk,
		Endpoint:   "splunk:8088",
		Credential: []byte("hec-token"),
	})
	if config.SplunkToken != "hec-token" {
		t.Errorf("SplunkToken lost")
	}
}

func TestApplyPayloadToConfig_NilIsNoop(t *testing.T) {
	defer resetTracingConfig()
	before := config.OTLPEndpoint
	mustApplyPayload(t, nil)
	if config.OTLPEndpoint != before {
		t.Errorf("nil payload mutated config: OTLPEndpoint=%q", config.OTLPEndpoint)
	}
}

func TestApplyPayloadToConfig_Jaeger(t *testing.T) {
	defer resetTracingConfig()
	mustApplyPayload(t, &bundle.Payload{
		Type:     bundle.TypeJaeger,
		Endpoint: "jaeger:4318",
	})
	if config.JaegerEndpoint != "jaeger:4318" {
		t.Errorf("JaegerEndpoint=%q", config.JaegerEndpoint)
	}
}

func TestApplyPayloadToConfig_Zipkin(t *testing.T) {
	defer resetTracingConfig()
	mustApplyPayload(t, &bundle.Payload{
		Type:     bundle.TypeZipkin,
		Endpoint: "zipkin:9411",
	})
	if config.ZipkinEndpoint != "zipkin:9411" {
		t.Errorf("ZipkinEndpoint=%q", config.ZipkinEndpoint)
	}
}

func TestApplyPayloadToConfig_NilSampleDoesNotOverride(t *testing.T) {
	defer resetTracingConfig()
	config.TracingSampleRate = 0.5
	mustApplyPayload(t, &bundle.Payload{
		Type:     bundle.TypeOTLP,
		Endpoint: "otel:4318",
		Sample:   nil,
	})
	if config.TracingSampleRate != 0.5 {
		t.Errorf("unset sample must not override; got %v", config.TracingSampleRate)
	}
}

func TestApplyExporterFromFile_RoundTrip(t *testing.T) {
	defer resetTracingConfig()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.yaml")
	contents := []byte(`
type: otlp
endpoint: otel.observability:4318
protocol: http
insecure: true
sample: 0.1
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applyExporterFromFile(path); err != nil {
		t.Fatalf("applyExporterFromFile: %v", err)
	}
	if !config.TracingEnabled {
		t.Error("TracingEnabled not flipped true")
	}
	if config.OTLPEndpoint != "http://otel.observability:4318" {
		t.Errorf("endpoint=%q", config.OTLPEndpoint)
	}
	if config.TracingSampleRate != 0.1 {
		t.Errorf("sample=%v", config.TracingSampleRate)
	}
}

// Regression test: the export gates in runPodtrace check the enableTracing
// flag var, not config.TracingEnabled.
func TestApplyExporterFromFile_EnablesExportGate(t *testing.T) {
	restoreTracingFlagGlobals(t)
	defer resetTracingConfig()
	enableTracing = false

	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.yaml")
	if err := os.WriteFile(path, []byte("type: otlp\nendpoint: otel:4318\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applyExporterFromFile(path); err != nil {
		t.Fatalf("applyExporterFromFile: %v", err)
	}
	if !enableTracing {
		t.Error("exporter bundle did not enable the export gate (enableTracing)")
	}
}

func TestApplyExporterFromFile_MissingFileErrors(t *testing.T) {
	defer resetTracingConfig()
	if err := applyExporterFromFile("/no/such/path"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestApplyExporterFromFile_MissingCredentialFileIsNonFatal(t *testing.T) {
	defer resetTracingConfig()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.yaml")
	if err := os.WriteFile(path, []byte("type: otlp\nendpoint: otel:4318\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PODTRACE_EXPORTER_CREDENTIAL_FILE", filepath.Join(dir, "does-not-exist"))
	if err := applyExporterFromFile(path); err != nil {
		t.Fatalf("missing credential file should be non-fatal: %v", err)
	}
	if config.OTLPEndpoint != "https://otel:4318" {
		t.Errorf("endpoint=%q", config.OTLPEndpoint)
	}
}

func TestApplyExporterFromFile_CredentialFileLoaded(t *testing.T) {
	defer resetTracingConfig()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.yaml")
	credPath := filepath.Join(dir, "credential")
	if err := os.WriteFile(path, []byte("type: datadog\nendpoint: ddtrace:8126\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credPath, []byte("dd-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PODTRACE_EXPORTER_CREDENTIAL_FILE", credPath)
	if err := applyExporterFromFile(path); err != nil {
		t.Fatal(err)
	}
	if config.DataDogAPIKey != "dd-key" {
		t.Errorf("DataDogAPIKey=%q want dd-key", config.DataDogAPIKey)
	}
}

func TestApplyExporterFromFile_EnvCredentialWins(t *testing.T) {
	defer resetTracingConfig()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.yaml")
	if err := os.WriteFile(path, []byte("type: splunk\nendpoint: splunk:8088\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PODTRACE_EXPORTER_CREDENTIAL", "env-hec-token")
	t.Setenv("PODTRACE_EXPORTER_CREDENTIAL_FILE", filepath.Join(dir, "ignored"))
	if err := applyExporterFromFile(path); err != nil {
		t.Fatalf("applyExporterFromFile: %v", err)
	}
	if config.SplunkToken != "env-hec-token" {
		t.Errorf("SplunkToken=%q want env-hec-token (env credential must win)", config.SplunkToken)
	}
}

func TestApplyExporterFromFile_MalformedYAMLErrors(t *testing.T) {
	defer resetTracingConfig()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.yaml")
	if err := os.WriteFile(path, []byte("\tnot: [valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applyExporterFromFile(path); err == nil {
		t.Fatal("expected error for malformed bundle YAML")
	}
}

func resetTracingConfig() {
	config.TracingEnabled = false
	config.OTLPEndpoint = config.DefaultOTLPEndpoint
	config.JaegerEndpoint = config.DefaultJaegerEndpoint
	config.ZipkinEndpoint = config.DefaultZipkinEndpoint
	config.SplunkEndpoint = config.DefaultSplunkEndpoint
	config.SplunkToken = ""
	config.DataDogEndpoint = config.DefaultDataDogEndpoint
	config.DataDogAPIKey = ""
	config.TracingSampleRate = config.DefaultTracingSampleRate
	config.OTLPHeaders = nil
}

func ptrFloat(v float64) *float64 { return &v }

func mustApplyPayload(t *testing.T, p *bundle.Payload) {
	t.Helper()
	if err := applyPayloadToConfig(p); err != nil {
		t.Fatal(err)
	}
}
