package main

import (
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/tracing/exporter"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func TestAnInsecureExporterConfigReachesACleartextCollector(t *testing.T) {
	defer resetTracingConfig()
	t.Setenv("PODTRACE_OTLP_INSECURE", "")
	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel.observability:4318", Insecure: true})

	if _, err := exporter.NewOTLPExporter(config.OTLPEndpoint, 1); err != nil {
		t.Fatalf("insecure: true must let the session export over http, got %v", err)
	}
}

func TestASecureExporterConfigStillRefusesCleartext(t *testing.T) {
	defer resetTracingConfig()
	t.Setenv("PODTRACE_OTLP_INSECURE", "")
	config.OTLPInsecure = true
	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "http://otel.observability:4318"})

	if config.OTLPInsecure {
		t.Fatal("a bundle without insecure: true inherited an earlier opt-in")
	}
	if _, err := exporter.NewOTLPExporter(config.OTLPEndpoint, 1); err == nil {
		t.Fatal("cleartext to a non-loopback collector must still need an opt-in")
	}
}

func TestADataDogBundleWithoutAHeaderNameUsesTheAgentConvention(t *testing.T) {
	defer resetTracingConfig()
	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeDataDog, Endpoint: "datadog-agent:4318", Credential: []byte("k")})

	if config.OTLPHeaders["DD-API-KEY"] != "k" {
		t.Fatalf("OTLPHeaders = %v, want DD-API-KEY", config.OTLPHeaders)
	}
}

func TestAZipkinBundleKeepsTheNativeExporter(t *testing.T) {
	defer resetTracingConfig()
	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeZipkin, Endpoint: "http://zipkin:9411/api/v2/spans"})

	if config.ZipkinEndpoint != "http://zipkin:9411/api/v2/spans" || config.OTLPEndpoint != "" {
		t.Fatalf("Zipkin=%q OTLP=%q", config.ZipkinEndpoint, config.OTLPEndpoint)
	}
}
