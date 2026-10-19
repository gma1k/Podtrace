package config

import (
	"os"
	"testing"
)

var initialTracingEndpoints = map[string]string{
	"PODTRACE_OTLP_ENDPOINT":    OTLPEndpoint,
	"PODTRACE_DATADOG_ENDPOINT": DataDogEndpoint,
	"PODTRACE_ZIPKIN_ENDPOINT":  ZipkinEndpoint,
	"PODTRACE_JAEGER_ENDPOINT":  JaegerEndpoint,
	"PODTRACE_SPLUNK_ENDPOINT":  SplunkEndpoint,
}

func TestOnlyOTLPHasADefaultTracingEndpoint(t *testing.T) {
	for env, got := range initialTracingEndpoints {
		if env == "PODTRACE_OTLP_ENDPOINT" {
			continue
		}
		if os.Getenv(env) != "" {
			continue
		}
		if got != "" {
			t.Errorf("%s unset but the endpoint defaults to %q: --tracing would start an exporter nobody configured", env, got)
		}
	}
	if got := initialTracingEndpoints["PODTRACE_OTLP_ENDPOINT"]; os.Getenv("PODTRACE_OTLP_ENDPOINT") == "" && got != DefaultOTLPEndpoint {
		t.Errorf("OTLPEndpoint = %q, want the documented default %q", got, DefaultOTLPEndpoint)
	}
}

func TestAnExporterConfigCanOptOTLPIntoCleartext(t *testing.T) {
	t.Setenv("PODTRACE_OTLP_INSECURE", "")
	saved := OTLPInsecure
	t.Cleanup(func() { OTLPInsecure = saved })

	OTLPInsecure = false
	if OTLPAllowInsecureNonLoopback() {
		t.Fatal("cleartext allowed without any opt-in")
	}
	OTLPInsecure = true
	if !OTLPAllowInsecureNonLoopback() {
		t.Fatal("insecure: true from the exporter configuration was ignored")
	}
}
