package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
)

func TestVendorExporters_MissingCredentialBuildsNoClient(t *testing.T) {
	cases := map[string]func(CRKey, *BundlePayload, ...sdkOption) (interface{ Name() string }, error){
		"datadog": func(k CRKey, b *BundlePayload, o ...sdkOption) (interface{ Name() string }, error) {
			return newDataDogEventExporter(k, b, o...)
		},
		"splunk": func(k CRKey, b *BundlePayload, o ...sdkOption) (interface{ Name() string }, error) {
			return newSplunkEventExporter(k, b, o...)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			orig := newTraceExporter
			built := 0
			newTraceExporter = func(ctx context.Context, c otlptrace.Client) (*otlptrace.Exporter, error) {
				built++
				return orig(ctx, c)
			}
			t.Cleanup(func() { newTraceExporter = orig })

			_, err := build(CRKey{Name: "cr"}, &BundlePayload{Endpoint: "http://collector:4318"})
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("err = %v, want a missing credential error", err)
			}
			if built != 0 {
				t.Errorf("OTLP client built %d times before the credential check", built)
			}
		})
	}
}

type shutdownCountingSpanExporter struct {
	noopSpanExporter
	shutdowns int
}

func (e *shutdownCountingSpanExporter) Shutdown(context.Context) error {
	e.shutdowns++
	return nil
}

func TestNewSDKEventExporter_ResourceFailureShutsDownSpanExporter(t *testing.T) {
	orig := buildResource
	buildResource = func(context.Context, ...resource.Option) (*resource.Resource, error) {
		return nil, errors.New("schema conflict")
	}
	t.Cleanup(func() { buildResource = orig })

	span := &shutdownCountingSpanExporter{}
	if _, err := newSDKEventExporter("otlp", CRKey{Name: "cr"}, &BundlePayload{}, span); err == nil {
		t.Fatal("expected the resource failure to surface")
	}
	if span.shutdowns != 1 {
		t.Errorf("span exporter shutdowns = %d, want 1", span.shutdowns)
	}
}
