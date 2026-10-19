package extractor

import (
	"strings"
	"testing"
)

func TestAnOversizedTracestateIsDiscarded(t *testing.T) {
	e := NewHTTPExtractor()
	tc := e.ExtractFromHeaders(map[string]string{
		"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"tracestate":  "vendor=" + strings.Repeat("x", 4000),
	})
	if tc == nil {
		t.Fatal("a valid traceparent must survive an oversized tracestate")
	}
	if tc.State != "" {
		t.Fatalf("tracestate of %d bytes was kept", len(tc.State))
	}
}

func TestATracestateAtTheLimitIsKept(t *testing.T) {
	e := NewHTTPExtractor()
	state := "vendor=" + strings.Repeat("x", 512-len("vendor="))
	tc := e.ExtractFromHeaders(map[string]string{
		"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"tracestate":  state,
	})
	if tc == nil || tc.State != state {
		t.Fatal("a 512-character tracestate must be kept")
	}
}

func TestAnOversizedSplunkRequestIDIsNotCarriedAsState(t *testing.T) {
	e := NewHTTPExtractor()
	tc := e.ExtractFromHeaders(map[string]string{"x-splunk-requestid": strings.Repeat("r", 1000)})
	if tc == nil || tc.TraceID == "" {
		t.Fatal("the request id must still seed a trace")
	}
	if tc.State != "" {
		t.Fatalf("request id of %d bytes was carried as trace state", len(tc.State))
	}
}
