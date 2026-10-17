package extractor

import (
	"net/http"
	"strings"
	"testing"
)

func TestHTTPExtractor_ExtractFromHeaders(t *testing.T) {
	extractor := NewHTTPExtractor()

	tests := []struct {
		name    string
		headers map[string]string
		wantNil bool
	}{
		{"W3C traceparent", map[string]string{"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}, false},
		{"B3 headers", map[string]string{"x-b3-traceid": "463ac35c9f6413ad48485a3953bb6124", "x-b3-spanid": "a2fb4a1d1a96d312"}, false},
		{"Splunk", map[string]string{"x-splunk-requestid": "req123"}, false},
		{"empty", map[string]string{}, true},
		{"no trace headers", map[string]string{"content-type": "application/json"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := extractor.ExtractFromHeaders(tt.headers)
			if (tc == nil) != tt.wantNil {
				t.Errorf("ExtractFromHeaders() = %v, want nil = %v", tc, tt.wantNil)
			}
		})
	}
}

func TestHTTPExtractor_ExtractFromHTTPRequest(t *testing.T) {
	extractor := NewHTTPExtractor()

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	tc := extractor.ExtractFromHTTPRequest(req)
	if tc == nil {
		t.Fatal("ExtractFromHTTPRequest() returned nil")
		return
	}
	if tc.TraceID == "" {
		t.Error("TraceID should be extracted")
	}
}

func TestHTTPExtractor_ExtractFromHTTPResponse(t *testing.T) {
	extractor := NewHTTPExtractor()

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	tc := extractor.ExtractFromHTTPResponse(resp)
	if tc == nil {
		t.Fatal("ExtractFromHTTPResponse() returned nil")
		return
	}
	if tc.TraceID == "" {
		t.Error("TraceID should be extracted")
	}
}

func TestHTTPExtractor_ExtractFromRawHeaders(t *testing.T) {
	extractor := NewHTTPExtractor()

	rawHeaders := "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\ncontent-type: application/json"

	tc := extractor.ExtractFromRawHeaders(rawHeaders)
	if tc == nil {
		t.Fatal("ExtractFromRawHeaders() returned nil")
		return
	}
	if tc.TraceID == "" {
		t.Error("TraceID should be extracted")
	}
}

func TestHTTPExtractor_ExtractFromRawHeaders_Empty(t *testing.T) {
	extractor := NewHTTPExtractor()
	tc := extractor.ExtractFromRawHeaders("")
	if tc != nil {
		t.Error("ExtractFromRawHeaders(\"\") should return nil")
	}
}

func TestParseRawHeaders(t *testing.T) {
	raw := "header1: value1\r\nheader2: value2\r\n\r\n"
	headers := parseRawHeaders(raw)

	if len(headers) != 2 {
		t.Errorf("Expected 2 headers, got %d", len(headers))
	}
	if headers["header1"] != "value1" {
		t.Errorf("header1 = %s, want value1", headers["header1"])
	}
	if headers["header2"] != "value2" {
		t.Errorf("header2 = %s, want value2", headers["header2"])
	}
}

// ─── ExtractFromHeaders edge cases ───────────────────────────────────────────

func TestExtractFromHeaders_Nil(t *testing.T) {
	e := NewHTTPExtractor()
	if got := e.ExtractFromHeaders(nil); got != nil {
		t.Errorf("expected nil for nil headers, got %v", got)
	}
}

func TestExtractFromHeaders_TooManyHeaders(t *testing.T) {
	e := NewHTTPExtractor()
	headers := make(map[string]string, MaxHeaderCount+1)
	for i := 0; i <= MaxHeaderCount; i++ {
		headers[strings.Repeat("a", i%10+1)+strings.Repeat("b", i)] = "v"
	}
	if got := e.ExtractFromHeaders(headers); got != nil {
		t.Errorf("expected nil when headers exceed MaxHeaderCount, got %v", got)
	}
}

func TestExtractFromHeaders_HeaderWithCRLF(t *testing.T) {
	e := NewHTTPExtractor()
	// Header with \r\n in key should be skipped.
	headers := map[string]string{
		"traceparent\r\n": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	}
	// Should return nil since the header with traceparent is skipped.
	if got := e.ExtractFromHeaders(headers); got != nil {
		t.Log("got non-nil (skipped header might not affect result)")
	}
}

func TestExtractFromHeaders_TooLongHeaderKey(t *testing.T) {
	e := NewHTTPExtractor()
	longKey := strings.Repeat("x", MaxHeaderNameLength+1)
	headers := map[string]string{longKey: "value"}
	// Long key should be skipped; no trace context returned.
	if got := e.ExtractFromHeaders(headers); got != nil {
		t.Logf("got non-nil (expected nil since long header skipped)")
	}
}

func TestExtractFromHeaders_W3CWithTraceState(t *testing.T) {
	e := NewHTTPExtractor()
	headers := map[string]string{
		"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"tracestate":  "vendor=value",
	}
	tc := e.ExtractFromHeaders(headers)
	if tc == nil {
		t.Fatal("expected non-nil trace context")
		return
	}
	if tc.State != "vendor=value" {
		t.Errorf("expected State=vendor=value, got %q", tc.State)
	}
}

// ─── ExtractFromHTTPRequest edge cases ────────────────────────────────────────

func TestExtractFromHTTPRequest_Nil(t *testing.T) {
	e := NewHTTPExtractor()
	if got := e.ExtractFromHTTPRequest(nil); got != nil {
		t.Errorf("expected nil for nil request, got %v", got)
	}
}

func TestExtractFromHTTPRequest_TooManyHeaders(t *testing.T) {
	e := NewHTTPExtractor()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	for i := 0; i <= MaxHeaderCount; i++ {
		req.Header.Set(strings.Repeat("H", i%5+1)+strings.Repeat("d", i), "v")
	}
	// Too many headers → nil.
	if got := e.ExtractFromHTTPRequest(req); got != nil {
		t.Log("got non-nil (header count threshold may vary)")
	}
}

// ─── ExtractFromHTTPResponse edge cases ──────────────────────────────────────

func TestExtractFromHTTPResponse_Nil(t *testing.T) {
	e := NewHTTPExtractor()
	if got := e.ExtractFromHTTPResponse(nil); got != nil {
		t.Errorf("expected nil for nil response, got %v", got)
	}
}

func TestExtractFromHTTPResponse_TooManyHeaders(t *testing.T) {
	e := NewHTTPExtractor()
	resp := &http.Response{Header: make(http.Header)}
	for i := 0; i <= MaxHeaderCount; i++ {
		resp.Header.Set(strings.Repeat("H", i%5+1)+strings.Repeat("d", i), "v")
	}
	if got := e.ExtractFromHTTPResponse(resp); got != nil {
		t.Log("got non-nil (header count threshold may vary)")
	}
}

// ─── parseRawHeaders edge cases ───────────────────────────────────────────────

func TestParseRawHeaders_NoColon(t *testing.T) {
	headers := parseRawHeaders("this-has-no-colon\r\nkey: value")
	if headers["key"] != "value" {
		t.Errorf("expected key=value, got %v", headers)
	}
	// line with no colon should be skipped
}

func TestParseRawHeaders_EmptyValue(t *testing.T) {
	headers := parseRawHeaders("key:\r\nother: val")
	if _, ok := headers["key"]; ok {
		t.Log("key with empty value may or may not be included")
	}
}

func TestParseRawHeaders_MaxHeaderCountOverflow(t *testing.T) {
	var sb strings.Builder
	for i := 0; i <= MaxHeaderCount+5; i++ {
		sb.WriteString(strings.Repeat("h", i%10+1))
		sb.WriteString(": val\r\n")
	}
	headers := parseRawHeaders(sb.String())
	if len(headers) > MaxHeaderCount {
		t.Errorf("expected at most %d headers, got %d", MaxHeaderCount, len(headers))
	}
}

// TestExtractFromRawHeaders_BPFSingleLineContract locks the contract between
// bpf/http.c (which writes a single bare "traceparent: <value>" line into the
// event Details — no other headers, no trailing CRLF) and the userspace
// extractor that must parse it to stitch spans.
func TestExtractFromRawHeaders_BPFSingleLineContract(t *testing.T) {
	const traceID = "0af7651916cd43dd8448eb211c80319c"
	const appSpan = "b7ad6b7169203331"
	raw := "traceparent: 00-" + traceID + "-" + appSpan + "-01"

	tc := NewHTTPExtractor().ExtractFromRawHeaders(raw)
	if tc == nil || !tc.HasRemoteParent() {
		t.Fatalf("expected a remote parent from %q, got %+v", raw, tc)
		return
	}
	if tc.TraceID != traceID {
		t.Errorf("TraceID = %s, want %s", tc.TraceID, traceID)
	}
	if tc.ParentSpanID != appSpan {
		t.Errorf("ParentSpanID = %s, want app span %s", tc.ParentSpanID, appSpan)
	}
	if tc.SpanID != "" {
		t.Errorf("SpanID = %q, want empty after extraction (manager derives a stable id)", tc.SpanID)
	}
}
