package extractor

import (
	"net/http"
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
		{"B3 headers", map[string]string{"x-b3-traceid": "abc", "x-b3-spanid": "def"}, false},
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
