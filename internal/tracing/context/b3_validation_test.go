package context

import "testing"

func TestParseB3TraceContextRejectsMalformedIDs(t *testing.T) {
	validTrace := "463ac35c9f6413ad48485a3953bb6124"
	validSpan := "a2fb4a1d1a96d312"
	tests := []struct {
		name    string
		traceID string
		spanID  string
	}{
		{"invalid utf8 trace id", "\xff\xfe", validSpan},
		{"non hex trace id", "463ac35c9f6413ad48485a3953bb612g", validSpan},
		{"short trace id", "463ac35c", validSpan},
		{"odd length trace id", "463ac35c9f6413ad48485a3953bb612", validSpan},
		{"all zero trace id", "00000000000000000000000000000000", validSpan},
		{"invalid utf8 span id", validTrace, "\xff"},
		{"short span id", validTrace, "ab"},
		{"all zero span id", validTrace, "0000000000000000"},
		{"non hex span id", validTrace, "a2fb4a1d1a96d31z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := ParseB3TraceContext(map[string]string{"x-b3-traceid": tt.traceID, "x-b3-spanid": tt.spanID})
			if tc != nil {
				t.Fatalf("ParseB3TraceContext accepted %q/%q as %+v", tt.traceID, tt.spanID, tc)
			}
		})
	}
}

func TestParseB3TraceContextPadsSixtyFourBitTraceID(t *testing.T) {
	tc := ParseB3TraceContext(map[string]string{"x-b3-traceid": "48485a3953bb6124", "x-b3-spanid": "a2fb4a1d1a96d312"})
	if tc == nil {
		t.Fatal("64-bit B3 trace id rejected")
	}
	if tc.TraceID != "000000000000000048485a3953bb6124" {
		t.Errorf("TraceID = %q, want zero-padded 32 hex digits", tc.TraceID)
	}
}

func TestParseB3TraceContextLowercasesIDs(t *testing.T) {
	tc := ParseB3TraceContext(map[string]string{"x-b3-traceid": "463AC35C9F6413AD48485A3953BB6124", "x-b3-spanid": "A2FB4A1D1A96D312"})
	if tc == nil {
		t.Fatal("upper-case B3 ids rejected")
	}
	if tc.TraceID != "463ac35c9f6413ad48485a3953bb6124" || tc.ParentSpanID != "a2fb4a1d1a96d312" {
		t.Errorf("ids not lower-cased: trace=%q parent=%q", tc.TraceID, tc.ParentSpanID)
	}
}
