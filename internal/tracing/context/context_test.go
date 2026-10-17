package context

import (
	"testing"
)

func TestNewTraceContext(t *testing.T) {
	tc := NewTraceContext()
	if tc == nil {
		t.Fatal("NewTraceContext returned nil")
		return
	}
	if tc.TraceID == "" {
		t.Error("TraceID is empty")
	}
	if tc.SpanID == "" {
		t.Error("SpanID is empty")
	}
	if !tc.IsSampled() {
		t.Error("New trace context should be sampled by default")
	}
}

func TestTraceContext_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		traceID   string
		spanID    string
		wantValid bool
	}{
		{"valid", "abc123", "def456", true},
		{"empty trace ID", "", "def456", false},
		{"empty span ID", "abc123", "", false},
		{"both empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &TraceContext{
				TraceID: tt.traceID,
				SpanID:  tt.spanID,
			}
			if got := tc.IsValid(); got != tt.wantValid {
				t.Errorf("IsValid() = %v, want %v", got, tt.wantValid)
			}
		})
	}
}

func TestTraceContext_IsSampled(t *testing.T) {
	tests := []struct {
		name  string
		flags uint8
		want  bool
	}{
		{"sampled", 0x01, true},
		{"not sampled", 0x00, false},
		{"other flags", 0x02, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &TraceContext{Flags: tt.flags}
			if got := tc.IsSampled(); got != tt.want {
				t.Errorf("IsSampled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTraceContext_SetSampled(t *testing.T) {
	tc := &TraceContext{Flags: 0x00}
	tc.SetSampled(true)
	if !tc.IsSampled() {
		t.Error("SetSampled(true) did not set sampled flag")
	}

	tc.SetSampled(false)
	if tc.IsSampled() {
		t.Error("SetSampled(false) did not clear sampled flag")
	}
}

func TestTraceContext_CreateChild(t *testing.T) {
	parent := NewTraceContext()
	parent.TraceID = "parent-trace-id"
	parent.SpanID = "parent-span-id"

	child := parent.CreateChild()
	if child == nil {
		t.Fatal("CreateChild returned nil")
		return
	}
	if child.TraceID != parent.TraceID {
		t.Errorf("Child TraceID = %s, want %s", child.TraceID, parent.TraceID)
	}
	if child.ParentSpanID != parent.SpanID {
		t.Errorf("Child ParentSpanID = %s, want %s", child.ParentSpanID, parent.SpanID)
	}
	if child.SpanID == parent.SpanID {
		t.Error("Child SpanID should be different from parent")
	}
}

func TestParseW3CTraceParent(t *testing.T) {
	tests := []struct {
		name         string
		traceParent  string
		wantErr      bool
		checkTraceID bool
	}{
		{"valid", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", false, true},
		{"empty", "", true, false},
		{"invalid format", "invalid", true, false},
		{"wrong version", "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", true, false},
		{"short trace ID", "00-abc-00f067aa0ba902b7-01", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc, err := ParseW3CTraceParent(tt.traceParent)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseW3CTraceParent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkTraceID {
				if tc == nil || tc.TraceID == "" {
					t.Error("TraceID should be set")
				}
			}
		})
	}
}

func TestParseB3TraceContext(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		wantNil bool
	}{
		{"valid", map[string]string{"x-b3-traceid": "463ac35c9f6413ad48485a3953bb6124", "x-b3-spanid": "a2fb4a1d1a96d312"}, false},
		{"with sampled", map[string]string{"x-b3-traceid": "463ac35c9f6413ad48485a3953bb6124", "x-b3-spanid": "a2fb4a1d1a96d312", "x-b3-sampled": "1"}, false},
		{"missing trace ID", map[string]string{"x-b3-spanid": "a2fb4a1d1a96d312"}, true},
		{"missing span ID", map[string]string{"x-b3-traceid": "463ac35c9f6413ad48485a3953bb6124"}, true},
		{"empty", map[string]string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := ParseB3TraceContext(tt.headers)
			if (tc == nil) != tt.wantNil {
				t.Errorf("ParseB3TraceContext() = %v, want nil = %v", tc, tt.wantNil)
			}
			if !tt.wantNil && tc != nil {
				if tc.TraceID == "" || tc.ParentSpanID == "" {
					t.Error("TraceID and ParentSpanID should be set")
				}
				if tc.SpanID != "" {
					t.Errorf("SpanID should be empty after extraction, got %q", tc.SpanID)
				}
				if spanID, ok := tt.headers["x-b3-spanid"]; ok && tc.SpanID == spanID {
					t.Error("SpanID must not reuse the caller's x-b3-spanid (collision)")
				}
			}
		})
	}
}

func TestTraceContext_ToW3CTraceParent(t *testing.T) {
	tc := &TraceContext{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "00f067aa0ba902b7",
		Flags:   0x01,
	}

	result := tc.ToW3CTraceParent()
	if result == "" {
		t.Error("ToW3CTraceParent() returned empty string")
	}
	if result[:3] != "00-" {
		t.Error("W3C traceparent should start with version 00")
	}
}

func TestTraceContext_ToB3Headers(t *testing.T) {
	tc := &TraceContext{
		TraceID:      "abc123",
		SpanID:       "def456",
		ParentSpanID: "parent789",
		Flags:        0x01,
	}

	headers := tc.ToB3Headers()
	if headers == nil {
		t.Fatal("ToB3Headers() returned nil")
		return
	}
	if headers["X-B3-TraceId"] != tc.TraceID {
		t.Errorf("X-B3-TraceId = %s, want %s", headers["X-B3-TraceId"], tc.TraceID)
	}
	if headers["X-B3-SpanId"] != tc.SpanID {
		t.Errorf("X-B3-SpanId = %s, want %s", headers["X-B3-SpanId"], tc.SpanID)
	}
	if headers["X-B3-Sampled"] != "1" {
		t.Error("X-B3-Sampled should be 1 when sampled")
	}
}

// ─── ParseW3CTraceParent edge cases ──────────────────────────────────────────

func TestParseW3CTraceParent_ShortParentID(t *testing.T) {
	// Parent ID must be 16 chars; provide only 8.
	_, err := ParseW3CTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa-01")
	if err == nil {
		t.Error("expected error for short parent ID")
	}
}

func TestParseW3CTraceParent_InvalidFlagsHex(t *testing.T) {
	// Flags must be valid hex; "gg" is not.
	_, err := ParseW3CTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-gg")
	if err == nil {
		t.Error("expected error for invalid flags hex")
	}
}

func TestParseW3CTraceParent_ShortFlagsLength(t *testing.T) {
	// Flags must be 2 chars.
	_, err := ParseW3CTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1")
	if err == nil {
		t.Error("expected error for single-char flags")
	}
}

// ─── ParseB3TraceContext edge cases ──────────────────────────────────────────

func TestParseB3TraceContext_FlagsOne(t *testing.T) {
	// x-b3-flags: "1" should set sampled.
	headers := map[string]string{
		"x-b3-traceid": "463ac35c9f6413ad48485a3953bb6124",
		"x-b3-spanid":  "a2fb4a1d1a96d312",
		"x-b3-flags":   "1",
	}
	tc := ParseB3TraceContext(headers)
	if tc == nil {
		t.Fatal("expected non-nil context")
		return
	}
	if !tc.IsSampled() {
		t.Error("expected sampled when x-b3-flags=1")
	}
}

func TestParseB3TraceContext_SampledTrue(t *testing.T) {
	// x-b3-sampled: "true" should set sampled.
	headers := map[string]string{
		"x-b3-traceid": "463ac35c9f6413ad48485a3953bb6124",
		"x-b3-spanid":  "a2fb4a1d1a96d312",
		"x-b3-sampled": "true",
	}
	tc := ParseB3TraceContext(headers)
	if tc == nil {
		t.Fatal("expected non-nil context")
		return
	}
	if !tc.IsSampled() {
		t.Error("expected sampled when x-b3-sampled=true")
	}
}

func TestParseB3TraceContext_WithParentSpanID(t *testing.T) {
	headers := map[string]string{
		"x-b3-traceid":      "463ac35c9f6413ad48485a3953bb6124",
		"x-b3-spanid":       "a2fb4a1d1a96d312",
		"x-b3-parentspanid": "0020000000000001",
	}
	tc := ParseB3TraceContext(headers)
	if tc == nil {
		t.Fatal("expected non-nil context")
		return
	}
	if tc.ParentSpanID != "a2fb4a1d1a96d312" {
		t.Errorf("expected ParentSpanID=a2fb4a1d1a96d312 (caller span), got %q", tc.ParentSpanID)
	}
	if tc.SpanID != "" {
		t.Errorf("expected empty SpanID after extraction, got %q", tc.SpanID)
	}
}

// ─── ToW3CTraceParent edge cases ─────────────────────────────────────────────

func TestToW3CTraceParent_Invalid(t *testing.T) {
	tc := &TraceContext{TraceID: "", SpanID: ""}
	if got := tc.ToW3CTraceParent(); got != "" {
		t.Errorf("expected empty string for invalid context, got %q", got)
	}
}

// ─── ToB3Headers edge cases ───────────────────────────────────────────────────

func TestToB3Headers_Invalid(t *testing.T) {
	tc := &TraceContext{TraceID: "", SpanID: ""}
	if got := tc.ToB3Headers(); got != nil {
		t.Errorf("expected nil for invalid context, got %v", got)
	}
}

func TestToB3Headers_NoParentSpanID_NotSampled(t *testing.T) {
	tc := &TraceContext{
		TraceID: "abc123",
		SpanID:  "def456",
		Flags:   0x00, // not sampled
	}
	headers := tc.ToB3Headers()
	if headers == nil {
		t.Fatal("expected non-nil headers for valid context")
		return
	}
	if _, ok := headers["X-B3-ParentSpanID"]; ok {
		t.Error("expected no X-B3-ParentSpanID when ParentSpanID is empty")
	}
	if _, ok := headers["X-B3-Sampled"]; ok {
		t.Error("expected no X-B3-Sampled when not sampled")
	}
}
