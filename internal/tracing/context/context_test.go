package context

import (
	"testing"
)

func TestNewTraceContext(t *testing.T) {
	tc := NewTraceContext()
	if tc == nil {
		t.Fatal("NewTraceContext returned nil")
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
		{"valid", map[string]string{"x-b3-traceid": "abc", "x-b3-spanid": "def"}, false},
		{"with sampled", map[string]string{"x-b3-traceid": "abc", "x-b3-spanid": "def", "x-b3-sampled": "1"}, false},
		{"missing trace ID", map[string]string{"x-b3-spanid": "def"}, true},
		{"missing span ID", map[string]string{"x-b3-traceid": "abc"}, true},
		{"empty", map[string]string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := ParseB3TraceContext(tt.headers)
			if (tc == nil) != tt.wantNil {
				t.Errorf("ParseB3TraceContext() = %v, want nil = %v", tc, tt.wantNil)
			}
			if !tt.wantNil && tc != nil {
				if tc.TraceID == "" || tc.SpanID == "" {
					t.Error("TraceID and SpanID should be set")
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
