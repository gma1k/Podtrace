package profiling

import (
	"strings"
	"testing"
	"time"
)

func TestReportSanitizesHotFrameAndHeapFunctionNames(t *testing.T) {
	cr := &CorrelatedResult{
		PageFaultCounts: map[uint32]int{},
		HotFrames:       []FrameCount{{Frame: "evil\x1b[2J\x1b]8;;http://x\x07frame", Count: 3}},
		HeapProfile: &ProfileResult{
			Available:    true,
			TopFunctions: []FunctionSample{{Function: "main.\x1b[31mleak\u202e", Bytes: 2048, Count: 1}},
		},
	}
	out := GenerateSection(cr, time.Second)
	for _, bad := range []string{"\x1b", "\x07", "\u202e"} {
		if strings.Contains(out, bad) {
			t.Errorf("report contains unsafe %q:\n%q", bad, out)
		}
	}
	if !strings.Contains(out, "frame") || !strings.Contains(out, "leak") {
		t.Errorf("sanitized names should keep their printable text:\n%q", out)
	}
}

func TestParseHeapTextSanitizesFunctionNames(t *testing.T) {
	text := "heap profile: 1: 1024 [1: 1024] @ heap/1048576\n" +
		"1: 1024 [1: 1024] @ 0x1\n" +
		"#\t0x1\tmain.\x1b[31mAlloc\x9b2J+0x10\tfile.go:1\n"
	samples := parseHeapText(text)
	if len(samples) != 1 {
		t.Fatalf("expected one sample, got %v", samples)
	}
	if strings.Contains(samples[0].Function, "\x1b") || strings.Contains(samples[0].Function, "\x9b") {
		t.Errorf("function name not sanitized: %q", samples[0].Function)
	}
}

func TestParseHeapTextLeavesCleanNamesUnchanged(t *testing.T) {
	text := "heap profile: 1: 1024 [1: 1024] @ heap/1048576\n" +
		"1: 1024 [1: 1024] @ 0x1\n" +
		"#\t0x1\tnet/http.(*persistConn).roundTrip+0x10\tfile.go:1\n"
	samples := parseHeapText(text)
	if len(samples) != 1 || samples[0].Function != "net/http.(*persistConn).roundTrip" {
		t.Errorf("unexpected samples %v", samples)
	}
}
