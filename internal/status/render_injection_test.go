package status

import (
	"bytes"
	"strings"
	"testing"
)

func TestAForgedPodNameCannotDriveTheTerminal(t *testing.T) {
	r := fullReport()
	r.Issues[0].Pod = "checkout-1\x1b]52;c;cHduZWQ=\x07\x1b[2J"
	var buf bytes.Buffer
	if err := RenderText(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(buf.String(), "\x1b\x07") {
		t.Fatalf("pod column carried control bytes: %q", buf.String())
	}
}

func TestAWarningCarryingAnAgentResponseCannotDriveTheTerminal(t *testing.T) {
	r := fullReport()
	r.Warnings = []string{"no profile from a on n1: the server responded with \x1b[2J\x1b]0;owned\x07"}
	var buf bytes.Buffer
	if err := RenderText(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(buf.String(), "\x1b\x07") {
		t.Fatalf("warning carried control bytes: %q", buf.String())
	}
}
