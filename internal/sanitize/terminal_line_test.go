package sanitize

import "testing"

func TestTerminalLineCollapsesWhitespaceAndScrubsControls(t *testing.T) {
	got := TerminalLine("  probe failed:\n\t\x1b[2J  next  ")
	if want := "probe failed: �[2J next"; got != want {
		t.Fatalf("TerminalLine = %q, want %q", got, want)
	}
}
