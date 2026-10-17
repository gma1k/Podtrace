package sanitize

import "testing"

func TestAStrayC1ByteIsReplaced(t *testing.T) {
	for in, want := range map[string]string{
		"a\x9b2Jb":     "a�2Jb",
		"\x9b\x9b":     "��",
		"x\xffy":       "x�y",
		"münchen":      "münchen",
		"keep � as is": "keep � as is",
	} {
		if got := Terminal(in); got != want {
			t.Errorf("Terminal(%q) = %q, want %q", in, got, want)
		}
	}
}
