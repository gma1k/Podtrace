package sanitize

import "testing"

func TestDirectionMarksAndInvisiblesAreReplaced(t *testing.T) {
	for in, want := range map[string]string{
		"user\u200fgnp.exe":          "user\ufffdgnp.exe",
		"a\u200eb":                   "a\ufffdb",
		"a\u061cb":                   "a\ufffdb",
		"\xef\xbb\xbfpod":            "\ufffdpod",
		"ad\u200bmin":                "ad\ufffdmin",
		"\U0001F469\u200d\U0001F4BB": "\U0001F469\u200d\U0001F4BB",
		"\u0995\u09cd\u200c\u09b7":   "\u0995\u09cd\u200c\u09b7",
	} {
		if got := Terminal(in); got != want {
			t.Errorf("Terminal(%q) = %q, want %q", in, got, want)
		}
	}
}
