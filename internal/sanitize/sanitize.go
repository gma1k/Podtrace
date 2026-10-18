// Package sanitize scrubs attacker-influenced strings before they are
// rendered into human-facing text (diagnose reports) that an operator may
// view in a terminal.
package sanitize

import (
	"strings"
	"unicode/utf8"
)

const Replacement = '�'

// TerminalLine is Terminal for a single table cell or log line: runs of
// whitespace, newlines included, collapse to one space first, so a value
// cannot break the layout it is printed into.
func TerminalLine(s string) string {
	return Terminal(strings.Join(strings.Fields(s), " "))
}

// Terminal returns s with every terminal-unsafe rune, and every byte that is
// not valid UTF-8, replaced by Replacement. A stray byte is unsafe because a
// terminal that is not decoding UTF-8 reads 0x9b as an 8-bit CSI.
func Terminal(s string) string {
	if clean(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if unsafeRune(r) || (r == utf8.RuneError && size == 1) {
			b.WriteRune(Replacement)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// clean reports whether s needs no replacement.
func clean(s string) bool {
	for i := 0; i < len(s); {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if unsafeRune(r) || (r == utf8.RuneError && size == 1) {
			return false
		}
		i += size
	}
	return true
}

// unsafeRune reports whether r can manipulate a terminal or forge report
// structure when printed:
//
//   - C0 controls (0x00–0x1f): includes ESC (starts ANSI sequences) and
//     TAB/CR/LF (would forge report columns and lines);
//   - DEL (0x7f) and the C1 controls (0x80–0x9f);
//   - the Unicode line/paragraph separators (U+2028/U+2029);
//   - the bidirectional override and isolate format characters
//     (U+202A–U+202E, U+2066–U+2069) — the Trojan-Source spoofing class.
//
// Every other rune, including normal printable Unicode, is preserved.
func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x2028, r == 0x2029:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	default:
		return false
	}
}
