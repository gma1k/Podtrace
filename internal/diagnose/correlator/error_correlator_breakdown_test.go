package correlator

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gma1k/podtrace/internal/events"
)

func errorEvent(typ events.EventType, code int32, target string) *events.Event {
	return &events.Event{
		Type:      typ,
		Error:     code,
		Target:    target,
		Timestamp: uint64(time.Now().UnixNano()),
	}
}

func TestErrorSummaryNamesWhichEventsWereCounted(t *testing.T) {
	ec := NewErrorCorrelator(30 * time.Second)
	ec.AddEvent(errorEvent(events.EventConnect, -111, "10.0.0.1:5432"), nil)
	ec.AddEvent(errorEvent(events.EventConnect, -111, "10.0.0.2:5432"), nil)
	ec.AddEvent(errorEvent(events.EventExec, -2, "/usr/sbin/tlsclient"), nil)

	summary := ec.GetErrorSummary()
	connect := fmt.Sprintf("    - %s (code: -111): 2, e.g. 10.0.0.1:5432\n", errorEvent(events.EventConnect, 0, "").TypeString())
	exec := fmt.Sprintf("    - %s (code: -2): 1, e.g. /usr/sbin/tlsclient\n", errorEvent(events.EventExec, 0, "").TypeString())
	for _, want := range []string{"  Total errors: 3\n", "  Errors by operation:\n", connect, exec} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}
	if strings.Index(summary, connect) > strings.Index(summary, exec) {
		t.Errorf("the most frequent error must come first:\n%s", summary)
	}
}

func TestErrorBreakdownCapsRows(t *testing.T) {
	var errs []*ErrorEvent
	for code := int32(1); code <= maxBreakdownRows+3; code++ {
		errs = append(errs, &ErrorEvent{Operation: "connect", ErrorCode: -code})
	}
	out := errorBreakdown(errs)
	if got := strings.Count(out, "    - connect"); got != maxBreakdownRows {
		t.Errorf("listed %d rows, want %d:\n%s", got, maxBreakdownRows, out)
	}
	if !strings.Contains(out, "    - ... 3 more kinds\n") {
		t.Errorf("the rows past the cap must be summarised:\n%s", out)
	}
}

func TestErrorBreakdownSanitisesAndTruncatesTargets(t *testing.T) {
	long := "\x1b[31m" + strings.Repeat("é", maxExampleTargetLen)
	out := errorBreakdown([]*ErrorEvent{{Operation: "http", ErrorCode: -1, Target: long}})
	if strings.Contains(out, "\x1b") {
		t.Errorf("an escape sequence from the target reached the report: %q", out)
	}
	if !utf8.ValidString(out) {
		t.Errorf("truncation split a rune: %q", out)
	}
	if !strings.Contains(out, "...") {
		t.Errorf("a long target must be truncated: %q", out)
	}
}

func TestErrorChainRootCauseTargetIsSanitised(t *testing.T) {
	ec := NewErrorCorrelator(30 * time.Second)
	base := time.Now()
	for i := 0; i < 3; i++ {
		e := errorEvent(events.EventConnect, -111, "evil\x1b[2J:80")
		e.Timestamp = uint64(base.Add(time.Duration(i) * time.Second).UnixNano())
		ec.AddEvent(e, nil)
	}
	summary := ec.GetErrorSummary()
	if !strings.Contains(summary, "Root cause: ") {
		t.Fatalf("expected an error chain with a root cause:\n%s", summary)
	}
	if strings.Contains(summary, "\x1b") {
		t.Errorf("an escape sequence from a target reached the report:\n%q", summary)
	}
}

func TestErrorBreakdownOrdersTiesByOperationThenCode(t *testing.T) {
	out := errorBreakdown([]*ErrorEvent{
		{Operation: "write", ErrorCode: -5},
		{Operation: "connect", ErrorCode: -113},
		{Operation: "connect", ErrorCode: -111},
	})
	want := "  Errors by operation:\n" +
		"    - connect (code: -111): 1\n" +
		"    - connect (code: -113): 1\n" +
		"    - write (code: -5): 1\n"
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}
