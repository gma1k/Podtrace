package report

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestOOMKillsShowTheVictimsMemory(t *testing.T) {
	out := formatOOMKills([]*events.Event{
		{Type: events.EventOOMKill, Target: "stress", Bytes: 150 * 1024 * 1024},
		{Type: events.EventOOMKill, Target: "stress", Bytes: 50 * 1024 * 1024},
	})
	for _, want := range []string{"OOM kills: 2", "Total memory killed: 200.00 MB", "Average memory per kill: 100.00 MB", "- stress (150.00 MB)"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
}

func TestOOMKillsWithoutMemoryDoNotClaimZeroBytes(t *testing.T) {
	out := formatOOMKills([]*events.Event{{Type: events.EventOOMKill, Target: "stress"}})
	if strings.Contains(out, "0 B") {
		t.Errorf("a kernel that reports no size must not show 0 B:\n%s", out)
	}
	for _, want := range []string{"Memory at kill: not reported by this kernel", "    - stress\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
}
