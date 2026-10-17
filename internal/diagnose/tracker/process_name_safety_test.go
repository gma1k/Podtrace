package tracker

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestProcessNamesFromTheKernelAreMadeSafeToPrint(t *testing.T) {
	infos := AnalyzeProcessActivity([]*events.Event{
		{PID: 4242, ProcessName: "\x1b[2J\x1b[H", Type: events.EventRead},
	})
	if len(infos) != 1 {
		t.Fatalf("got %d processes, want 1", len(infos))
	}
	if strings.ContainsRune(infos[0].Name, 0x1b) {
		t.Errorf("name = %q, want the escape stripped at the source", infos[0].Name)
	}
}
