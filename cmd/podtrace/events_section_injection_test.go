package main

import (
	"strings"
	"testing"
	"time"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
)

func TestAnEventMessageCannotDriveTheOperatorsTerminal(t *testing.T) {
	section := formatK8sEventsSection([]podEvents{{
		pod: "shop/checkout-1",
		events: []*pkgkube.K8sEvent{{
			Type:      "Warning\x1b[8m",
			Reason:    "Unhealthy\x9b2J",
			Message:   "Liveness probe failed: \x1b]52;c;cHduZWQ=\x07\x1b[2J\nfake line",
			Timestamp: time.Unix(0, 0),
		}},
	}})
	if strings.IndexByte(section, 0x1b) >= 0 || strings.IndexByte(section, 0x07) >= 0 || strings.IndexByte(section, 0x9b) >= 0 {
		t.Fatalf("event text reached the terminal unsanitised: %q", section)
	}
	if strings.Contains(section, "\nfake line") {
		t.Fatalf("an event message started a line of its own: %q", section)
	}
	if !strings.Contains(section, "Liveness probe failed:") {
		t.Fatalf("the readable part of the message was lost: %q", section)
	}
}
