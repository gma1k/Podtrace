package usdt

import (
	"encoding/binary"
	"testing"
)

func TestParseStapsdtNotes_CapsProbeCount(t *testing.T) {
	order := binary.ByteOrder(binary.LittleEndian)
	one := note(order, "stapsdt", 3, stapsdtDesc(order, 0x1000, 0x2000, "p", "n"), -1, -1)

	var data []byte
	for i := 0; i < maxScannedProbes+500; i++ {
		data = append(data, one...)
	}

	got := parseStapsdtNotes(data, order, hostArgArch())
	if len(got) != maxScannedProbes {
		t.Fatalf("parseStapsdtNotes returned %d probes, want the %d cap", len(got), maxScannedProbes)
	}
}

func TestParseStapsdtNotes_UnderCapReturnsAll(t *testing.T) {
	order := binary.ByteOrder(binary.LittleEndian)
	one := note(order, "stapsdt", 3, stapsdtDesc(order, 0x1000, 0x2000, "p", "n"), -1, -1)

	const n = 10
	var data []byte
	for i := 0; i < n; i++ {
		data = append(data, one...)
	}
	if got := parseStapsdtNotes(data, order, hostArgArch()); len(got) != n {
		t.Fatalf("parseStapsdtNotes returned %d probes, want %d", len(got), n)
	}
}
