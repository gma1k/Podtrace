package probes

import (
	"testing"
)

func TestH3OffsetsFromDWARFRealBinary(t *testing.T) {
	bin := goFixtureBinary(t)
	off, ok := h3OffsetsFromDWARF(bin, 0)
	if !ok {
		t.Fatal("expected DWARF offset resolution to succeed on the fixture binary")
	}
	want := h3FieldOffsets{Method: 0, URL: 16, Path: 56, Status: 16}
	if off != want {
		t.Fatalf("DWARF offsets = %+v, want %+v", off, want)
	}
}

func TestResolveH3FieldOffsetsPrefersDWARF(t *testing.T) {
	bin := goFixtureBinary(t)
	off, source := resolveH3FieldOffsets(bin, 0)
	if source != "dwarf" {
		t.Fatalf("source = %q, want dwarf when the binary carries usable DWARF", source)
	}
	if off != (h3FieldOffsets{Method: 0, URL: 16, Path: 56, Status: 16}) {
		t.Fatalf("offsets = %+v", off)
	}
}
