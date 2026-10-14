package probes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestH3OffsetsForGoVersion_RealGoBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	off, source := h3OffsetsForGoVersion(exe)
	if !strings.HasPrefix(source, "version:") {
		t.Fatalf("source = %q, want a \"version:\" prefix for a real Go binary", source)
	}
	if !strings.Contains(source, "go") {
		t.Errorf("source = %q, want it to embed the Go version string", source)
	}
	if off != h3DefaultOffsets {
		t.Errorf("offsets = %+v, want the default table %+v", off, h3DefaultOffsets)
	}
}

func TestH3OffsetsForGoVersion_NonGoFileFallsBackToDefault(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-a-go-binary")
	if err := os.WriteFile(p, []byte("just some bytes, not an ELF"), 0o644); err != nil {
		t.Fatal(err)
	}
	off, source := h3OffsetsForGoVersion(p)
	if source != "default" {
		t.Fatalf("source = %q, want \"default\" when build info is unreadable", source)
	}
	if off != h3DefaultOffsets {
		t.Errorf("offsets = %+v, want %+v", off, h3DefaultOffsets)
	}
}

func TestResolveH3FieldOffsets_FallsBackWhenNoDWARF(t *testing.T) {
	p := filepath.Join(t.TempDir(), "plain-file")
	if err := os.WriteFile(p, []byte("no dwarf, no build info"), 0o644); err != nil {
		t.Fatal(err)
	}
	off, source := resolveH3FieldOffsets(p, 0)
	if source != "default" {
		t.Fatalf("source = %q, want \"default\" for a non-Go, DWARF-less file", source)
	}
	if off != h3DefaultOffsets {
		t.Errorf("offsets = %+v, want %+v", off, h3DefaultOffsets)
	}
}
