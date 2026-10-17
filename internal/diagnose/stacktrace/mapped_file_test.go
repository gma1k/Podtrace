package stacktrace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func fakeMaps(t *testing.T, pid, maps string) {
	t.Helper()
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, pid), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, pid, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pointProcfsAt(t, base))
}

const deletedExeMaps = "555555554000-555555556000 r-xp 00001000 08:01 100 /tmp/busybox (deleted)\n" +
	"7f0000000000-7f0000100000 r-xp 00028000 08:01 200 /usr/lib/libc.so.6\n" +
	"7f0000200000-7f0000201000 rw-p 00000000 00:00 0 \n" +
	"7ffff7fc1000-7ffff7fc3000 r-xp 00000000 00:00 0 [vdso]\n"

func TestADeletedExecutableStillMatchesItsMappings(t *testing.T) {
	fakeMaps(t, "91", deletedExeMaps)

	got := (&stackResolver{}).exeMappings(91, "/tmp/busybox (deleted)")
	if len(got) != 1 || got[0].start != 0x555555554000 || got[0].pgoff != 0x1000 {
		t.Fatalf("mappings = %+v; readlink keeps \" (deleted)\" and the maps parser drops it, "+
			"so the two must be compared without it", got)
	}
}

func TestAnUnreadableMapsFileIsNotTakenAsUnmapped(t *testing.T) {
	t.Cleanup(pointProcfsAt(t, t.TempDir()))
	if name, unmapped := (&stackResolver{}).otherMappedFile(93, "/bin/app", 0x401000); name != "" || unmapped {
		t.Errorf("got (%q, %v); without maps the executable's own symbols must still be tried", name, unmapped)
	}
}

func TestAnAddressInALibraryIsNamedAfterTheLibrary(t *testing.T) {
	fakeMaps(t, "92", deletedExeMaps)
	r := &stackResolver{}

	for addr, want := range map[uint64]struct {
		name     string
		unmapped bool
	}{
		0x7f0000000123: {"libc.so.6", false},
		0x7ffff7fc1010: {"[vdso]", false},
		0x555555554100: {"", false},
		0x7f0000200010: {"", false},
		0xffffffff:     {"", true},
	} {
		name, unmapped := r.otherMappedFile(92, "/tmp/busybox (deleted)", addr)
		if name != want.name || unmapped != want.unmapped {
			t.Errorf("otherMappedFile(%#x) = (%q, %v), want (%q, %v)", addr, name, unmapped, want.name, want.unmapped)
		}
	}
}

func processWithLibrary(t *testing.T) uint32 {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "94"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(base, "94", "exe")); err != nil {
		t.Fatal(err)
	}
	maps := "00400000-00401000 r-xp 00000000 08:01 100 " + exe + "\n" +
		"7f0000000000-7f0000100000 r-xp 00028000 08:01 200 /usr/lib/libc.so.6\n"
	if err := os.WriteFile(filepath.Join(base, "94", "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pointProcfsAt(t, base))
	return 94
}

func TestResolveNamesALibraryFrameAfterTheLibrary(t *testing.T) {
	pid := processWithLibrary(t)
	r := &stackResolver{cache: map[string]string{}}

	if got := r.resolve(context.Background(), pid, 0x7f0000000123); got != "libc.so.6@0x7f0000000123" {
		t.Errorf("resolve(libc frame) = %q, want libc.so.6@0x7f0000000123", got)
	}
	if got := r.resolve(context.Background(), pid, 0xffffffff); got != "0xffffffff" {
		t.Errorf("resolve(unmapped frame) = %q, want the raw address", got)
	}
}

func TestLoadSegmentsOfARegularFileThatIsNotELF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := readLoadSegments(path); got != nil {
		t.Errorf("readLoadSegments(non-ELF) = %v, want nil", got)
	}
}

func TestAStackStopsAtItsFirstEmptyFrame(t *testing.T) {
	pid := processWithLibrary(t)
	d := &mockDiagnostician{events: []*events.Event{{
		Type:      events.EventLockContention,
		PID:       pid,
		LatencyNS: 5_000_000,
		Stack:     []uint64{0x7f0000000123, 0, 0x7f0000000456},
	}}}

	got := GenerateStackTraceSectionWithContext(d, context.Background())
	if !strings.Contains(got, "#0 libc.so.6@0x7f0000000123") {
		t.Fatalf("want the first frame resolved:\n%s", got)
	}
	if strings.Contains(got, "#1") || strings.Contains(got, "0x7f0000000456") {
		t.Errorf("frames after the zero terminator were printed:\n%s", got)
	}
}
