//go:build linux

package hostfs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAFIFOIsNotARegularFile(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "libssl.so.3")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if IsRegularFile(fifo) {
		t.Error("IsRegularFile accepted a FIFO; opening it to parse an ELF blocks until a writer appears")
	}
}

func TestWalkRegularSkipsFIFOsAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "libssl.so.3")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "libssl.so.fifo"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "libssl.so")); err != nil {
		t.Fatal(err)
	}

	var got []string
	if err := WalkRegular(dir, func(path string, _ os.FileInfo) error {
		got = append(got, path)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != real {
		t.Errorf("WalkRegular visited %v, want only %s", got, real)
	}
}
