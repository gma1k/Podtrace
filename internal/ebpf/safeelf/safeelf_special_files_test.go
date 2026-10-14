//go:build linux

package safeelf

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func finishesQuickly(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s blocked on a FIFO with no writer", what)
	}
}

func TestOpeningAFIFOFailsInsteadOfBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "libssl.so.3")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	finishesQuickly(t, "OpenRegular", func() {
		if f, _, err := OpenRegular(fifo); err == nil {
			_ = f.Close()
			t.Error("OpenRegular accepted a FIFO")
		}
	})
	finishesQuickly(t, "Open", func() {
		if f, err := Open(fifo); err == nil {
			_ = f.Close()
			t.Error("Open accepted a FIFO")
		}
	})
}

func TestOpenParsesTheFileThatWasChecked(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	f, fi, err := OpenRegular(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	pinned := PinnedPath(f, exe)
	pi, err := os.Stat(pinned)
	if err != nil {
		t.Fatalf("stat %s: %v", pinned, err)
	}
	if !os.SameFile(fi, pi) {
		t.Errorf("%s does not name the file that was opened", pinned)
	}
}

func TestOpenRejectsAnOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxFileSize + 1); err != nil {
		t.Skipf("truncate: %v", err)
	}
	_ = f.Close()
	if _, _, err := OpenRegular(path); err == nil {
		t.Error("OpenRegular accepted a file over MaxFileSize")
	}
}
