//go:build linux

package probes

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
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

func TestAFIFONamedLikeALibraryDoesNotHangTheAttachPath(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "usr/lib/libssl.so.3")
	if err := os.MkdirAll(filepath.Dir(fifo), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}

	finishesQuickly(t, "openExecutable", func() {
		if exe, err := openExecutable(fifo); err == nil {
			_ = exe.Close()
			t.Error("openExecutable accepted a FIFO")
		}
	})
	finishesQuickly(t, "openELFWithinRoot", func() {
		if f, err := openELFWithinRoot(root, "usr/lib/libssl.so.3"); err == nil {
			_ = f.Close()
			t.Error("openELFWithinRoot accepted a FIFO")
		}
	})
	finishesQuickly(t, "the rootfs library scan", func() {
		if got := scanLibDirsWithinRoot(root, []string{"libssl"}); len(got) != 0 {
			t.Errorf("the scan offered a FIFO as a library: %v", got)
		}
	})
}

func TestAByNameAttachIsRefusedWhenTheSymbolTablesAreTooLarge(t *testing.T) {
	exe := &executable{symbolsUnsafe: true}
	_, err := exe.Uprobe("SSL_write", nil, nil)
	if !errors.Is(err, errSymbolTablesTooLarge) {
		t.Fatalf("Uprobe = %v, want errSymbolTablesTooLarge before cilium parses the tables", err)
	}
	_, err = exe.Uretprobe("SSL_write", nil, &link.UprobeOptions{})
	if !errors.Is(err, errSymbolTablesTooLarge) {
		t.Fatalf("Uretprobe = %v, want errSymbolTablesTooLarge", err)
	}
}

func TestAnExecutableKeepsTheCheckedFileOpenUntilClosed(t *testing.T) {
	exe, err := openExecutable(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	pinned := filepath.Join("/proc/self/fd", strconv.Itoa(int(exe.file.Fd())))
	if _, err := os.Stat(pinned); err != nil {
		t.Fatalf("the pinned path %s is not open: %v", pinned, err)
	}
	if err := exe.Close(); err != nil {
		t.Fatal(err)
	}
	if exe.symbolsUnsafe {
		t.Error("the test binary's symbol tables were judged too large")
	}
}

func TestGoBuildInfoIsReadOnlyFromARegularFile(t *testing.T) {
	if _, ok := readGoBuildInfo(os.Args[0]); !ok {
		t.Error("no build info read from the Go test binary")
	}
	fifo := filepath.Join(t.TempDir(), "server")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	finishesQuickly(t, "readGoBuildInfo", func() {
		if _, ok := readGoBuildInfo(fifo); ok {
			t.Error("read build info from a FIFO")
		}
	})
}
