package stacktrace

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

func plantFIFO(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x (deleted)")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	return path
}

func finishesWithin(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s blocked on a FIFO", what)
	}
}

func TestExeLinkIsTheKernelLinkNotTheReportedName(t *testing.T) {
	orig := config.ProcBasePath
	config.SetProcBasePath("/host/proc")
	t.Cleanup(func() { config.SetProcBasePath(orig) })

	if got, want := exeLink(4242), "/host/proc/4242/exe"; got != want {
		t.Errorf("exeLink = %q, want %q", got, want)
	}
}

func TestSymbolTableLoadDoesNotBlockOnAFIFO(t *testing.T) {
	fifo := plantFIFO(t)
	finishesWithin(t, 5*time.Second, "loadSymbolTable", func() {
		if got := loadSymbolTable(fifo); got != nil {
			t.Errorf("loadSymbolTable(fifo) = %+v, want nil", got)
		}
	})
}

func TestLoadSegmentsDoesNotBlockOnAFIFO(t *testing.T) {
	fifo := plantFIFO(t)
	r := &stackResolver{}
	finishesWithin(t, 5*time.Second, "loadSegments", func() {
		if got := r.loadSegments(fifo); len(got) != 0 {
			t.Errorf("loadSegments(fifo) = %v, want none", got)
		}
	})
}

func TestLazySymbolReadsDoNotBlockOnAFIFO(t *testing.T) {
	fifo := plantFIFO(t)
	table := &symbolTable{elfLazy: true}
	finishesWithin(t, 5*time.Second, "elfSymbols", func() {
		if got := table.elfSymbols(fifo); len(got) != 0 {
			t.Errorf("elfSymbols(fifo) = %v, want none", got)
		}
	})
}

func TestResolveSanitisesSymbolNamesFromTheBinary(t *testing.T) {
	pid := uint32(os.Getpid())
	r := NewResolver()
	key := filepath.Join(config.ProcBasePath, strconv.Itoa(int(pid)), "exe") + "|1234"
	r.inner.cache[key] = "main.\x1b]8;;http://evil\x07click\x1b[2J"

	got := r.Resolve(context.Background(), pid, 0x1234)
	for _, b := range []byte(got) {
		if b == 0x1b || b == 0x07 {
			t.Fatalf("Resolve = %q, want terminal controls stripped", got)
		}
	}
	if got == "" {
		t.Fatal("Resolve returned nothing for a cached frame")
	}
}

func TestSlowTableParseDoesNotStallOtherBinaries(t *testing.T) {
	release := make(chan struct{})
	var loads atomic.Int32
	c := &symbolTableCache{
		statID: func(path string) (fileID, bool) {
			if path == "slow" {
				return fileID{ino: 1}, true
			}
			return fileID{ino: 2}, true
		},
		load: func(path string) *symbolTable {
			loads.Add(1)
			if path == "slow" {
				<-release
			}
			return &symbolTable{path: path}
		},
	}

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.get("slow")
		}()
	}
	time.Sleep(50 * time.Millisecond)

	finishesWithin(t, 2*time.Second, "a second binary behind a slow parse", func() {
		if got := c.get("fast"); got == nil || got.path != "fast" {
			t.Errorf("get(fast) = %+v", got)
		}
	})

	close(release)
	wg.Wait()
	if n := loads.Load(); n != 2 {
		t.Errorf("loads = %d, want 2: concurrent callers for one binary must share a single parse", n)
	}
	if c.len() != 2 {
		t.Errorf("cached tables = %d, want 2", c.len())
	}
}
