package probes

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

func TestAGoBinaryIsParsedOncePerAttachPass(t *testing.T) {
	goBinaries.reset()
	t.Cleanup(goBinaries.reset)

	first, ok := loadGoBinary(os.Args[0])
	if !ok {
		t.Skip("the test binary has no pclntab")
	}
	second, _ := loadGoBinary(os.Args[0])
	if first != second {
		t.Error("the same executable was parsed again; every probe site re-read the whole pclntab")
	}
	if _, ok := goSymbolFileOffset(os.Args[0], "runtime.main"); !ok {
		t.Error("runtime.main did not resolve from the cached table")
	}
}

func TestACachedGoBinaryIsDroppedOnceIdle(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	c := &goBinaryCache{now: func() time.Time { return now }}
	c.put(goBinaryKey{fileID: fileID{ino: 1}}, &goBinary{})
	c.put(goBinaryKey{fileID: fileID{ino: 2}}, &goBinary{})
	c.put(goBinaryKey{fileID: fileID{ino: 3}}, &goBinary{})
	if len(c.entries) != maxCachedGoBinaries {
		t.Fatalf("cache holds %d tables, want at most %d", len(c.entries), maxCachedGoBinaries)
	}
	if _, ok := c.get(goBinaryKey{fileID: fileID{ino: 1}}); ok {
		t.Error("the least recently used table survived an overflow")
	}

	now = now.Add(goBinaryTTL)
	c.expire()
	if len(c.entries) != 0 {
		t.Errorf("%d tables still held after %s idle", len(c.entries), goBinaryTTL)
	}
	if c.timer != nil {
		c.timer.Stop()
	}
}

func TestFunctionBytesAreNotReadFromADifferentFile(t *testing.T) {
	goBinaries.reset()
	t.Cleanup(goBinaries.reset)
	bin, ok := loadGoBinary(os.Args[0])
	if !ok {
		t.Skip("the test binary has no pclntab")
	}
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	fn := bin.table.LookupFunc("runtime.main")
	if _, ok := bin.readText(other, fn.Entry, fn.End); ok {
		t.Error("read a function's code out of a file the table was not built from")
	}
}

func TestAKnownPIDDoesNotTriggerAProcRescanPerLibrary(t *testing.T) {
	procWithCgroups(t, map[string]string{
		"100": "0::/kubepods.slice/cri-containerd-containerbbbb.scope\n",
		"200": "0::/kubepods.slice/cri-containerd-containerbbbb.scope\n",
	})
	other := filepath.Join(config.ProcBasePath, "200")
	lib := filepath.Join(other, "root/usr/lib/libpq.so.5")
	if err := os.MkdirAll(filepath.Dir(lib), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lib, []byte("\x7fELF"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := findDBLibsWithPID("containerbbbb", 100, []string{"libpq.so.5"}); len(got) != 0 {
		t.Errorf("found %v through another pid of the container; a known pid must not trigger a full /proc scan", got)
	}
	if got := FindLibcPathWithPID("containerbbbb", 100); got != "" {
		t.Errorf("found libc %q through a /proc rescan", got)
	}
}
