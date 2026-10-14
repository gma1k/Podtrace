package probes

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func debugLinkSection(name string) []byte {
	data := append([]byte(name), 0)
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	return append(data, 0, 0, 0, 0)
}

func fakeTargetProcess(t *testing.T, pid string, exe string) string {
	t.Helper()
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	t.Cleanup(func() { config.ProcBasePath = orig })
	pidDir := filepath.Join(base, pid)
	if err := os.MkdirAll(filepath.Join(pidDir, "root"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(pidDir, "root")
}

func TestADebugLinkIsFoundNextToTheBinaryInsideTheTarget(t *testing.T) {
	root := fakeTargetProcess(t, "52001", "/app/server")
	if err := os.MkdirAll(filepath.Join(root, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app/server.debug"), buildELFWithSections(nil), 0o644); err != nil {
		t.Fatal(err)
	}
	target, err := elfFromSections([]fixtureSection{{name: ".gnu_debuglink", typ: uint32(elf.SHT_PROGBITS), data: debugLinkSection("server.debug")}})
	if err != nil {
		t.Fatal(err)
	}

	dbg, source := openDebugInfo(target, 52001)
	if dbg == nil {
		t.Fatal("the debug file beside the binary was not found; the lookup searched /proc/<pid> instead of the binary's directory")
	}
	_ = dbg.Close()
	if source != "debug-link" {
		t.Errorf("source = %q, want debug-link", source)
	}
}

func TestADebugLinkUnderUsrLibDebugMirrorsTheBinaryDirectory(t *testing.T) {
	root := fakeTargetProcess(t, "52002", "/opt/svc/bin/server")
	mirrored := filepath.Join(root, "usr/lib/debug/opt/svc/bin")
	if err := os.MkdirAll(mirrored, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirrored, "server.debug"), buildELFWithSections(nil), 0o644); err != nil {
		t.Fatal(err)
	}
	target, err := elfFromSections([]fixtureSection{{name: ".gnu_debuglink", typ: uint32(elf.SHT_PROGBITS), data: debugLinkSection("server.debug")}})
	if err != nil {
		t.Fatal(err)
	}

	dbg, _ := openDebugInfo(target, 52002)
	if dbg == nil {
		t.Fatal("the debug file under /usr/lib/debug/<binary dir> was not found")
	}
	_ = dbg.Close()
}

func TestNoDebugLookupRunsWithoutATargetProcess(t *testing.T) {
	target, err := elfFromSections([]fixtureSection{{name: ".gnu_debuglink", typ: uint32(elf.SHT_PROGBITS), data: debugLinkSection("server.debug")}})
	if err != nil {
		t.Fatal(err)
	}
	if dbg, _ := openDebugInfo(target, 0); dbg != nil {
		_ = dbg.Close()
		t.Error("openDebugInfo searched a root for pid 0, which names no process")
	}
}
