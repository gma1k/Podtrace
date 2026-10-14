package probes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/procfs"
)

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("\x7fELF"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestAnAbsoluteSymlinkOutOfTheRootfsIsNotFollowedIntoTheAgent(t *testing.T) {
	root := t.TempDir()
	agentFile := filepath.Join(t.TempDir(), "node-libc.so.6")
	writeFile(t, agentFile)
	symlink(t, agentFile, filepath.Join(root, "lib/x86_64-linux-gnu/libc.so.6"))

	if got := fileWithinRoot(root, "/lib/x86_64-linux-gnu/libc.so.6"); got != "" {
		t.Fatalf("resolved to %q; an absolute symlink in the container must resolve inside its rootfs, not the agent's", got)
	}
}

func TestAnAbsoluteSymlinkInsideTheRootfsResolvesInsideIt(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr/lib/libc-2.36.so"))
	symlink(t, "/usr/lib/libc-2.36.so", filepath.Join(root, "lib/libc.so.6"))

	want := filepath.Join(root, "usr/lib/libc-2.36.so")
	if got := fileWithinRoot(root, "/lib/libc.so.6"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestASymlinkedDirectoryResolvesInsideTheRootfs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr/lib/libssl.so.3"))
	symlink(t, "/usr/lib", filepath.Join(root, "lib"))
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "libssl.so.3"))
	symlink(t, outside, filepath.Join(root, "opt/lib"))

	if got, want := fileWithinRoot(root, "/lib/libssl.so.3"), filepath.Join(root, "usr/lib/libssl.so.3"); got != want {
		t.Errorf("through /lib: got %q, want %q", got, want)
	}
	if got := fileWithinRoot(root, "/opt/lib/libssl.so.3"); got != "" {
		t.Errorf("through a directory symlink out of the rootfs: got %q, want nothing", got)
	}
}

func TestDotDotCannotClimbAboveTheRootfs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/passwd"))
	symlink(t, "../../../../../etc/passwd", filepath.Join(root, "lib/libc.so.6"))

	if got, want := fileWithinRoot(root, "/lib/libc.so.6"), filepath.Join(root, "etc/passwd"); got != want {
		t.Errorf("got %q, want %q clamped at the rootfs", got, want)
	}
	if got, want := fileWithinRoot(root, "/../../etc/passwd"), filepath.Join(root, "etc/passwd"); got != want {
		t.Errorf("got %q, want %q clamped at the rootfs", got, want)
	}
}

func TestASymlinkLoopIsRejected(t *testing.T) {
	root := t.TempDir()
	symlink(t, "/lib/b", filepath.Join(root, "lib/a"))
	symlink(t, "/lib/a", filepath.Join(root, "lib/b"))

	if got := fileWithinRoot(root, "/lib/a"); got != "" {
		t.Errorf("got %q for a symlink loop", got)
	}
}

func TestOnlyRegularFilesAreReturned(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "lib/libc.so.6"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := fileWithinRoot(root, "/lib/libc.so.6"); got != "" {
		t.Errorf("got %q for a directory", got)
	}
}

func TestTheFixedPathLibcFallbackStaysInsideTheTarget(t *testing.T) {
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	t.Cleanup(func() { config.ProcBasePath = orig })

	const pid = 51001
	root := filepath.Join(base, "51001", "root")
	agentFile := filepath.Join(t.TempDir(), "libc.so.6")
	writeFile(t, agentFile)
	for _, p := range getArchitecturePaths() {
		symlink(t, agentFile, filepath.Join(root, p))
	}

	if got := findLibcInProcess(pid); got != "" {
		t.Fatalf("findLibcInProcess = %q; a container symlink steered the libc uprobe onto a file outside it", got)
	}
	if got := findDBLibsInRoot(root, []string{"libc.so.6"}); len(got) != 0 {
		t.Fatalf("findDBLibsInRoot = %v; a container symlink steered a DB uprobe outside the container", got)
	}
}

func TestTheGoBinaryFallbacksStayInsideTheTarget(t *testing.T) {
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	procfs.ResetForTesting()
	t.Cleanup(func() {
		config.ProcBasePath = orig
		procfs.ResetForTesting()
	})

	const pid = 51002
	pidDir := filepath.Join(base, "51002")
	root := filepath.Join(pidDir, "root")
	agentFile := filepath.Join(t.TempDir(), "kubelet")
	writeFile(t, agentFile)
	symlink(t, agentFile, filepath.Join(root, "app/server"))
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("/app/server\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("server\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := findGoBinaryInContainer("", pid); got != "" {
		t.Fatalf("findGoBinaryInContainer = %q; the cmdline/comm fallback followed a symlink out of the container", got)
	}
}

func TestTheTLSRootfsScanDoesNotListADirectoryOutsideTheRootfs(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "libssl.so.3"))
	symlink(t, outside, filepath.Join(root, "usr/lib/x86_64-linux-gnu"))

	if got := scanLibDirsWithinRoot(root, []string{"libssl"}); len(got) != 0 {
		t.Fatalf("scan found %v through a directory symlink out of the rootfs", got)
	}
}

func TestTheTLSRootfsScanOnlyOffersSharedLibrariesInLibraryDirectories(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr/lib/libssl.so.3"))
	writeFile(t, filepath.Join(root, "usr/lib/openssl.cnf"))
	writeFile(t, filepath.Join(root, "srv/data/libssl.so.3"))
	writeFile(t, filepath.Join(root, "home/app/ssl-cert.pem"))

	got := scanLibDirsWithinRoot(root, tlsLibPatterns)
	if len(got) != 1 || got[0] != filepath.Join(root, "usr/lib/libssl.so.3") {
		t.Errorf("scan offered %v, want only usr/lib/libssl.so.3; every candidate costs a full ELF symbol load", got)
	}
}
