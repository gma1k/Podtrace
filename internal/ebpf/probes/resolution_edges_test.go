//go:build linux

package probes

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gma1k/podtrace/internal/config"
)

func containerRootfs(t *testing.T, containerID string) string {
	t.Helper()
	base := t.TempDir()
	orig := config.DockerBasePath
	config.DockerBasePath = base
	t.Cleanup(func() { config.DockerBasePath = orig })
	t.Setenv("PODTRACE_CONTAINERD_OVERLAY_PATTERN", filepath.Join(t.TempDir(), "snap", "*", "fs"))
	t.Setenv("PODTRACE_CONTAINERD_NATIVE_PATTERN", "[")
	return filepath.Join(base, containerID, "rootfs")
}

func TestTheRuntimeRootfsIsSearchedWhenNoProcessResolves(t *testing.T) {
	procWithCgroups(t, map[string]string{})
	root := containerRootfs(t, "cidrootfs")
	writeFile(t, filepath.Join(root, "lib/libc.so.6"))
	writeFile(t, filepath.Join(root, "usr/lib/libpq.so.5"))
	writeFile(t, filepath.Join(root, "usr/lib/libssl.so.3"))
	writeFile(t, filepath.Join(root, "app/main"))

	if got := findLibcInContainer("cidrootfs"); got != filepath.Join(root, "lib/libc.so.6") {
		t.Errorf("findLibcInContainer = %q", got)
	}
	if got := findDBLibsInContainer("cidrootfs", []string{"libpq.so.5"}); len(got) != 1 {
		t.Errorf("findDBLibsInContainer = %v", got)
	}
	if got := findTLSLibsInContainerWithPID("cidrootfs", 31337, []string{"libssl"}); len(got) != 1 {
		t.Errorf("findTLSLibsInContainerWithPID = %v", got)
	}
	if got := findGoBinaryInContainer("cidrootfs", 31337); got != filepath.Join(root, "app/main") {
		t.Errorf("findGoBinaryInContainer = %q", got)
	}
}

func TestAContainerdSnapshotNamedForTheContainerIsSearched(t *testing.T) {
	procWithCgroups(t, map[string]string{})
	containerRootfs(t, "unused")
	snap := t.TempDir()
	t.Setenv("PODTRACE_CONTAINERD_OVERLAY_PATTERN", filepath.Join(snap, "*", "fs"))
	writeFile(t, filepath.Join(snap, "cidsnap", "fs", "lib/libc.so.6"))

	if got := containerRootfsPaths("cidsnap"); len(got) != 1 {
		t.Fatalf("containerRootfsPaths = %v, want the snapshot", got)
	}
	if got := findLibcInContainerRootfs("cidsnap"); got == "" {
		t.Error("libc in a containerd snapshot was not found")
	}
}

func TestTheContainerProcessRootIsSearchedForLibc(t *testing.T) {
	procWithCgroups(t, map[string]string{"77": "0::/kubepods/cri-containerd-cidproc.scope\n"})
	writeFile(t, filepath.Join(config.ProcBasePath, "77", "root", "lib/libc.so.6"))
	if got := findLibcInContainer("cidproc"); got != filepath.Join(config.ProcBasePath, "77", "root", "lib/libc.so.6") {
		t.Errorf("findLibcInContainer = %q", got)
	}
}

func TestALibraryDirectoryThatCannotBeListedIsSkipped(t *testing.T) {
	if _, err := readDirLimited(filepath.Join(t.TempDir(), "missing"), 10); err == nil {
		t.Error("listing a missing directory succeeded")
	}
	file := filepath.Join(t.TempDir(), "file")
	writeFile(t, file)
	if _, err := readDirLimited(file, 10); err == nil {
		t.Error("listing a regular file succeeded")
	}
}

func TestAMalformedStatHasNoStartTime(t *testing.T) {
	procWithCgroups(t, map[string]string{})
	base := config.ProcBasePath
	for pid, stat := range map[string]string{"61": "61 no-parenthesis S 1", "62": "62 (short) S 1 2 3"} {
		writeFileContent(t, filepath.Join(base, pid, "stat"), stat)
	}
	if _, ok := processStartTime(61); ok {
		t.Error("a stat line with no comm parentheses gave a start time")
	}
	if _, ok := processStartTime(62); ok {
		t.Error("a truncated stat line gave a start time")
	}
}

func writeFileContent(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPathsResolvedWhileThePidWasReusedAreDiscarded(t *testing.T) {
	procWithCgroups(t, map[string]string{})
	pidDir := filepath.Join(config.ProcBasePath, "63")
	writeFileContent(t, filepath.Join(pidDir, "maps"),
		"00400000-00401000 r-xp 00000000 00:00 0 /app/server\n7f0000000000-7f0000001000 r-xp 00000000 00:00 0 /usr/lib/libssl.so.3\n")
	writeFile(t, filepath.Join(pidDir, "root", "app/server"))
	writeFile(t, filepath.Join(pidDir, "root", "usr/lib/libssl.so.3"))

	calls := 0
	orig := processStartTimeOf
	processStartTimeOf = func(uint32) (uint64, bool) { calls++; return uint64(calls), true }
	t.Cleanup(func() { processStartTimeOf = orig })

	if got := mappedFilesMatching(63, []string{"libssl"}); got != nil {
		t.Errorf("mappedFilesMatching = %v from a pid reused mid-scan", got)
	}
	if got := findGoBinaryViaProcessMaps(63); got != "" {
		t.Errorf("findGoBinaryViaProcessMaps = %q from a pid reused mid-scan", got)
	}

	processStartTimeOf = func(uint32) (uint64, bool) { return 5, true }
	if got := mappedFilesMatching(63, []string{"libssl"}); len(got) != 1 {
		t.Errorf("mappedFilesMatching = %v for a stable process", got)
	}
}

func TestInRootChecksFailClosed(t *testing.T) {
	if _, _, err := statWithinRoot(filepath.Join(t.TempDir(), "missing"), "x"); err == nil {
		t.Error("statWithinRoot accepted a missing root")
	}
	root := t.TempDir()
	host := filepath.Join(t.TempDir(), "host-file")
	writeFile(t, host)
	if confirmWithinRoot(root, "not-there", host) {
		t.Error("a path missing inside the root was confirmed by a host file of the same name")
	}

	orig := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { openat2 = orig })
	if _, supported, _ := statWithinRoot(root, "x"); supported {
		t.Error("ENOSYS was not reported as an unsupported kernel")
	}
	if !confirmWithinRoot(root, "x", host) {
		t.Error("without openat2 the manual in-root resolution must stand on its own")
	}
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.EACCES }
	if _, supported, err := statWithinRoot(root, "x"); !supported || !errors.Is(err, unix.EACCES) {
		t.Errorf("an openat2 failure = %v supported=%v, want it surfaced", err, supported)
	}
}

func TestTheTargetsExecutableDirectoryNeedsAnAbsoluteLink(t *testing.T) {
	procWithCgroups(t, map[string]string{})
	if got := executableDirInTarget(64); got != "" {
		t.Errorf("executableDirInTarget with no exe link = %q", got)
	}
	if err := os.MkdirAll(filepath.Join(config.ProcBasePath, "65"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("relative/server", filepath.Join(config.ProcBasePath, "65", "exe")); err != nil {
		t.Fatal(err)
	}
	if got := executableDirInTarget(65); got != "" {
		t.Errorf("executableDirInTarget with a relative link = %q", got)
	}
	if err := os.MkdirAll(filepath.Join(config.ProcBasePath, "66"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/srv/app/server (deleted)", filepath.Join(config.ProcBasePath, "66", "exe")); err != nil {
		t.Fatal(err)
	}
	if got := executableDirInTarget(66); got != "/srv/app" {
		t.Errorf("executableDirInTarget for a deleted binary = %q, want /srv/app", got)
	}
}

func TestBinariesWithoutDebugInfoTryTheTargetsDebugFiles(t *testing.T) {
	root := fakeTargetProcess(t, "52010", "/app/server")
	bin := filepath.Join(root, "app/server")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, buildELFWithSections(nil), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := h3OffsetsFromDWARF(bin, 52010); ok {
		t.Error("HTTP/3 offsets resolved from a binary with no DWARF and no debug file")
	}
	if _, _, ok := openDWARF(bin, 52010); ok {
		t.Error("DWARF opened for a binary with no DWARF and no debug file")
	}
	if _, ok := poolOffsetsFromDWARF(bin, 52010); ok {
		t.Error("pool offsets resolved from a binary with no DWARF and no debug file")
	}

	const pid = 4402
	syntheticProc(t, pid, rustLikeSections("f"))
	if got := AttachRustlsProbes(placeholderPrograms("uprobe_rustls_write", "uprobe_rustls_read", "uretprobe_rustls_read"), pid); len(got) != 0 {
		t.Error("rustls probes attached to a binary without rustls")
	}
	if got := AttachQuicheRustProbes(placeholderPrograms("uprobe_quiche_rs_send_request"), pid); len(got) != 0 {
		t.Error("quiche probes attached to a binary without quiche")
	}
}

type sysless struct{ fs.FileInfo }

func (sysless) Sys() any { return nil }

func TestGoBinaryEdges(t *testing.T) {
	goBinaries.reset()
	t.Cleanup(goBinaries.reset)
	bin, ok := loadGoBinary(os.Args[0])
	if !ok {
		t.Skip("the test binary has no pclntab")
	}
	if _, ok := bin.fileOffset(1); ok {
		t.Error("an address outside every segment mapped to a file offset")
	}
	fn := bin.table.LookupFunc("runtime.main")
	if _, ok := bin.readText(os.Args[0], fn.End, fn.Entry); ok {
		t.Error("read an inverted range")
	}
	if _, ok := bin.readText(filepath.Join(t.TempDir(), "missing"), fn.Entry, fn.End); ok {
		t.Error("read code from a missing file")
	}
	short := filepath.Join(t.TempDir(), "short")
	writeFile(t, short)
	unbound := *bin
	unbound.identified = false
	if _, ok := unbound.readText(short, fn.Entry, fn.End); ok {
		t.Error("read code past the end of a short file")
	}

	other := filepath.Join(t.TempDir(), "other")
	writeFile(t, other)
	fi, _ := os.Stat(other)
	key, _ := goBinaryKeyOf(fi)
	goBinaries.put(key, bin)
	if _, _, ok := goFuncReturnOffsets(other, "runtime.main"); ok {
		t.Error("return sites were scanned out of a file the table was not built from")
	}

	if _, ok := goBinaryKeyOf(sysless{fi}); ok {
		t.Error("a file with no inode got a cache key")
	}
	if _, ok := parseGoBinary(other); ok {
		t.Error("parsed a file with no pclntab")
	}
	garbage := filepath.Join(t.TempDir(), "garbage-symtab")
	writeTestELF(t, garbage, []testSection{
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 16)},
		{name: ".gopclntab", typ: shtProgbits, data: make([]byte, 16)},
		{name: ".gosymtab", typ: shtProgbits, data: []byte{0xfd, 0xff, 0xff, 0xff, 0, 0, 1, 8, 0xff, 0xff}},
	})
	if _, ok := parseGoBinary(garbage); ok {
		t.Error("parsed a binary whose .gosymtab is garbage")
	}
	if !pclnFunctionCountWithinCap([]byte{0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 3}) {
		t.Error("a header with an impossible pointer size was rejected here instead of by gosym")
	}
	if !pclnFunctionCountWithinCap([]byte{0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8, 1, 2}) {
		t.Error("a header too short for its function count was rejected here instead of by gosym")
	}
}

func TestTheGoBinaryCacheKeepsWhatIsStillInUse(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	c := &goBinaryCache{now: func() time.Time { return now }}
	a, b, d := goBinaryKey{fileID: fileID{ino: 1}}, goBinaryKey{fileID: fileID{ino: 2}}, goBinaryKey{fileID: fileID{ino: 3}}
	c.put(a, &goBinary{})
	now = now.Add(time.Second)
	c.put(b, &goBinary{})
	now = now.Add(time.Second)
	c.get(a)
	c.put(d, &goBinary{})
	if _, ok := c.get(b); ok {
		t.Error("the least recently used table survived although it was not first in line")
	}
	if _, ok := c.get(a); !ok {
		t.Error("a table used since its insertion was evicted")
	}

	now = now.Add(goBinaryTTL - time.Second)
	c.get(d)
	now = now.Add(2 * time.Second)
	c.expire()
	if _, ok := c.get(d); !ok || len(c.entries) != 1 {
		t.Errorf("expire kept %d tables; it must keep the one used within the TTL", len(c.entries))
	}
	if c.timer == nil {
		t.Error("the expiry timer was not re-armed while a table remains")
	} else {
		c.timer.Stop()
	}
}
