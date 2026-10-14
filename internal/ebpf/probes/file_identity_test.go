//go:build linux

package probes

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/procfs"
)

func buildIDNote(id []byte) []byte {
	note := make([]byte, 16, 16+len(id))
	binary.LittleEndian.PutUint32(note[0:], 4)
	binary.LittleEndian.PutUint32(note[4:], uint32(len(id)))
	binary.LittleEndian.PutUint32(note[8:], 3)
	copy(note[12:], "GNU\x00")
	return append(note, id...)
}

func TestTwoDifferentLibrariesNeverShareAUprobeIdentity(t *testing.T) {
	dir := t.TempDir()
	var ids []fileID
	for i, build := range [][]byte{{1, 2, 3, 4, 5, 6, 7, 8}, {9, 9, 9, 9, 9, 9, 9, 9}} {
		path := filepath.Join(dir, fmt.Sprintf("libssl.so.%d", i))
		writeTestELF(t, path, []testSection{{name: ".note.gnu.build-id", typ: shtNote, flags: shfAlloc, data: buildIDNote(build)}})
		exe, err := openExecutable(path)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, exe.id)
		_ = exe.Close()
	}
	if ids[0].buildID == "" || ids[0].buildID == ids[1].buildID {
		t.Fatalf("build ids %q and %q; two libraries with one inode number, size and mtime on different filesystems would share a uprobe",
			ids[0].buildID, ids[1].buildID)
	}
	same := ids[1]
	same.ino, same.size, same.mtimeNs = ids[0].ino, ids[0].size, ids[0].mtimeNs
	if same == ids[0] {
		t.Error("identities that differ only in build id compare equal")
	}
}

func TestOneFileReachedTwoWaysHasOneUprobeIdentity(t *testing.T) {
	a, err := openExecutable(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, err := openExecutable("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if a.id != b.id {
		t.Errorf("identities %+v and %+v for one file; its uprobes would be attached twice and every call reported twice", a.id, b.id)
	}
}

func fakeStat(t *testing.T, base string, pid uint32, comm string, started uint64) {
	t.Helper()
	dir := filepath.Join(base, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (%s) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0", pid, comm, started)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAReusedPIDIsToldApartByItsStartTime(t *testing.T) {
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	procfs.ResetForTesting()
	t.Cleanup(func() {
		config.ProcBasePath = orig
		procfs.ResetForTesting()
	})

	const pid = 53001
	fakeStat(t, base, pid, "we ird) (name", 777)
	started, ok := processStartTime(pid)
	if !ok || started != 777 {
		t.Fatalf("processStartTime = %d, %v; want 777", started, ok)
	}
	if !sameProcess(pid, started) {
		t.Fatal("the same process was reported as replaced")
	}
	fakeStat(t, base, pid, "other", 999)
	if sameProcess(pid, started) {
		t.Error("a process that reused the pid was taken for the original; its rootfs would be searched instead")
	}
}
