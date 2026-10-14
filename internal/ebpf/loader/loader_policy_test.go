//go:build linux

package loader

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func withAuxv(t *testing.T, secure uintptr) {
	t.Helper()
	orig := auxv
	auxv = func() ([][2]uintptr, error) { return [][2]uintptr{{6, 4096}, {atSecure, secure}}, nil }
	t.Cleanup(func() { auxv = orig })
}

func withObjectPath(t *testing.T, path string) {
	t.Helper()
	orig := config.BPFObjectPath
	config.BPFObjectPath = path
	t.Cleanup(func() { config.BPFObjectPath = orig })
}

func TestAnObjectOverrideIsRefusedUnderFileCapabilities(t *testing.T) {
	withAuxv(t, 1)
	withObjectPath(t, filepath.Join(t.TempDir(), "attacker.bpf.o"))

	_, err := LoadPodtrace()
	if !errors.Is(err, errOverrideUnderSecureExec) {
		t.Fatalf("LoadPodtrace = %v; a setcap binary loaded a BPF object its caller chose", err)
	}
}

func TestSecureExecIsReadFromTheAuxiliaryVector(t *testing.T) {
	withAuxv(t, 0)
	if secureExec() {
		t.Error("AT_SECURE=0 read as secure")
	}
	withAuxv(t, 1)
	if !secureExec() {
		t.Error("AT_SECURE=1 read as not secure")
	}
	orig := auxv
	auxv = func() ([][2]uintptr, error) { return nil, errors.New("no auxv") }
	t.Cleanup(func() { auxv = orig })
	if !secureExec() {
		t.Error("an unreadable auxiliary vector was taken as not secure")
	}
}

func TestTheDefaultObjectIsNotLookedUpInTheParentDirectory(t *testing.T) {
	if len(embeddedObject) > 0 {
		t.Skip("this build embeds the object, which is loaded before any path")
	}
	withAuxv(t, 0)
	withObjectPath(t, config.DefaultBPFObjectPath())

	real := findBPFObjectPath()
	src, err := os.Open(real)
	if err != nil {
		t.Skipf("no compiled BPF object to plant: %v", err)
	}
	defer func() { _ = src.Close() }()

	dir := t.TempDir()
	planted := filepath.Join(dir, config.DefaultBPFObjectPath())
	if err := os.MkdirAll(filepath.Dir(planted), 0o755); err != nil {
		t.Fatal(err)
	}
	dst, err := os.Create(planted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	_ = dst.Close()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)

	if spec, err := LoadPodtrace(); err == nil && spec != nil {
		t.Fatal("loaded an object from ../ of the working directory")
	}
}

func TestTheWorkingDirectoryObjectIsRefusedUnderFileCapabilities(t *testing.T) {
	if len(embeddedObject) > 0 {
		t.Skip("this build embeds the object")
	}
	withAuxv(t, 1)
	withObjectPath(t, config.DefaultBPFObjectPath())

	if _, err := LoadPodtrace(); !errors.Is(err, errNoEmbeddedUnderSecureExec) {
		t.Fatalf("LoadPodtrace = %v; a setcap build without an embedded object read one from the working directory", err)
	}
}

func withEmbeddedObject(t *testing.T, obj []byte) {
	t.Helper()
	orig := embeddedObject
	embeddedObject = obj
	t.Cleanup(func() { embeddedObject = orig })
}

func TestTheEmbeddedObjectIsLoadedBeforeAnyPath(t *testing.T) {
	data, err := os.ReadFile(findBPFObjectPath())
	if err != nil {
		t.Skipf("no compiled BPF object: %v", err)
	}
	withAuxv(t, 1)
	withEmbeddedObject(t, data)
	withObjectPath(t, config.DefaultBPFObjectPath())
	t.Chdir(t.TempDir())

	spec, err := LoadPodtrace()
	if err != nil || spec == nil {
		t.Fatalf("LoadPodtrace = %v; the embedded object must load even under file capabilities", err)
	}
}

func TestACorruptEmbeddedObjectIsReported(t *testing.T) {
	withAuxv(t, 0)
	withEmbeddedObject(t, []byte("not an ELF object"))
	withObjectPath(t, config.DefaultBPFObjectPath())

	if _, err := LoadPodtrace(); err == nil {
		t.Fatal("a corrupt embedded object loaded")
	}
}

func TestAnAuxiliaryVectorWithoutAtSecureIsNotSecure(t *testing.T) {
	orig := auxv
	auxv = func() ([][2]uintptr, error) { return [][2]uintptr{{6, 4096}}, nil }
	t.Cleanup(func() { auxv = orig })
	if secureExec() {
		t.Error("a vector with no AT_SECURE entry read as secure")
	}
}
