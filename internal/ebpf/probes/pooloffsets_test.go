package probes

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
)

const poolFixtureSource = `package main

import (
	"database/sql"
	"fmt"
)

var sink any

func main() {
	var db *sql.DB
	sink = db
	fmt.Println(sink)
}
`

var (
	poolFixtureOnce     sync.Once
	poolFixtureBin      string
	poolFixtureStripped string
	poolFixtureErr      error
)

func buildPoolFixtures() {
	goTool, err := exec.LookPath("go")
	if err != nil {
		poolFixtureErr = err
		return
	}
	dir, err := os.MkdirTemp("", "poolofffix")
	if err != nil {
		poolFixtureErr = err
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(poolFixtureSource), 0o644); err != nil {
		poolFixtureErr = err
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module poolofffix\ngo 1.21\n"), 0o644); err != nil {
		poolFixtureErr = err
		return
	}

	build := func(out string, extra ...string) error {
		args := append([]string{"build", "-o", out}, extra...)
		cmd := exec.Command(goTool, append(args, ".")...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go build: %v\n%s", err, out)
		}
		return nil
	}

	plain := filepath.Join(dir, "pool")
	if err := build(plain); err != nil {
		poolFixtureErr = err
		return
	}
	stripped := filepath.Join(dir, "pool-stripped")
	if err := build(stripped, "-ldflags=-w"); err != nil {
		poolFixtureErr = err
		return
	}
	poolFixtureBin, poolFixtureStripped = plain, stripped
}

func poolFixtures(t *testing.T) (plain, stripped string) {
	t.Helper()
	poolFixtureOnce.Do(buildPoolFixtures)
	if poolFixtureErr != nil {
		t.Skipf("cannot build database/sql fixture binaries: %v", poolFixtureErr)
	}
	return poolFixtureBin, poolFixtureStripped
}

func runtimePoolOffsets(t *testing.T) poolFieldOffsets {
	t.Helper()
	typ := reflect.TypeOf((*sql.DB)(nil)).Elem()

	numOpen, ok := typ.FieldByName("numOpen")
	if !ok {
		t.Skip("database/sql.DB has no numOpen field in this Go release")
	}
	maxOpen, ok := typ.FieldByName("maxOpen")
	if !ok {
		t.Skip("database/sql.DB has no maxOpen field in this Go release")
	}
	freeConn, ok := typ.FieldByName("freeConn")
	if !ok {
		t.Skip("database/sql.DB has no freeConn field in this Go release")
	}
	return poolFieldOffsets{
		NumOpen:  uint32(numOpen.Offset),
		MaxOpen:  uint32(maxOpen.Offset),
		FreeConn: uint32(freeConn.Offset),
	}
}

func TestPoolOffsetsMatchTheRuntimeStructLayout(t *testing.T) {
	plain, _ := poolFixtures(t)

	got, ok := poolOffsetsFromDWARF(plain, 0)
	if !ok {
		t.Fatal("no offsets resolved from a fixture built with DWARF")
	}

	want := runtimePoolOffsets(t)
	if got != want {
		t.Fatalf("offsets = %+v, want %+v.\n\nThese are byte offsets the uprobe reads "+
			"with bpf_probe_read_user. reflect reports the same struct the fixture was "+
			"compiled against, so a mismatch means the DWARF reader is picking the wrong "+
			"member and the pool gauges would carry a plausible but invented count.",
			got, want)
	}
}

func TestResolvePoolFieldOffsetsUsesTheBinarysOwnDWARF(t *testing.T) {
	plain, _ := poolFixtures(t)

	got, ok := resolvePoolFieldOffsets(plain, 0)
	if !ok {
		t.Fatal("no offsets resolved from a fixture built with DWARF")
	}
	if want := runtimePoolOffsets(t); got != want {
		t.Fatalf("offsets = %+v, want %+v", got, want)
	}
}

func TestPoolOffsetsAreAbsentFromAStrippedBinary(t *testing.T) {
	_, stripped := poolFixtures(t)

	if got, ok := poolOffsetsFromDWARF(stripped, 0); ok {
		t.Fatalf("offsets = %+v resolved from a binary built with -ldflags=-w", got)
	}
}

func TestResolvePoolFieldOffsetsRefusesToGuessWithoutDWARF(t *testing.T) {
	_, stripped := poolFixtures(t)

	got, ok := resolvePoolFieldOffsets(stripped, 0)
	if ok {
		t.Fatalf("resolvePoolFieldOffsets = %+v, ok on a stripped binary.\n\nThere is "+
			"deliberately no version-table fallback here: a wrong integer offset yields a "+
			"connection count nothing downstream can tell from a real one, unlike the h3 "+
			"string fields where a wrong offset is visible garbage.", got)
	}
	if got != (poolFieldOffsets{}) {
		t.Fatalf("offsets = %+v alongside ok=false; the caller publishes whatever is "+
			"returned", got)
	}
}

func TestPoolOffsetsSkipABinaryThatNeverPools(t *testing.T) {
	bin := goFixtureBinary(t)

	if got, ok := poolOffsetsFromDWARF(bin, 0); ok {
		t.Fatalf("offsets = %+v from a binary that does not import database/sql", got)
	}
}

func TestResolvePoolFieldOffsetsToleratesAnUnreadablePath(t *testing.T) {
	for _, path := range []string{
		filepath.Join(t.TempDir(), "absent"),
		t.TempDir(),
	} {
		if _, ok := resolvePoolFieldOffsets(path, 0); ok {
			t.Errorf("resolvePoolFieldOffsets(%q, 0) reported offsets", path)
		}
	}
}

func TestPoolOffsetsRejectANonELFFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notanelf")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, ok := poolOffsetsFromDWARF(path, 0); ok {
		t.Error("offsets resolved from a shell script")
	}
}

func TestPublishPoolOffsetsIsInertWithoutAMapOrATarget(t *testing.T) {
	plain, _ := poolFixtures(t)

	for name, call := range map[string]func(){
		"collection carries no maps": func() {
			publishPoolOffsets(&ebpf.Collection{}, plain, 42)
		},
		"pool_offsets was not loaded": func() {
			publishPoolOffsets(&ebpf.Collection{Maps: map[string]*ebpf.Map{}}, plain, 42)
		},
		"target is host-wide": func() {
			publishPoolOffsets(&ebpf.Collection{}, plain, 0)
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("publishPoolOffsets panicked: %v.\n\nAn agent running a BPF "+
						"object built before this map existed would take the whole probe "+
						"attach down with it.", r)
				}
			}()
			call()
		})
	}
}
