package probes

import (
	"debug/dwarf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	fixtureOnce sync.Once
	fixtureBin  string
	fixtureErr  error
)

const fixtureSource = `package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
)

var sink any

func main() {
	var a net.UDPAddr
	var r http.Request
	var resp http.Response
	var u url.URL
	var o sync.Once
	sink = []any{&a, &r, &resp, &u, &o}
	fmt.Println(sink)
}
`

func buildGoFixture() {
	goTool, err := exec.LookPath("go")
	if err != nil {
		fixtureErr = err
		return
	}
	dir, err := os.MkdirTemp("", "probesdwarffix")
	if err != nil {
		fixtureErr = err
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(fixtureSource), 0o644); err != nil {
		fixtureErr = err
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module probesdwarffix\ngo 1.21\n"), 0o644); err != nil {
		fixtureErr = err
		return
	}
	bin := filepath.Join(dir, "fixture")
	cmd := exec.Command(goTool, "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		fixtureErr = fmt.Errorf("go build: %v\n%s", err, out)
		return
	}
	fixtureBin = bin
}

func goFixtureBinary(t *testing.T) string {
	t.Helper()
	fixtureOnce.Do(buildGoFixture)
	if fixtureErr != nil {
		t.Skipf("cannot build Go fixture binary: %v", fixtureErr)
	}
	return fixtureBin
}

func fixtureDWARF(t *testing.T) (*dwarf.Data, func(), map[string]dwarf.Offset) {
	t.Helper()
	bin := goFixtureBinary(t)
	d, cleanup, ok := openDWARF(bin, 0)
	if !ok {
		t.Skip("fixture binary carries no readable DWARF")
	}
	return d, cleanup, indexDWARFStructs(d)
}
