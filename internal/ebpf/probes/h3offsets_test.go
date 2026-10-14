package probes

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestResolveH3FieldOffsets_DWARF builds a tiny net/http binary so its DWARF
// carries net/http.Request/Response and net/url.URL, then checks the resolver
// reads the field offsets from DWARF.
func TestResolveH3FieldOffsets_DWARF(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary; skipped in -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	src := `package main
import ("net/http";"net/url";"fmt")
func main(){ r,_:=http.NewRequest("GET","http://x/y",nil); u,_:=url.Parse("http://x/y"); var resp http.Response; fmt.Println(r.Method,u.Path,resp.StatusCode) }
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module h3probe\ngo 1.23\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "h3probe")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build helper binary: %v\n%s", err, out)
	}

	off, source := resolveH3FieldOffsets(bin, 0)
	if source != "dwarf" {
		t.Fatalf("expected dwarf source, got %q", source)
	}
	want := h3FieldOffsets{Method: 0, URL: 16, Path: 56, Status: 16}
	if off != want {
		t.Fatalf("DWARF offsets = %+v, want %+v", off, want)
	}
}

func TestH3OffsetsFromDWARF_MissingFileFallsBack(t *testing.T) {
	if _, ok := h3OffsetsFromDWARF("/no/such/binary", 0); ok {
		t.Fatal("expected ok=false for a missing binary")
	}
}

func TestGoMinorVersion(t *testing.T) {
	cases := []struct {
		in    string
		minor int
		ok    bool
	}{
		{"go1.23.4", 23, true},
		{"go1.21", 21, true},
		{"go1.26.0", 26, true},
		{"devel go1.27-abcdef", 0, false},
		{"1.22.1", 22, true},
		{"garbage", 0, false},
		{"go1", 0, false},
	}
	for _, c := range cases {
		minor, ok := goMinorVersion(c.in)
		if ok != c.ok || (ok && minor != c.minor) {
			t.Errorf("goMinorVersion(%q) = (%d,%v), want (%d,%v)", c.in, minor, ok, c.minor, c.ok)
		}
	}
}

func TestH3DefaultOffsetsStable(t *testing.T) {
	want := h3FieldOffsets{Method: 0, URL: 16, Path: 56, Status: 16}
	if h3DefaultOffsets != want {
		t.Fatalf("h3DefaultOffsets = %+v, want %+v", h3DefaultOffsets, want)
	}
}
