package stacktrace

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKallsyms_ResolveBelowFirstSymbol(t *testing.T) {
	cleanup := writeKallsyms(t, "ffffffff81000100 T first\nffffffff81000200 T second\n")
	defer cleanup()

	k := &kallsymsLookup{}
	if got := k.Resolve(0xffffffff81000050); got != "" {
		t.Errorf("Resolve for an address below the first symbol = %q, want empty", got)
	}
}

func TestTranslateAddr_MappedButOutsideSegments(t *testing.T) {
	r := &stackResolver{
		segments: map[string][]loadSegment{"/bin/app": {{off: 0x10000, vaddr: 0x10000, filesz: 0x1000}}},
		mappings: map[string][]exeMapping{"9|/bin/app": {{start: 0x1000, end: 0x2000, pgoff: 0}}},
	}
	if _, ok := r.translateAddr(9, "/bin/app", "/bin/app", 0x1500); ok {
		t.Fatal("an address inside a mapping but outside every load segment must return ok=false")
	}
}

func TestExeMappings_SkipsUnparseableAddress(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "77"), 0o755); err != nil {
		t.Fatal(err)
	}
	maps := "gggggggg-hhhhhhhh r-xp 00001000 08:01 100 /bin/app\n"
	if err := os.WriteFile(filepath.Join(base, "77", "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}
	cleanup := pointProcfsAt(t, base)
	defer cleanup()

	r := &stackResolver{}
	if got := r.exeMappings(77, "/bin/app"); len(got) != 0 {
		t.Fatalf("a mapping line with an unparseable address range must be skipped, got %+v", got)
	}
}

func TestExeMappings_SkipsRangeWithoutDash(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "78"), 0o755); err != nil {
		t.Fatal(err)
	}
	maps := "ffffffff r-xp 00001000 08:01 100 /bin/app\n"
	if err := os.WriteFile(filepath.Join(base, "78", "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}
	cleanup := pointProcfsAt(t, base)
	defer cleanup()

	r := &stackResolver{}
	if got := r.exeMappings(78, "/bin/app"); len(got) != 0 {
		t.Fatalf("a mapping line whose range has no dash must be skipped, got %+v", got)
	}
}

func TestStackResolver_Addr2lineMissing(t *testing.T) {
	t.Setenv("PATH", "")
	r := &stackResolver{cache: map[string]string{}}
	got := r.resolve(context.Background(), processOfTheTestBinary(t), 0x1234)
	if !strings.Contains(got, "@0x1234") {
		t.Errorf("resolve() = %q, want the base@0x<addr> fallback when addr2line is not on PATH", got)
	}
}

func TestStackResolver_RealCodeAddress(t *testing.T) {
	pc, _, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("no caller PC available")
	}
	r := &stackResolver{cache: map[string]string{}}
	got := r.resolve(context.Background(), uint32(os.Getpid()), uint64(pc))
	if got == "" {
		t.Fatal("resolve() of a real in-binary code address must return a non-empty frame")
	}
}

func TestStackResolver_KernelAddressResolvesSymbol(t *testing.T) {
	cleanup := writeKallsyms(t, "ffffffff81000000 T do_thing\nffffffff81000100 T other\n")
	defer cleanup()

	orig := defaultKallsyms
	defaultKallsyms = &kallsymsLookup{}
	defer func() { defaultKallsyms = orig }()

	r := &stackResolver{cache: map[string]string{}}
	got := r.resolve(context.Background(), 1, 0xffffffff81000010)
	if got != "do_thing+0x10" {
		t.Errorf("resolve(kernel addr) = %q, want do_thing+0x10", got)
	}
}

func TestStackResolver_ExeStatFails(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "55"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent/podtrace-binary", filepath.Join(base, "55", "exe")); err != nil {
		t.Fatal(err)
	}
	cleanup := pointProcfsAt(t, base)
	defer cleanup()

	r := &stackResolver{cache: map[string]string{}}
	got := r.resolve(context.Background(), 55, 0x1234)
	if got != "0x1234" {
		t.Errorf("resolve() = %q, want the raw hex form when the exe path cannot be stat'd", got)
	}
}
