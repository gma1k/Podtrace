package stacktrace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeAddr2line(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "addr2line"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func processOfTheTestBinary(t *testing.T) uint32 {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "4242"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(base, "4242", "exe")); err != nil {
		t.Fatal(err)
	}
	maps := "00001000-00002000 r-xp 7fffffff000 08:01 100 " + exe + "\n"
	if err := os.WriteFile(filepath.Join(base, "4242", "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pointProcfsAt(t, base))
	return 4242
}

func TestAFailingAddr2lineFallsBackToTheRawAddress(t *testing.T) {
	fakeAddr2line(t, "exit 1")
	r := &stackResolver{cache: map[string]string{}}
	got := r.resolve(context.Background(), processOfTheTestBinary(t), 0x1234)
	if !strings.HasSuffix(got, "@0x1234") {
		t.Errorf("resolve = %q, want binary@0x1234 when addr2line fails", got)
	}
}

func TestAnAddr2lineAnswerIsPrefixedWithTheBinary(t *testing.T) {
	fakeAddr2line(t, "echo /src/app/main.go:42")
	r := &stackResolver{cache: map[string]string{}}
	got := r.resolve(context.Background(), processOfTheTestBinary(t), 0x1234)
	if !strings.HasSuffix(got, ":/src/app/main.go:42") || strings.Contains(got, "@0x") {
		t.Errorf("resolve = %q, want <binary>:/src/app/main.go:42", got)
	}
}

func TestAnAddr2lineThatKnowsNothingFallsBackToTheRawAddress(t *testing.T) {
	fakeAddr2line(t, "echo '??:0'")
	r := &stackResolver{cache: map[string]string{}}
	got := r.resolve(context.Background(), processOfTheTestBinary(t), 0x1234)
	if !strings.HasSuffix(got, "@0x1234") {
		t.Errorf("resolve = %q, want binary@0x1234 when addr2line answers ??:0", got)
	}
}
