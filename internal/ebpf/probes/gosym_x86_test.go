package probes

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestX86ReturnPositions_Clean finds RET at the right offset in valid code.
func TestX86ReturnPositions_Clean(t *testing.T) {
	// 0x90 NOP, 0xc3 RET
	got, ok := x86ReturnPositions([]byte{0x90, 0xc3})
	if !ok || len(got) != 1 || got[0] != 1 {
		t.Fatalf("positions = %v, want [1]", got)
	}
}

// TestX86ReturnPositions_StopsOnDesync guards ebpf M1: after an undecodable
// byte (0x06 = PUSH ES, invalid in 64-bit mode) the scan must stop rather than
// resync mid-instruction and report a spurious RET, which would plant a
// uretprobe mid-instruction and corrupt the traced process.
func TestX86ReturnPositions_StopsOnDesync(t *testing.T) {
	got, ok := x86ReturnPositions([]byte{0x06, 0x90, 0xc3})
	if ok || len(got) != 0 {
		t.Fatalf("expected a failed scan after a decode failure, got %v ok=%v", got, ok)
	}
}

func TestX86ReturnPositions_AnUndecodableInstructionAfterARetFailsTheScan(t *testing.T) {
	got, ok := x86ReturnPositions([]byte{0xc3, 0x06, 0xc3})
	if ok {
		t.Fatalf("returned %v as a complete scan; the RET after the undecodable byte is missed and its entry probe's state is never cleared", got)
	}
}

func TestAFunctionTheDecoderCannotReadGetsNoReturnProbes(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("x86-64 only")
	}
	goBinaries.reset()
	t.Cleanup(goBinaries.reset)
	bin, ok := loadGoBinary(os.Args[0])
	if !ok {
		t.Skip("the test binary has no pclntab")
	}
	fn := bin.table.LookupFunc("runtime.main")
	data, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	start := bin.textOffset + (fn.Entry - bin.textAddr)
	for i := start; i < start+(fn.End-fn.Entry); i++ {
		data[i] = 0x06
	}
	patched := filepath.Join(t.TempDir(), "patched")
	if err := os.WriteFile(patched, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, rets, ok := goFuncReturnOffsets(patched, "runtime.main"); ok {
		t.Errorf("returned %d return sites for a function whose code cannot be decoded", len(rets))
	}
}
