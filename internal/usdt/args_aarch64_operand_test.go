package usdt

import (
	"debug/elf"
	"encoding/binary"
	"reflect"
	"runtime"
	"testing"
)

func TestParseArgDescFor_AArch64Operands(t *testing.T) {
	args := parseArgDescFor("8@x0 -4@w1 8@[x1] -8@[x29, -16]", argArchARM64)
	want := []Arg{
		{Size: 8, Kind: ArgReg, RegOff: 0},
		{Size: -4, Kind: ArgReg, RegOff: 8},
		{Size: 8, Kind: ArgMem, RegOff: 8, Disp: 0},
		{Size: -8, Kind: ArgMem, RegOff: 29 * 8, Disp: -16},
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %+v, want %+v", args, want)
	}
}

func TestParseArgDescFor_AArch64StackAndConstants(t *testing.T) {
	args := parseArgDescFor("-4@[sp, 12] 4@5 -8@-10 4@#7", argArchARM64)
	want := []Arg{
		{Size: -4, Kind: ArgMem, RegOff: 31 * 8, Disp: 12},
		{Size: 4, Kind: ArgConst, Disp: 5},
		{Size: -8, Kind: ArgConst, Disp: -10},
		{Size: 4, Kind: ArgConst, Disp: 7},
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %+v, want %+v", args, want)
	}
}

func TestParseArgDescFor_AArch64HashDisplacementAndHighRegisters(t *testing.T) {
	args := parseArgDescFor("8@[sp, #16] 8@x30 4@SP", argArchARM64)
	want := []Arg{
		{Size: 8, Kind: ArgMem, RegOff: 31 * 8, Disp: 16},
		{Size: 8, Kind: ArgReg, RegOff: 30 * 8},
		{Size: 4, Kind: ArgReg, RegOff: 31 * 8},
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %+v, want %+v", args, want)
	}
}

func TestParseArgDescFor_AArch64RejectsUnsupportedForms(t *testing.T) {
	for _, desc := range []string{
		"8@x31",
		"8@xzr",
		"8@[x1, x2]",
		"8@[x1, 8]!",
		"8@[x1",
		"8@[q0]",
		"8@%rax",
		"8@$5",
		"8@-8(%rbp)",
	} {
		args := parseArgDescFor(desc, argArchARM64)
		if len(args) != 1 || args[0].Kind != ArgUnsupported {
			t.Errorf("parseArgDescFor(%q) = %+v, want one unsupported arg", desc, args)
		}
	}
}

func TestParseArgDescFor_AMD64IgnoresAArch64Syntax(t *testing.T) {
	args := parseArgDescFor("8@x0 4@5 8@[sp, 8] 8@%rbx", argArchAMD64)
	want := []Arg{
		{Size: 8, Kind: ArgUnsupported},
		{Size: 4, Kind: ArgUnsupported},
		{Size: 8, Kind: ArgUnsupported},
		{Size: 8, Kind: ArgReg, RegOff: 40},
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %+v, want %+v", args, want)
	}
}

func TestParseArgDescFor_AMD64MemoryAndConstant(t *testing.T) {
	args := parseArgDescFor("8@-16(%rbp) 4@$5", argArchAMD64)
	want := []Arg{
		{Size: 8, Kind: ArgMem, RegOff: 32, Disp: -16},
		{Size: 4, Kind: ArgConst, Disp: 5},
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %+v, want %+v", args, want)
	}
}

func TestParseArgDescFor_BracketedSpacesDoNotSplitOperands(t *testing.T) {
	args := parseArgDescFor("-4@[sp, 12] 8@[x29,   -16]   8@x2", argArchARM64)
	if len(args) != 3 {
		t.Fatalf("got %d args, want 3: %+v", len(args), args)
	}
	for i, a := range args {
		if a.Kind == ArgUnsupported {
			t.Errorf("arg %d unsupported: %+v", i, a)
		}
	}
}

func TestSplitArgTokens(t *testing.T) {
	got := splitArgTokens(" 8@x0\t-4@[sp, 12]  8@-8(%rax,%rbx,4) ")
	want := []string{"8@x0", "-4@[sp, 12]", "8@-8(%rax,%rbx,4)"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitArgTokens = %q, want %q", got, want)
	}
}

func TestArgArchForMachine(t *testing.T) {
	host := hostArgArch()
	cases := []struct {
		machine elf.Machine
		arch    argArch
	}{
		{elf.EM_X86_64, argArchAMD64},
		{elf.EM_AARCH64, argArchARM64},
	}
	for _, c := range cases {
		got := argArchForMachine(c.machine)
		want := argArchUnknown
		if c.arch == host {
			want = c.arch
		}
		if got != want {
			t.Errorf("argArchForMachine(%v) on %s = %v, want %v", c.machine, runtime.GOARCH, got, want)
		}
	}
	if got := argArchForMachine(elf.EM_RISCV); got != argArchUnknown {
		t.Errorf("argArchForMachine(EM_RISCV) = %v, want unknown", got)
	}
}

func TestParseStapsdtNotesDecodesWithTheGivenArchitecture(t *testing.T) {
	order := binary.ByteOrder(binary.LittleEndian)
	desc := make([]byte, 24)
	desc = append(desc, "prov\x00probe\x00-4@[sp, 12] 8@x1\x00"...)
	data := note(order, "stapsdt", 3, desc, -1, -1)
	got := parseStapsdtNotes(data, order, argArchARM64)
	if len(got) != 1 || len(got[0].Args) != 2 {
		t.Fatalf("probes = %+v, want one probe with two args", got)
	}
	if got[0].Args[0].Kind != ArgMem || got[0].Args[1].Kind != ArgReg {
		t.Errorf("args = %+v, want mem then reg", got[0].Args)
	}
}
