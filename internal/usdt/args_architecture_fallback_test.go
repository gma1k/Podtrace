package usdt

import "testing"

func TestArgArchForGOARCH(t *testing.T) {
	cases := map[string]argArch{
		"amd64":   argArchAMD64,
		"arm64":   argArchARM64,
		"riscv64": argArchUnknown,
		"":        argArchUnknown,
	}
	for goarch, want := range cases {
		if got := argArchForGOARCH(goarch); got != want {
			t.Errorf("argArchForGOARCH(%q) = %v, want %v", goarch, got, want)
		}
	}
}

func TestParseArgDescFor_UnknownArchDecodesOnlyConstants(t *testing.T) {
	args := parseArgDescFor("4@$7 -8@$-3 8@%rax 4@$notanumber", argArchUnknown)
	if len(args) != 4 {
		t.Fatalf("got %d args, want 4", len(args))
	}
	if args[0].Kind != ArgConst || args[0].Disp != 7 || args[0].Size != 4 {
		t.Errorf("arg0 = %+v, want const 7 size=4", args[0])
	}
	if args[1].Kind != ArgConst || args[1].Disp != -3 || args[1].Size != -8 {
		t.Errorf("arg1 = %+v, want const -3 size=-8", args[1])
	}
	for i, a := range args[2:] {
		if a.Kind != ArgUnsupported {
			t.Errorf("arg%d = %+v, want unsupported", i+2, a)
		}
	}
}

func TestParseArgDescFor_AMD64RejectsNonNumericDisplacement(t *testing.T) {
	args := parseArgDescFor("8@sym(%rbp) 8@0x10(%rbp)", argArchAMD64)
	if len(args) != 2 {
		t.Fatalf("got %d args, want 2", len(args))
	}
	for i, a := range args {
		if a.Kind != ArgUnsupported || a.RegOff != 0 || a.Disp != 0 {
			t.Errorf("arg%d = %+v, want unsupported with no register or displacement", i, a)
		}
	}
}
