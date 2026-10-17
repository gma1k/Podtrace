//go:build bpf_loadtest && linux

package probes

import (
	"debug/elf"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func uprobeMultiProgram(t *testing.T) *ebpf.Program {
	t.Helper()
	if err := features.HaveBPFLinkUprobeMulti(); err != nil {
		t.Skipf("kernel has no uprobe_multi links: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.Kprobe,
		AttachType:   ebpf.AttachTraceUprobeMulti,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		t.Skipf("cannot load a uprobe_multi program (needs privileges): %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	return prog
}

func TestKernelUprobesAttachAsSharedUprobeMultiLinks(t *testing.T) {
	prog := uprobeMultiProgram(t)
	defer SetUprobeMulti(UprobeMultiEnabled())
	SetUprobeMulti(true)

	a, err := openExecutable(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := openExecutable("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	for _, ret := range []bool{false, true} {
		attach, again := a.Uprobe, b.Uprobe
		if ret {
			attach, again = a.Uretprobe, b.Uretprobe
		}
		first, err := attach("runtime.main", prog, nil)
		if err != nil {
			t.Fatalf("attach (ret=%v): %v", ret, err)
		}
		second, err := again("runtime.main", prog, nil)
		if err != nil {
			t.Fatalf("second attach (ret=%v): %v", ret, err)
		}
		if first.(*uprobeHandle).Link != second.(*uprobeHandle).Link {
			t.Errorf("ret=%v: one file reached by two paths got two links", ret)
		}
		info, err := first.Info()
		if err != nil {
			t.Fatalf("link info (ret=%v): %v", ret, err)
		}
		if info.Type != link.UprobeMultiType {
			t.Errorf("ret=%v: link type %v, want uprobe_multi", ret, info.Type)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		if err := second.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(sharedUprobes.sites) != 0 {
		t.Errorf("%d uprobes left attached after every holder closed", len(sharedUprobes.sites))
	}
}

func TestKernelUprobeMultiAttachesAtAnExplicitAddress(t *testing.T) {
	prog := uprobeMultiProgram(t)
	defer SetUprobeMulti(UprobeMultiEnabled())
	SetUprobeMulti(true)

	exe, err := openExecutable(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	addr := fileOffsetOf(t, os.Args[0], "runtime.main")
	l, err := exe.uprobeWithHooks(prog, &link.UprobeOptions{Address: addr, Cookie: 42}, siteHooks{})
	if err != nil {
		t.Fatalf("attach at address %#x: %v", addr, err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func fileOffsetOf(t *testing.T, path, symbol string) uint64 {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	syms, err := f.Symbols()
	if err != nil {
		t.Skipf("no symbol table: %v", err)
	}
	for _, s := range syms {
		if s.Name != symbol {
			continue
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && s.Value >= p.Vaddr && s.Value < p.Vaddr+p.Memsz {
				return s.Value - p.Vaddr + p.Off
			}
		}
	}
	t.Skipf("symbol %s not found in an executable segment", symbol)
	return 0
}
