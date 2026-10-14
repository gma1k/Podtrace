//go:build bpf_loadtest && linux

package probes

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
)

func uprobeProgram(t *testing.T) *ebpf.Program {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.Kprobe,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		t.Skipf("cannot load a uprobe program (needs privileges): %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	return prog
}

func socketFilterProgram(t *testing.T) *ebpf.Program {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		t.Skipf("cannot load a socket filter program: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	return prog
}

func TestKernelAHandlerWhoseEntryCannotAttachIsSkipped(t *testing.T) {
	withContinuousProfiling(t, true)
	uprobe := uprobeProgram(t)
	origHandlers, origServers := goRequestHandlers, goConnectionServers
	goRequestHandlers = []goRequestHandler{{"runtime.main", "wrong", "wrong_ret"}}
	goConnectionServers = nil
	t.Cleanup(func() { goRequestHandlers, goConnectionServers = origHandlers, origServers })

	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{"wrong": socketFilterProgram(t), "wrong_ret": uprobe}}
	if links := AttachGoRequestProbes(coll, uint32(os.Getpid())); len(links) != 0 {
		t.Errorf("attached %d links although the entry probe was refused; return probes alone would end requests nothing began", len(links))
	}
}

func TestKernelGoRequestProbesAttachToEveryHandlerTheBinaryHas(t *testing.T) {
	withContinuousProfiling(t, true)
	prog := uprobeProgram(t)
	origHandlers, origServers := goRequestHandlers, goConnectionServers
	goRequestHandlers = []goRequestHandler{
		{"runtime.main", "entry", "entry_ret"},
		{"definitely.NotAReal.Handler", "entry", "entry_ret"},
	}
	goConnectionServers = []struct{ symbol, prog string }{
		{"runtime.goexit", "conn"},
		{"definitely.NotAReal.ServeConn", "conn"},
		{"runtime.main", "missing"},
	}
	t.Cleanup(func() { goRequestHandlers, goConnectionServers = origHandlers, origServers })

	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{"entry": prog, "entry_ret": prog, "conn": prog}}
	links := AttachGoRequestProbes(coll, uint32(os.Getpid()))
	t.Cleanup(func() {
		for _, l := range links {
			_ = l.Close()
		}
	})
	if len(links) < 3 {
		t.Errorf("attached %d links; want runtime.main's entry and return sites plus runtime.goexit, and nothing for the missing symbols", len(links))
	}
}
