package probes

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type scriptedTarget struct {
	entryProg *ebpf.Program
	failRets  bool
	failEntry bool
	attached  []uint64
	links     []*fakeLink
}

func (s *scriptedTarget) Uprobe(_ string, prog *ebpf.Program, opts *link.UprobeOptions) (link.Link, error) {
	isEntry := prog == s.entryProg
	if (isEntry && s.failEntry) || (!isEntry && s.failRets) {
		return nil, errors.New("refused")
	}
	s.attached = append(s.attached, opts.Address)
	l := &fakeLink{}
	s.links = append(s.links, l)
	return l, nil
}

func (s *scriptedTarget) Uretprobe(string, *ebpf.Program, *link.UprobeOptions) (link.Link, error) {
	return nil, errors.New("Go return probes are placed on RET sites, never as uretprobes")
}

func TestNoEntryProbeIsLeftWithoutAReturnProbe(t *testing.T) {
	entry, ret := &ebpf.Program{}, &ebpf.Program{}
	target := &scriptedTarget{entryProg: entry, failRets: true}

	if got := attachEntryAfterReturns(target, entry, ret, 0x10, []uint64{0x20, 0x30}); len(got) != 0 {
		t.Fatalf("attached %d links with no return site; the entry stashes state nothing clears", len(got))
	}
	for _, addr := range target.attached {
		if addr == 0x10 {
			t.Error("the entry probe was attached although every return attach failed")
		}
	}
}

func TestReturnsAreReleasedWhenTheEntryCannotAttach(t *testing.T) {
	entry, ret := &ebpf.Program{}, &ebpf.Program{}
	target := &scriptedTarget{entryProg: entry, failEntry: true}

	if got := attachEntryAfterReturns(target, entry, ret, 0x10, []uint64{0x20}); len(got) != 0 {
		t.Fatalf("kept %d links without an entry", len(got))
	}
	for _, l := range target.links {
		if l.closed != 1 {
			t.Error("a return probe was left attached after its entry failed")
		}
	}
}

func TestReturnsAttachBeforeTheEntry(t *testing.T) {
	entry, ret := &ebpf.Program{}, &ebpf.Program{}
	target := &scriptedTarget{entryProg: entry}

	got := attachEntryAfterReturns(target, entry, ret, 0x10, []uint64{0x20, 0x30})
	if len(got) != 3 {
		t.Fatalf("attached %d links, want 3", len(got))
	}
	if target.attached[len(target.attached)-1] != 0x10 {
		t.Errorf("attach order %#x; the entry must come after its returns", target.attached)
	}
}
