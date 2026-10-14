package probes

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type fakeSpecMap struct {
	entries map[uint64]bool
	updates int
	deletes int
}

func (m *fakeSpecMap) Update(key, _ any, _ ebpf.MapUpdateFlags) error {
	m.entries[key.(uint64)] = true
	m.updates++
	return nil
}

func (m *fakeSpecMap) Delete(key any) error {
	delete(m.entries, key.(uint64))
	m.deletes++
	return nil
}

func TestTheSameProbeInTheSameBinaryGetsTheSameCookie(t *testing.T) {
	a := &executable{id: fileID{ino: 7, size: 100, mtimeNs: 5}, shared: true}
	b := &executable{id: fileID{ino: 7, size: 100, mtimeNs: 5}, shared: true}
	other := &executable{id: fileID{ino: 8, size: 100, mtimeNs: 5}, shared: true}

	if usdtCookie(a, 0x40) != usdtCookie(b, 0x40) {
		t.Error("two containers of one image got different cookies for one probe; their uprobes cannot be shared")
	}
	if usdtCookie(a, 0x40) == usdtCookie(a, 0x80) {
		t.Error("two probes in one binary share a cookie")
	}
	if usdtCookie(a, 0x40) == usdtCookie(other, 0x40) {
		t.Error("the same address in two different files shares a cookie")
	}
	unshared := &executable{}
	first := usdtCookie(unshared, 0x40)
	if second := usdtCookie(unshared, 0x40); first == second {
		t.Error("a file with no identity reused a cookie")
	}
}

func TestAUSDTSpecLivesExactlyAsLongAsTheSitesReadingIt(t *testing.T) {
	table := &usdtSpecTable{users: map[uint64]int{}}
	m := &fakeSpecMap{entries: map[uint64]bool{}}
	val := &usdtProbeValue{}

	if err := table.hold(m, 9, val); err != nil {
		t.Fatal(err)
	}
	if err := table.hold(m, 9, val); err != nil {
		t.Fatal(err)
	}
	if m.updates != 1 {
		t.Errorf("wrote the spec %d times, want once", m.updates)
	}
	table.release(m, 9)
	if !m.entries[9] {
		t.Fatal("the spec was deleted while a site still reads it")
	}
	table.release(m, 9)
	if m.entries[9] || m.deletes != 1 {
		t.Errorf("the spec outlived its last site (present=%v, deletes=%d); usdt_probes leaks until the LRU evicts live entries",
			m.entries[9], m.deletes)
	}
}

func TestSiteHooksRunAroundTheOneRealAttach(t *testing.T) {
	r := newRegistry()
	setups, teardowns, attaches := 0, 0, 0
	hooks := siteHooks{
		setup:    func() error { setups++; return nil },
		teardown: func() { teardowns++ },
	}
	attach := func() (link.Link, error) { attaches++; return &fakeLink{}, nil }
	site := uprobeSite{file: fileID{ino: 3}, opts: link.UprobeOptions{Address: 0x40, Cookie: 9}}

	a, err := r.acquireWithHooks(site, attach, hooks)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.acquireWithHooks(site, attach, hooks)
	if err != nil {
		t.Fatal(err)
	}
	if setups != 1 || attaches != 1 {
		t.Fatalf("setup ran %d times and attach %d for one shared site, want once each", setups, attaches)
	}
	_ = a.Close()
	if teardowns != 0 {
		t.Fatal("teardown ran while a holder remained")
	}
	_ = b.Close()
	if teardowns != 1 {
		t.Errorf("teardown ran %d times after the last holder left, want once", teardowns)
	}
}

func TestAFailedAttachTearsDownWhatItsSetupMade(t *testing.T) {
	r := newRegistry()
	teardowns := 0
	hooks := siteHooks{setup: func() error { return nil }, teardown: func() { teardowns++ }}
	_, err := r.acquireWithHooks(uprobeSite{file: fileID{ino: 4}}, func() (link.Link, error) {
		return nil, errors.New("attach refused")
	}, hooks)
	if err == nil {
		t.Fatal("a failed attach was reported as a success")
	}
	if teardowns != 1 || len(r.sites) != 0 {
		t.Errorf("teardowns=%d sites=%d after a failed attach, want 1 and 0", teardowns, len(r.sites))
	}
}
