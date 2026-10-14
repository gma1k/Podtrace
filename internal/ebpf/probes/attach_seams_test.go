package probes

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/config"
)

func addLoadSegment(t *testing.T, path string, vaddr uint64) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	phoff := uint64(len(data))
	ph := make([]byte, 56)
	le.PutUint32(ph[0:], 1)
	le.PutUint32(ph[4:], 5)
	le.PutUint64(ph[16:], vaddr)
	le.PutUint64(ph[24:], vaddr)
	le.PutUint64(ph[32:], 0x100000)
	le.PutUint64(ph[40:], 0x100000)
	data = append(data, ph...)
	le.PutUint64(data[32:], phoff)
	le.PutUint16(data[56:], 1)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

type attachCall struct {
	symbol string
	prog   *ebpf.Program
	addr   uint64
	cookie uint64
	refCtr uint64
	ret    bool
}

type fakeAttacher struct {
	mu    sync.Mutex
	calls []attachCall
	fail  func(c attachCall) error
	links []*fakeLink
}

func installFakeAttacher(t *testing.T, fail func(c attachCall) error) *fakeAttacher {
	t.Helper()
	f := &fakeAttacher{fail: fail}
	origAttach, origPreload := attachToExecutable, preloadSymbols
	attachToExecutable = func(_ *link.Executable, symbol string, prog *ebpf.Program, opts *link.UprobeOptions, ret bool) (link.Link, error) {
		c := attachCall{symbol: symbol, prog: prog, ret: ret}
		if opts != nil {
			c.addr, c.cookie, c.refCtr = opts.Address, opts.Cookie, opts.RefCtrOffset
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, c)
		if f.fail != nil {
			if err := f.fail(c); err != nil {
				return nil, err
			}
		}
		l := &fakeLink{}
		f.links = append(f.links, l)
		return l, nil
	}
	preloadSymbols = func(*link.Executable) {}
	sharedUprobes = &uprobeRegistry{sites: map[uprobeSite]*sharedUprobe{}}
	t.Cleanup(func() {
		attachToExecutable, preloadSymbols = origAttach, origPreload
		sharedUprobes = &uprobeRegistry{sites: map[uprobeSite]*sharedUprobe{}}
	})
	return f
}

type recordingSpecMap struct {
	entries   map[uint64]bool
	updateErr error
}

func (m *recordingSpecMap) Update(key, _ any, _ ebpf.MapUpdateFlags) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.entries[key.(uint64)] = true
	return nil
}

func (m *recordingSpecMap) Delete(key any) error {
	delete(m.entries, key.(uint64))
	return nil
}

func usdtTarget(t *testing.T, pid uint32, semaphore bool) *recordingSpecMap {
	t.Helper()
	sections := rustLikeSections("f")
	note := stapsdtNote(testTextVA, "app", "tick")
	if semaphore {
		binary.LittleEndian.PutUint64(note[12+8+16:], testTextVA+0x10)
	}
	sections = append(sections, testSection{name: ".note.stapsdt", typ: shtNote, data: note})
	syntheticProc(t, pid, sections)
	addLoadSegment(t, filepath.Join(config.ProcBasePath, strconv.FormatUint(uint64(pid), 10), "exe"), 0x400000)
	orig := config.USDTEnabled
	config.USDTEnabled = true
	m := &recordingSpecMap{entries: map[uint64]bool{}}
	origMap := usdtSpecMapOf
	usdtSpecMapOf = func(*ebpf.Collection) usdtSpecMap { return m }
	origSpecs := usdtSpecs
	usdtSpecs = &usdtSpecTable{users: map[uint64]int{}}
	t.Cleanup(func() {
		config.USDTEnabled = orig
		usdtSpecMapOf = origMap
		usdtSpecs = origSpecs
	})
	return m
}

func TestAUSDTProbeIsAttachedWithItsSpecAndDetachedWithoutIt(t *testing.T) {
	const pid = 4301
	m := usdtTarget(t, pid, false)
	f := installFakeAttacher(t, nil)

	coll := placeholderPrograms("uprobe_usdt")
	links := AttachUSDTProbes(coll, pid)
	if len(links) != 1 || len(f.calls) != 1 {
		t.Fatalf("links=%d attaches=%d, want 1 and 1", len(links), len(f.calls))
	}
	if !m.entries[f.calls[0].cookie] {
		t.Fatal("the probe was attached with no spec for its cookie")
	}
	again := AttachUSDTProbes(coll, pid)
	if len(f.calls) != 1 {
		t.Errorf("a second holder attached %d more uprobes; the same probe in the same file must be shared", len(f.calls)-1)
	}
	_ = links[0].Close()
	if !m.entries[f.calls[0].cookie] {
		t.Fatal("the spec was dropped while a holder remained")
	}
	_ = again[0].Close()
	if len(m.entries) != 0 {
		t.Error("the spec outlived the last holder")
	}
}

func TestASemaphoreAttachThatFailsIsRetriedWithoutTheSemaphore(t *testing.T) {
	const pid = 4302
	m := usdtTarget(t, pid, true)
	f := installFakeAttacher(t, func(c attachCall) error {
		if c.refCtr != 0 {
			return errors.New("ref_ctr_offset refused")
		}
		return nil
	})

	links := AttachUSDTProbes(placeholderPrograms("uprobe_usdt"), pid)
	if !uprobeRefCtrOffsetSupported() {
		if len(links) != 1 {
			t.Fatalf("links=%d, want 1", len(links))
		}
		return
	}
	if len(links) != 1 || len(f.calls) != 2 || f.calls[1].refCtr != 0 {
		t.Fatalf("links=%d calls=%+v; a refused semaphore attach must be retried once without it", len(links), f.calls)
	}
	if len(m.entries) != 1 {
		t.Errorf("%d specs after the retry, want 1", len(m.entries))
	}
}

func TestAUSDTSpecThatCannotBeWrittenAttachesNothing(t *testing.T) {
	const pid = 4303
	m := usdtTarget(t, pid, false)
	m.updateErr = errors.New("map full")
	f := installFakeAttacher(t, nil)

	if links := AttachUSDTProbes(placeholderPrograms("uprobe_usdt"), pid); len(links) != 0 || len(f.calls) != 0 {
		t.Errorf("links=%d attaches=%d with no spec written; the probe would fire with nothing to decode", len(links), len(f.calls))
	}
}

func TestAnUnsharedExecutableRunsItsHooksAroundItsOwnLink(t *testing.T) {
	f := installFakeAttacher(t, nil)
	exe := &executable{}
	setups, teardowns := 0, 0
	l, err := exe.uprobeWithHooks(&ebpf.Program{}, &link.UprobeOptions{Address: 8}, siteHooks{
		setup:    func() error { setups++; return nil },
		teardown: func() { teardowns++ },
	})
	if err != nil || setups != 1 {
		t.Fatalf("attach = %v, setups=%d", err, setups)
	}
	_ = l.Close()
	_ = l.Close()
	if teardowns != 1 || f.links[0].closed != 1 {
		t.Errorf("teardowns=%d closes=%d after closing twice, want 1 and 1", teardowns, f.links[0].closed)
	}

	boom := errors.New("setup refused")
	if _, err := exe.uprobeWithHooks(&ebpf.Program{}, nil, siteHooks{setup: func() error { return boom }}); !errors.Is(err, boom) {
		t.Errorf("a failed setup = %v, want it returned", err)
	}
	f.fail = func(attachCall) error { return errors.New("attach refused") }
	teardowns = 0
	if _, err := exe.uprobeWithHooks(&ebpf.Program{}, nil, siteHooks{setup: func() error { return nil }, teardown: func() { teardowns++ }}); err == nil || teardowns != 1 {
		t.Errorf("a failed attach = %v with %d teardowns, want an error and 1", err, teardowns)
	}
	if l, err := exe.Uprobe("", &ebpf.Program{}, nil); err == nil || l != nil {
		t.Error("a failed plain attach was reported as a link")
	}
}

func TestASharedSiteWhoseSetupFailsIsNotRecorded(t *testing.T) {
	r := newRegistry()
	boom := errors.New("setup refused")
	_, err := r.acquireWithHooks(uprobeSite{file: fileID{ino: 5}}, func() (link.Link, error) {
		t.Fatal("attached after a failed setup")
		return nil, nil
	}, siteHooks{setup: func() error { return boom }})
	if !errors.Is(err, boom) || len(r.sites) != 0 {
		t.Errorf("err=%v sites=%d, want the setup error and no site", err, len(r.sites))
	}
}

func TestAnExecutableCiliumCannotOpenIsReleased(t *testing.T) {
	orig := openLinkExecutable
	openLinkExecutable = func(string) (*link.Executable, error) { return nil, errors.New("refused") }
	t.Cleanup(func() { openLinkExecutable = orig })
	if exe, err := openExecutable(os.Args[0]); err == nil || exe != nil {
		t.Fatal("openExecutable succeeded although cilium refused the file")
	}
	var nilExe *executable
	if err := nilExe.Close(); err != nil {
		t.Errorf("closing a nil executable = %v", err)
	}
}

func TestUSDTNeedsTheSpecMap(t *testing.T) {
	const pid = 4304
	builtIn := usdtSpecMapOf
	usdtTarget(t, pid, false)
	usdtSpecMapOf = builtIn
	f := installFakeAttacher(t, nil)
	if links := AttachUSDTProbes(placeholderPrograms("uprobe_usdt"), pid); len(links) != 0 || len(f.calls) != 0 {
		t.Errorf("attached %d USDT probes with no usdt_probes map to describe them", len(f.calls))
	}
}
