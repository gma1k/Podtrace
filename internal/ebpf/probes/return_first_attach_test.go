package probes

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/config"
)

func TestATLSEntryProbeIsSkippedWhenItsReturnProbeFails(t *testing.T) {
	const pid = 4401
	syntheticProc(t, pid, rustLikeSections("f"))
	writeTestELF(t, filepath.Join(config.ProcBasePath, "4401", "root", "usr/lib/libssl.so.3"), rustLikeSections("SSL_write"))
	coll := placeholderPrograms("uprobe_SSL_write", "uretprobe_SSL_write", "uprobe_SSL_read", "uretprobe_SSL_read", "uprobe_SSL_free", "uprobe_SSL_connect", "uretprobe_SSL_connect")
	f := installFakeAttacher(t, func(c attachCall) error {
		switch {
		case c.symbol == "SSL_write" && c.ret:
			return errors.New("uretprobe refused")
		case c.symbol == "SSL_read" && c.ret:
			return errors.New("symbol SSL_read: not found")
		}
		return nil
	})

	AttachTLSProbesWithPID(coll, "", pid, nil)

	attached := map[string]bool{}
	for _, c := range f.calls {
		if !c.ret {
			attached[c.symbol] = true
		}
	}
	if attached["SSL_write"] || attached["SSL_read"] {
		t.Errorf("entry probes attached with no return probe: %v", attached)
	}
	if !attached["SSL_free"] {
		t.Error("SSL_free has no return probe and must still attach its entry")
	}
	if !attached["SSL_connect"] {
		t.Error("SSL_connect's entry did not attach although its return probe did")
	}
}

func withResolvedGoReturns(t *testing.T, entry uint64, rets []uint64, ok bool) {
	t.Helper()
	orig := goFuncReturns
	goFuncReturns = func(string, string) (uint64, []uint64, bool) { return entry, rets, ok }
	t.Cleanup(func() { goFuncReturns = orig })
}

func TestGoEntryProbesFollowTheirReturnSites(t *testing.T) {
	coll := placeholderPrograms("uprobe_go_tls_read", "uprobe_go_tls_read_ret", "e", "r")
	withResolvedGoReturns(t, 0x10, []uint64{0x20, 0x30}, true)

	if got := attachGoTLSReadProbes(coll, &scriptedTarget{entryProg: coll.Programs["uprobe_go_tls_read"]}, "/bin", 1); len(got) != 3 {
		t.Errorf("TLS Read probes = %d links, want 2 returns and the entry", len(got))
	}
	if got := attachGoTLSReadProbes(coll, &scriptedTarget{entryProg: coll.Programs["uprobe_go_tls_read"], failRets: true}, "/bin", 1); got != nil {
		t.Errorf("TLS Read kept %d links with no return site", len(got))
	}
	if got := attachGoEntryReturnProbes(coll, &scriptedTarget{entryProg: coll.Programs["e"]}, "/bin", 1, "f", "e", "r"); len(got) != 3 {
		t.Errorf("entry+return probes = %d links, want 3", len(got))
	}
	if got := attachGoEntryReturnProbes(coll, &scriptedTarget{entryProg: coll.Programs["e"], failRets: true}, "/bin", 1, "f", "e", "r"); got != nil {
		t.Errorf("entry+return kept %d links with no return site", len(got))
	}
	withResolvedGoReturns(t, 0, nil, false)
	if got := attachGoTLSReadProbes(coll, &scriptedTarget{}, "/bin", 1); len(got) != 0 {
		t.Error("attached TLS Read probes for an unresolved symbol")
	}
}

type kprobeCall struct {
	symbol string
	ret    bool
}

func installFakeKprobes(t *testing.T, fail func(kprobeCall) bool) (*[]kprobeCall, *[]*fakeLink) {
	t.Helper()
	var calls []kprobeCall
	var links []*fakeLink
	orig := kprobeAttach
	kprobeAttach = func(symbol string, _ *ebpf.Program, ret bool) (link.Link, error) {
		c := kprobeCall{symbol, ret}
		calls = append(calls, c)
		if fail != nil && fail(c) {
			return nil, errors.New("refused")
		}
		l := &fakeLink{}
		links = append(links, l)
		return l, nil
	}
	t.Cleanup(func() { kprobeAttach = orig })
	return &calls, &links
}

func TestAKprobeWhoseReturnProbeFailsIsNotAttached(t *testing.T) {
	coll := placeholderPrograms("kprobe_h2_tcp_sendmsg", "kretprobe_h2_tcp_sendmsg", "kprobe_h2_tcp_recvmsg", "kretprobe_h2_tcp_recvmsg", "kprobe_h2_tcp_close")
	calls, _ := installFakeKprobes(t, func(c kprobeCall) bool { return c.symbol == "tcp_recvmsg" && c.ret })

	links := AttachH2Probes(coll)
	for _, c := range *calls {
		if c.symbol == "tcp_recvmsg" && !c.ret {
			t.Error("the tcp_recvmsg entry attached although its return probe failed")
		}
	}
	if len(links) != 3 {
		t.Errorf("%d links, want sendmsg pair and tcp_close", len(links))
	}
}

func TestAReturnProbeIsReleasedWhenItsEntryCannotAttach(t *testing.T) {
	coll := placeholderPrograms("kprobe_http_tcp_sendmsg", "kprobe_http_tcp_recvmsg", "kretprobe_http_tcp_recvmsg")
	_, links := installFakeKprobes(t, func(c kprobeCall) bool { return c.symbol == "tcp_recvmsg" && !c.ret })

	got := AttachHTTPProbes(coll)
	if len(got) != 1 {
		t.Fatalf("%d links, want only the sendmsg entry", len(got))
	}
	for _, l := range *links {
		if l.closed == 0 && l != got[0] {
			t.Error("a return probe was left attached without its entry")
		}
	}

	withoutEntry := placeholderPrograms("kretprobe_unix_stream_recvmsg")
	_, links = installFakeKprobes(t, nil)
	if got := AttachFastCGIProbes(withoutEntry); len(got) != 0 {
		t.Errorf("FastCGI kept %d links with no entry program", len(got))
	}
	if len(*links) != 1 || (*links)[0].closed != 1 {
		t.Error("the return probe of a missing entry program was not released")
	}
	if got := AttachFastCGIProbes(placeholderPrograms("kprobe_unix_stream_recvmsg")); len(got) != 0 {
		t.Errorf("FastCGI attached %d links with no return program", len(got))
	}
}
