package tracer

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/ebpf/h3decode"
	"github.com/gma1k/podtrace/internal/ebpf/h3stream"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

func TestAContainerWhoseBinariesAllVanishedStillGetsOnePID(t *testing.T) {
	const cid = "0123456789ab0123456789ab0123456789ab0123456789ab0123456789ab0123"
	cgroupDir := fakeContainerProc(t, cid, []uint32{301, 302}, map[uint32]string{})
	tr := &Tracer{}
	tr.setCgroupPaths([]string{cgroupDir})

	if got := tr.pidsForContainer(cid, nil); len(got) != 1 || got[0] != 301 {
		t.Errorf("pidsForContainer = %v, want [301]: with no executable left to inspect, the "+
			"first process still gives uprobe discovery somewhere to start", got)
	}
}

func TestAnUnknownGroupAttachesNoContainerUprobes(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{}}
	if ls := tr.attachContainerGroupUprobes(probes.ProbeGroup("no-such-group"), "c1", []uint32{1}, nil); ls != nil {
		t.Errorf("an unknown group attached %d links", len(ls))
	}
}

func TestReattachSkipsEmptyAttachesAndDropsLinksForAContainerThatLeft(t *testing.T) {
	tr := &Tracer{containerUprobes: map[string]*containerUprobeSet{
		"empty":   {pids: []uint32{1}},
		"nolinks": {pids: []uint32{2}},
		"moved":   {pids: []uint32{3}},
		"gone":    {pids: []uint32{4}},
	}}
	var kept, stale *fakeLink
	tr.attachContainerGroupFn = func(_ probes.ProbeGroup, id string, _ []uint32) []link.Link {
		switch id {
		case "empty":
			return nil
		case "moved":
			tr.probeGroupsMu.Lock()
			tr.containerUprobes["moved"].pids = []uint32{99}
			tr.probeGroupsMu.Unlock()
			kept = &fakeLink{}
			return []link.Link{kept}
		case "gone":
			tr.probeGroupsMu.Lock()
			delete(tr.containerUprobes, "gone")
			tr.probeGroupsMu.Unlock()
			stale = &fakeLink{}
			return []link.Link{stale}
		default:
			return []link.Link{&fakeLink{}}
		}
	}

	if got := tr.reattachContainerGroupUprobes(probes.GroupTLS); got != 2 {
		t.Errorf("reattached %d links, want 2 (the containers still targeted)", got)
	}
	if len(tr.containerUprobes["nolinks"].links[probes.GroupTLS]) != 1 {
		t.Error("a container with no link map did not get its reattached link")
	}
	if kept.closes.Load() != 0 || len(tr.containerUprobes["moved"].links[probes.GroupTLS]) != 1 {
		t.Error("a uprobe is bound to a file, not a PID: a container whose processes changed keeps its link")
	}
	if stale.closes.Load() != 1 {
		t.Errorf("a link attached for a container that left the target set was closed %d times, want 1", stale.closes.Load())
	}
}

func TestATxnWithNoStashOrConnectionIsNotParked(t *testing.T) {
	if (&Tracer{}).h3EnrichOrPark(&h3decode.Txn{AdapterConn: 1, IsClient: true}) {
		t.Error("parked a txn with no section stash to ever enrich it")
	}
	tr := &Tracer{h3SectionStash: h3stream.NewSectionStash(time.Minute, 16)}
	if tr.h3EnrichOrPark(&h3decode.Txn{AdapterConn: 0, IsClient: true}) {
		t.Error("parked a txn with no connection to key it on")
	}
}

func TestTheParkingLotIsBounded(t *testing.T) {
	tr := &Tracer{h3SectionStash: h3stream.NewSectionStash(time.Minute, 16)}
	for i := 0; i < h3MaxParked; i++ {
		tr.h3Parked = append(tr.h3Parked, h3ParkedTxn{})
	}
	if tr.h3EnrichOrPark(&h3decode.Txn{PID: 1, AdapterConn: 2, IsClient: true}) {
		t.Error("a txn was parked past h3MaxParked; the lot would grow without bound")
	}
}

func TestPIDNamespaceStatReportsWhenNeitherNamespaceIsReadable(t *testing.T) {
	orig := selfPIDNamespace
	selfPIDNamespace = "/nonexistent/ns/pid"
	t.Cleanup(func() { selfPIDNamespace = orig })

	if _, _, err := pidNamespaceStat(t.TempDir()); err == nil {
		t.Error("no error when neither the node's nor the agent's PID namespace could be read")
	}
}

type noStat struct{ os.FileInfo }

func (noStat) Sys() any { return nil }

func TestAFileInfoWithoutStatDataYieldsNoRecord(t *testing.T) {
	st, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statRecordOf(noStat{st}); err == nil {
		t.Error("a stat record was invented for a FileInfo without one")
	}
	if _, err := getCgroupIDFromPath("/nonexistent/cgroup"); err == nil {
		t.Error("a missing cgroup path returned an id")
	}
}

func TestAManagementAPIThatCannotListenReturns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	done := make(chan struct{})
	go func() { (&Tracer{}).serveManagementAPI(context.Background(), port); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveManagementAPI did not return when its port was taken")
	}
}

func TestASecondProcessOfTheSameBinaryAddsNoBinaryProbes(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{}}
	af := probes.NewAttachedFiles()
	self := uint32(os.Getpid())
	if ls := tr.attachContainerGroupUprobes(probes.GroupTLS, "c1", []uint32{self, self}, af); len(ls) != 0 {
		t.Errorf("an empty collection attached %d links", len(ls))
	}
	if af.Claim("exe:"+string(probes.GroupTLS), fmt.Sprintf("/proc/%d/exe", self)) {
		t.Error("the first process's binary was not recorded, so a second process would attach its probes again")
	}
}

func TestReenablingAGroupStartsItsAttachedFileRecordAfresh(t *testing.T) {
	stale := probes.NewAttachedFiles()
	set := &containerUprobeSet{pids: []uint32{1}, claimed: map[probes.ProbeGroup]*probes.AttachedFiles{probes.GroupTLS: stale}}
	tr := &Tracer{containerUprobes: map[string]*containerUprobeSet{"c": set}}
	var got *probes.AttachedFiles
	tr.attachContainerGroupFn = func(probes.ProbeGroup, string, []uint32) []link.Link { return nil }
	tr.reattachContainerGroupUprobes(probes.GroupTLS)
	got = set.claimed[probes.GroupTLS]
	if got == nil || got == stale {
		t.Error("re-enabling a group must forget which files the closed probes had covered, or nothing is re-attached")
	}
}
