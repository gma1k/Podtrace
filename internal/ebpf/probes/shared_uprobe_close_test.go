package probes

import (
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
)

type blockingLink struct {
	link.Link
	entered chan struct{}
	unblock chan struct{}
}

func (b *blockingLink) Close() error {
	close(b.entered)
	<-b.unblock
	return nil
}

func TestReleasingOneUprobeDoesNotWaitForAnotherToClose(t *testing.T) {
	r := newRegistry()
	slow := &blockingLink{entered: make(chan struct{}), unblock: make(chan struct{})}
	defer close(slow.unblock)
	fast := &fakeLink{}
	slowSite := uprobeSite{file: fileID{ino: 1}, symbol: "slow"}
	fastSite := uprobeSite{file: fileID{ino: 1}, symbol: "fast"}

	slowHandle, err := r.acquire(slowSite, func() (link.Link, error) { return slow, nil })
	if err != nil {
		t.Fatal(err)
	}
	fastHandle, err := r.acquire(fastSite, func() (link.Link, error) { return fast, nil })
	if err != nil {
		t.Fatal(err)
	}

	go func() { _ = slowHandle.Close() }()
	<-slow.entered

	done := make(chan struct{})
	go func() { _ = fastHandle.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a uprobe link close held the registry lock, so every other close waited behind it")
	}
	if fast.closed != 1 {
		t.Errorf("fast link closed %d times, want 1", fast.closed)
	}

	reattached := 0
	if _, err := r.acquire(slowSite, func() (link.Link, error) { reattached++; return &fakeLink{}, nil }); err != nil {
		t.Fatal(err)
	}
	if reattached != 1 {
		t.Error("a site whose last link is still closing must be attached afresh, not handed the closing link")
	}
}
