//go:build bpf_loadtest && linux

package tracer

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
)

type eventLog struct {
	mu   sync.Mutex
	kept []*events.Event
}

func (l *eventLog) events() []*events.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*events.Event(nil), l.kept...)
}

func traceGroup(t *testing.T, group probes.ProbeGroup, keep func(*events.Event) bool) *eventLog {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	links, err := probes.AttachProbeGroup(tr.collection, group)
	if err != nil {
		t.Fatalf("attach %s: %v", group, err)
	}
	t.Cleanup(func() {
		for _, l := range links {
			_ = l.Close()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan *events.Event, 1<<16)
	log := &eventLog{}
	go func() {
		for {
			select {
			case ev := <-ch:
				if keep(ev) {
					log.mu.Lock()
					log.kept = append(log.kept, ev)
					log.mu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	if err := tr.Start(ctx, ch); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return log
}

func TestKernelAFailedRenameCarriesItsErrno(t *testing.T) {
	log := traceGroup(t, probes.GroupFileSystem, func(ev *events.Event) bool {
		return ev.Type == events.EventRename && strings.Contains(ev.Target, "errno-rename-from")
	})
	dir := t.TempDir()
	from := filepath.Join(dir, "errno-rename-from")
	to := filepath.Join(dir, "errno-rename-to")
	if err := os.Mkdir(from, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(to, "occupied"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Rename(from, to); !errors.Is(err, syscall.ENOTEMPTY) {
		t.Fatalf("rename over a non-empty directory = %v", err)
	}
	time.Sleep(2 * time.Second)

	got := log.events()
	if len(got) == 0 {
		t.Fatal("the rename was not seen")
	}
	for _, ev := range got {
		if ev.Error != -int32(syscall.ENOTEMPTY) {
			t.Errorf("rename %q error = %d, want -ENOTEMPTY", ev.Target, ev.Error)
		}
	}
}

func resetConnection(t *testing.T) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		c, err := lis.Accept()
		if err == nil {
			accepted <- c.(*net.TCPConn)
		}
	}()
	client, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server := <-accepted
	readErr := make(chan error, 1)
	go func() {
		_, err := client.Read(make([]byte, 16))
		readErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = server.SetLinger(0)
	_ = server.Close()
	if err := <-readErr; !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("read after the peer reset = %v", err)
	}
}

func TestKernelAResetConnectionCarriesItsErrnoAndAnEmptyReadNone(t *testing.T) {
	pid := uint32(os.Getpid())
	log := traceGroup(t, probes.GroupNetwork, func(ev *events.Event) bool {
		return ev.Type == events.EventTCPRecv && ev.PID == pid
	})
	for i := 0; i < 20; i++ {
		resetConnection(t)
	}
	time.Sleep(2 * time.Second)

	got := log.events()
	reset, wouldBlock := 0, 0
	for _, ev := range got {
		switch ev.Error {
		case -int32(syscall.ECONNRESET):
			reset++
		case -int32(syscall.EAGAIN):
			wouldBlock++
		}
	}
	if reset == 0 {
		t.Errorf("no receive carried -ECONNRESET among %d receives", len(got))
	}
	if wouldBlock != 0 {
		t.Errorf("%d receives that found no data were reported as errors", wouldBlock)
	}
}
