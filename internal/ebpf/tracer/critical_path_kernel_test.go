//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/analysis/criticalpath"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
)

func stampedTrace(t *testing.T, stamp bool) *eventLog {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	tr.attachGlobalProtocolProbesOnce()
	links, err := probes.AttachProbeGroup(tr.collection, probes.GroupNetwork)
	if err != nil {
		t.Fatalf("attach network: %v", err)
	}
	t.Cleanup(func() {
		for _, l := range links {
			_ = l.Close()
		}
	})
	own := ownCgroupID(t)
	if err := tr.SetCgroups([]string{ownCgroupPath(t)}); err != nil {
		t.Fatalf("target this process: %v", err)
	}
	if err := tr.SetEnabledCategories([]string{"net"}); err != nil {
		t.Fatalf("network only: %v", err)
	}
	if stamp {
		if err := tr.StampRequests(); err != nil {
			t.Fatalf("StampRequests: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan *events.Event, 1<<16)
	log := &eventLog{}
	go func() {
		for {
			select {
			case ev := <-ch:
				if ev.CgroupID == own && ev.CorrelationID != 0 {
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

func ownCgroupPath(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skipf("no cgroup: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return "/sys/fs/cgroup" + rest
		}
	}
	t.Skip("no cgroup v2 membership")
	return ""
}

func slowBackend(t *testing.T, delay time.Duration) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 16)
				if _, err := c.Read(buf); err != nil {
					return
				}
				time.Sleep(delay)
				_, _ = c.Write([]byte("reply"))
			}()
		}
	}()
	return lis.Addr().String()
}

func blockingSocket(t *testing.T) int {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func sockaddr(t *testing.T, addr string) *syscall.SockaddrInet4 {
	t.Helper()
	tcp, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	sa := &syscall.SockaddrInet4{Port: tcp.Port}
	copy(sa.Addr[:], tcp.IP.To4())
	return sa
}

func serveOneBlockingRequest(t *testing.T, path, backend string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	lfd := blockingSocket(t)
	defer func() { _ = syscall.Close(lfd) }()
	if err := syscall.Bind(lfd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return err
	}
	if err := syscall.Listen(lfd, 1); err != nil {
		return err
	}
	bound, err := syscall.Getsockname(lfd)
	if err != nil {
		return err
	}
	port := bound.(*syscall.SockaddrInet4).Port

	clientDone := make(chan error, 1)
	go func() {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			clientDone <- err
			return
		}
		defer func() { _ = c.Close() }()
		if _, err := io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			clientDone <- err
			return
		}
		_, err = bufio.NewReader(c).ReadString('\n')
		clientDone <- err
	}()

	cfd, _, err := syscall.Accept(lfd)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(cfd) }()
	if _, err := syscall.Read(cfd, make([]byte, 512)); err != nil {
		return err
	}

	bfd := blockingSocket(t)
	defer func() { _ = syscall.Close(bfd) }()
	if err := syscall.Connect(bfd, sockaddr(t, backend)); err != nil {
		return err
	}
	if _, err := syscall.Write(bfd, []byte("query")); err != nil {
		return err
	}
	if _, err := syscall.Read(bfd, make([]byte, 16)); err != nil {
		return err
	}
	if _, err := syscall.Write(cfd, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		return err
	}
	return <-clientDone
}

func TestKernelConcurrentRequestsInOneProcessKeepTheirOwnWaits(t *testing.T) {
	log := stampedTrace(t, true)
	slow, fast := slowBackend(t, 400*time.Millisecond), slowBackend(t, 50*time.Millisecond)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, r := range []struct{ path, backend string }{{"/slow", slow}, {"/fast", fast}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- serveOneBlockingRequest(t, r.path, r.backend)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(500 * time.Millisecond)

	collector := criticalpath.New()
	var done []*events.Event
	for _, ev := range log.events() {
		collector.Feed(ev)
		if ev.Type == events.EventRequestDone {
			done = append(done, ev)
		}
	}
	if len(done) != 2 {
		t.Fatalf("got %d request-done events, want one per request: %+v", len(done), done)
	}

	waits := map[uint64]uint64{}
	for _, ev := range log.events() {
		if ev.Type == events.EventTCPRecv && ev.LatencyNS > waits[ev.CorrelationID] {
			waits[ev.CorrelationID] = ev.LatencyNS
		}
	}
	for _, d := range done {
		wait := time.Duration(waits[d.CorrelationID])
		latency := time.Duration(d.LatencyNS)
		switch {
		case latency >= 350*time.Millisecond:
			if wait < 350*time.Millisecond {
				t.Errorf("the slow request (%v) was stamped with a %v backend wait; its own wait is 400ms", latency, wait)
			}
		default:
			if wait < 40*time.Millisecond || wait >= 350*time.Millisecond {
				t.Errorf("the fast request (%v) was stamped with a %v backend wait; its own wait is 50ms", latency, wait)
			}
		}
	}

	s := collector.Summary()
	if len(s.Slowest) != 2 || s.Slowest[0].Endpoint != "GET /slow" {
		t.Fatalf("slowest requests = %+v, want /slow first with its endpoint", s.Slowest)
	}
	var network time.Duration
	for _, sh := range s.Slowest[0].Shares {
		if sh.Category == criticalpath.Network {
			network = sh.Duration
		}
	}
	if network < s.Slowest[0].Latency*3/4 {
		t.Errorf("the slow request spent %v of %v waiting on its backend, the breakdown says %v: %+v",
			400*time.Millisecond, s.Slowest[0].Latency, network, s.Slowest[0].Shares)
	}
}

func TestKernelNothingIsStampedUntilTheCriticalPathAsks(t *testing.T) {
	log := stampedTrace(t, false)
	if err := serveOneBlockingRequest(t, "/quiet", slowBackend(t, 20*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	for _, ev := range log.events() {
		if ev.CorrelationID != 0 && (ev.Type == events.EventTCPRecv || ev.Type == events.EventRequestDone) {
			t.Errorf("stamping is off but a %v event carries correlation id %d", ev.Type, ev.CorrelationID)
		}
	}
}

func TestKernelRequestsWokenTogetherGetDistinctIDs(t *testing.T) {
	log := stampedTrace(t, true)
	const servers, rounds = 16, 25

	ready := make(chan net.Conn, servers)
	var wg sync.WaitGroup
	for i := 0; i < servers; i++ {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lis.Close() })
		lfd := listenerFD(t, lis)
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			cfd, _, err := syscall.Accept(lfd)
			if err != nil {
				return
			}
			defer func() { _ = syscall.Close(cfd) }()
			buf := make([]byte, 512)
			for r := 0; r < rounds; r++ {
				if _, err := syscall.Read(cfd, buf); err != nil {
					return
				}
				if _, err := syscall.Write(cfd, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")); err != nil {
					return
				}
			}
		}()
		c, err := net.Dial("tcp", lis.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		ready <- c
	}
	close(ready)
	var clients []net.Conn
	for c := range ready {
		clients = append(clients, c)
	}
	request := []byte("GET /together HTTP/1.1\r\nHost: x\r\n\r\n")
	for r := 0; r < rounds; r++ {
		start := make(chan struct{})
		var sent sync.WaitGroup
		for _, c := range clients {
			sent.Add(1)
			go func() {
				defer sent.Done()
				<-start
				if _, err := c.Write(request); err != nil {
					return
				}
				_, _ = c.Read(make([]byte, 64))
			}()
		}
		close(start)
		sent.Wait()
	}
	wg.Wait()
	time.Sleep(500 * time.Millisecond)

	seen := map[uint64]int{}
	done := 0
	for _, ev := range log.events() {
		if ev.Type == events.EventRequestDone {
			done++
			seen[ev.CorrelationID]++
		}
	}
	if done < servers*rounds/2 {
		t.Fatalf("only %d of %d requests finished", done, servers*rounds)
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("%d requests share correlation id %d; their waits and their CPU merge into one", n, id)
		}
	}
}

func listenerFD(t *testing.T, lis net.Listener) int {
	t.Helper()
	f, err := lis.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	fd := int(f.Fd())
	if err := syscall.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	return fd
}
