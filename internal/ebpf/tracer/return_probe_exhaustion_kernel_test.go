//go:build bpf_loadtest && linux

package tracer

import (
	"net"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func parkReadersInRecv(t *testing.T, n int) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	lfd := listenerFD(t, lis)
	var parked sync.WaitGroup
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", lis.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		parked.Add(1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			cfd, _, err := syscall.Accept(lfd)
			parked.Done()
			if err != nil {
				return
			}
			defer func() { _ = syscall.Close(cfd) }()
			_, _ = syscall.Read(cfd, make([]byte, 16))
		}()
	}
	parked.Wait()
	time.Sleep(200 * time.Millisecond)
}

func TestKernelRequestsStillFinishWhileManyThreadsWaitInRecv(t *testing.T) {
	log := stampedTrace(t, true)
	parkReadersInRecv(t, 4*runtime.NumCPU()+16)

	const servers, rounds = 16, 25
	var wg sync.WaitGroup
	var clients []net.Conn
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
		clients = append(clients, c)
	}
	request := []byte("GET /parked HTTP/1.1\r\nHost: x\r\n\r\n")
	for r := 0; r < rounds; r++ {
		var sent sync.WaitGroup
		for _, c := range clients {
			sent.Add(1)
			go func() {
				defer sent.Done()
				if _, err := c.Write(request); err != nil {
					return
				}
				_, _ = c.Read(make([]byte, 64))
			}()
		}
		sent.Wait()
	}
	wg.Wait()
	time.Sleep(500 * time.Millisecond)

	done := 0
	for _, ev := range log.events() {
		if ev.Type == events.EventRequestDone {
			done++
		}
	}
	if done != servers*rounds {
		t.Errorf("%d of %d requests finished while %d threads waited in recv: the return probe "+
			"dropped the rest", done, servers*rounds, 4*runtime.NumCPU()+16)
	}
}
