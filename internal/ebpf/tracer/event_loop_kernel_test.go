//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

func ownCgroupID(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skipf("no cgroup: %v", err)
	}
	var path string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::") {
			path = strings.TrimPrefix(line, "0::")
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/sys/fs/cgroup"+path, &st); err != nil {
		t.Skipf("no cgroup v2 directory for %q: %v", path, err)
	}
	return st.Ino
}

func readRequestHead(t *testing.T, c net.Conn) {
	t.Helper()
	var head bytes.Buffer
	buf := make([]byte, 512)
	for !bytes.Contains(head.Bytes(), []byte("\r\n\r\n")) {
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
		head.Write(buf[:n])
	}
}

var burnSink uint64

//go:noinline
func burnForTheSlowRequest(d time.Duration) uint64 {
	end := time.Now().Add(d)
	x := uint64(1)
	for time.Now().Before(end) {
		for i := 0; i < 1000; i++ {
			x = x*6364136223846793005 + 1442695040888963407
		}
	}
	return x
}

func TestKernelAnEventLoopChargesTheRequestWhoseConnectionItServes(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	tr.attachGlobalProtocolProbesOnce()
	own := ownCgroupID(t)
	if err := tr.collection.Maps["target_cgroup_ids"].Put(own, uint8(1)); err != nil {
		t.Fatalf("target this process: %v", err)
	}
	if _, err := tr.StartOnCPUSampler(); err != nil {
		t.Skipf("no on-CPU sampler here: %v", err)
	}
	if _, err := tr.DrainOnCPUSamples(); err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	addr := lis.Addr().String()

	sendBody := make(chan struct{})
	clientsDone := make(chan error, 2)
	client := func(head string, body <-chan struct{}) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			clientsDone <- err
			return
		}
		defer func() { _ = c.Close() }()
		if _, err := io.WriteString(c, head); err != nil {
			clientsDone <- err
			return
		}
		if body != nil {
			<-body
			if _, err := io.WriteString(c, "body"); err != nil {
				clientsDone <- err
				return
			}
		}
		_, err = bufio.NewReader(c).ReadString('\n')
		clientsDone <- err
	}

	served := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		go client("POST /slow HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n", sendBody)
		slow, err := lis.Accept()
		if err != nil {
			served <- err
			return
		}
		defer func() { _ = slow.Close() }()
		readRequestHead(t, slow)

		go client("GET /fast HTTP/1.1\r\nHost: x\r\n\r\n", nil)
		fast, err := lis.Accept()
		if err != nil {
			served <- err
			return
		}
		defer func() { _ = fast.Close() }()
		readRequestHead(t, fast)

		close(sendBody)
		if _, err := io.ReadFull(slow, make([]byte, 4)); err != nil {
			served <- err
			return
		}
		burnSink = burnForTheSlowRequest(400 * time.Millisecond)
		if _, err := io.WriteString(slow, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
			served <- err
			return
		}
		_, err = io.WriteString(fast, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		served <- err
	}()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := <-clientsDone; err != nil {
			t.Fatalf("client: %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	drained, err := tr.DrainOnCPUSamples()
	if err != nil {
		t.Fatal(err)
	}
	var slowID, fastID uint64
	var slowLatency uint64
	var mine []uint64
	for _, c := range drained.Completions {
		if c.CgroupID != own {
			continue
		}
		mine = append(mine, c.CorrelationID)
		if c.LatencyNS > slowLatency {
			fastID, slowID, slowLatency = slowID, c.CorrelationID, c.LatencyNS
		} else {
			fastID = c.CorrelationID
		}
	}
	if len(mine) != 2 || slowLatency < uint64(300*time.Millisecond) {
		t.Fatalf("this process's completions = %v, want the slow and the fast request", mine)
	}
	slowSamples, fastSamples := uint64(0), uint64(0)
	for _, s := range drained.Samples {
		switch s.CorrelationID {
		case slowID:
			slowSamples += s.Count
		case fastID:
			fastSamples += s.Count
		}
	}
	if slowSamples < 10 {
		t.Errorf("the slow request was charged %d samples for 400ms of CPU on its connection", slowSamples)
	}
	if fastSamples > slowSamples/10 {
		t.Errorf("the fast request was charged %d samples, the slow one %d; the thread read the fast request last, but it was serving the slow one", fastSamples, slowSamples)
	}
}

func TestKernelAThreadPerRequestServerKeepsItsRequestAcrossBackendIO(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	tr.attachGlobalProtocolProbesOnce()
	own := ownCgroupID(t)
	if err := tr.collection.Maps["target_cgroup_ids"].Put(own, uint8(1)); err != nil {
		t.Fatalf("target this process: %v", err)
	}
	if _, err := tr.StartOnCPUSampler(); err != nil {
		t.Skipf("no on-CPU sampler here: %v", err)
	}
	if _, err := tr.DrainOnCPUSamples(); err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 16)
		if n, err := c.Read(buf); err == nil {
			_, _ = c.Write(buf[:n])
		}
	}()

	clientDone := make(chan error, 1)
	go func() {
		c, err := net.Dial("tcp", lis.Addr().String())
		if err != nil {
			clientDone <- err
			return
		}
		defer func() { _ = c.Close() }()
		if _, err := io.WriteString(c, "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			clientDone <- err
			return
		}
		_, err = bufio.NewReader(c).ReadString('\n')
		clientDone <- err
	}()

	served := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		c, err := lis.Accept()
		if err != nil {
			served <- err
			return
		}
		defer func() { _ = c.Close() }()
		readRequestHead(t, c)
		db, err := net.Dial("tcp", backend.Addr().String())
		if err != nil {
			served <- err
			return
		}
		defer func() { _ = db.Close() }()
		if _, err := io.WriteString(db, "query"); err != nil {
			served <- err
			return
		}
		if _, err := io.ReadFull(db, make([]byte, 5)); err != nil {
			served <- err
			return
		}
		burnSink = burnForTheSlowRequest(400 * time.Millisecond)
		_, err = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		served <- err
	}()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("client: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	drained, err := tr.DrainOnCPUSamples()
	if err != nil {
		t.Fatal(err)
	}
	var requestID uint64
	for _, c := range drained.Completions {
		if c.CgroupID == own && c.LatencyNS >= uint64(300*time.Millisecond) {
			requestID = c.CorrelationID
		}
	}
	if requestID == 0 {
		t.Fatalf("no completion for the request among %+v", drained.Completions)
	}
	charged := uint64(0)
	for _, s := range drained.Samples {
		if s.CorrelationID == requestID {
			charged += s.Count
		}
	}
	if charged < 10 {
		t.Errorf("the request was charged %d samples for 400ms of CPU after its backend call", charged)
	}
}
