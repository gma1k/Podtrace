//go:build bpf_loadtest && linux

package tracer

import (
	"context"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/events"
)

const pythonTLSClient = `
import gc, socket, ssl, sys
host, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = socket.create_connection((host, port))
if mode == "abandon":
    s.setblocking(False)
    t = ctx.wrap_socket(s, do_handshake_on_connect=False)
    try:
        t.do_handshake()
    except ssl.SSLWantReadError:
        pass
else:
    t = ctx.wrap_socket(s)
    t.do_handshake()
    t.do_handshake()
t.close()
del t
gc.collect()
`

func silentServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		_ = lis.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	return lis.Addr().String()
}

func TestKernelAnAbandonedHandshakeIsAFailureAndARepeatedOneCountsOnce(t *testing.T) {
	const lib = "/lib/x86_64-linux-gnu/libssl.so.3"
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 here")
	}
	if _, err := os.Stat(lib); err != nil {
		t.Skipf("no %s here", lib)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	exe, err := link.OpenExecutable(lib)
	if err != nil {
		t.Fatal(err)
	}
	for _, symbol := range append(openSSLSymbols, "SSL_accept") {
		for _, name := range []string{"uprobe_" + symbol, "uretprobe_" + symbol} {
			attach := exe.Uprobe
			if name[:3] == "ure" {
				attach = exe.Uretprobe
			}
			l, err := attach(symbol, tr.collection.Programs[name], nil)
			if err != nil {
				t.Fatalf("attach %s: %v", name, err)
			}
			t.Cleanup(func() { _ = l.Close() })
		}
	}
	l, err := exe.Uprobe("SSL_free", tr.collection.Programs["uprobe_SSL_free"], nil)
	if err != nil {
		t.Fatalf("attach uprobe_SSL_free: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan *events.Event, 1<<16)
	var mu sync.Mutex
	byPID := map[uint32][]int32{}
	go func() {
		for {
			select {
			case ev := <-ch:
				if ev.Type == events.EventTLSHandshake {
					mu.Lock()
					byPID[ev.PID] = append(byPID[ev.PID], ev.Error)
					mu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	if err := tr.Start(ctx, ch); err != nil {
		t.Fatalf("Start: %v", err)
	}

	run := func(addr, mode string) *exec.Cmd {
		hp := hostPort(addr)
		cmd := exec.Command(python, "-I", "-c", pythonTLSClient, hp[0], hp[1], mode)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s client: %v %s", mode, err, out)
		}
		return cmd
	}
	abandoned := run(silentServer(t), "abandon")
	repeated := run(tlsServer(t), "repeat")
	time.Sleep(2 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	failed := byPID[uint32(abandoned.Process.Pid)]
	if len(failed) != 1 || failed[0] >= 0 {
		t.Errorf("the abandoned handshake reported %v, want one handshake with a negative error", failed)
	}
	ok := byPID[uint32(repeated.Process.Pid)]
	if len(ok) != 1 || ok[0] != 0 {
		t.Errorf("the handshake called twice reported %v, want exactly one, without an error", ok)
	}
}
