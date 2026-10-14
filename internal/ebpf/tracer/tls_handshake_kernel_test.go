//go:build bpf_loadtest && linux

package tracer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/events"
)

func tlsServer(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
	}
	go func() { _ = srv.ServeTLS(lis, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return lis.Addr().String()
}

func notTLSServer(t *testing.T) string {
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
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = c.Read(make([]byte, 4096))
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			_ = c.Close()
		}
	}()
	return lis.Addr().String()
}

type handshakeLibrary struct {
	name    string
	lib     string
	symbols []string
	client  string
	command func(client, addr string) *exec.Cmd
}

func hostPort(addr string) []string {
	host, port, _ := net.SplitHostPort(addr)
	return []string{host, port}
}

func nonBlockingClient(client, addr string) *exec.Cmd {
	return exec.Command(client, hostPort(addr)...)
}

var openSSLSymbols = []string{"SSL_connect", "SSL_do_handshake", "SSL_get_error"}

var handshakeLibraries = []handshakeLibrary{
	{"openssl-curl", "/lib/x86_64-linux-gnu/libssl.so.3", openSSLSymbols, "/usr/bin/curl",
		func(client, addr string) *exec.Cmd { return exec.Command(client, "-sk", "https://"+addr+"/") }},
	{"openssl", "/usr/lib/x86_64-linux-gnu/libssl.so.3", openSSLSymbols, "/usr/local/bin/openssl-nb-client", nonBlockingClient},
	{"libressl", "/usr/lib/libssl.so.59", openSSLSymbols, "/usr/local/bin/openssl-nb-client", nonBlockingClient},
	{"gnutls", "/usr/lib/x86_64-linux-gnu/libgnutls.so.30", []string{"gnutls_handshake"}, "/usr/local/bin/gnutls-nb-client", nonBlockingClient},
	{"mbedtls", "/usr/lib/x86_64-linux-gnu/libmbedtls.so.21", []string{"mbedtls_ssl_handshake"}, "/usr/local/bin/mbedtls-nb-client", nonBlockingClient},
}

func TestKernelATLSHandshakeReportsItsOutcomeNotItsRetries(t *testing.T) {
	for _, hl := range handshakeLibraries {
		t.Run(hl.name, func(t *testing.T) {
			if _, err := os.Stat(hl.lib); err != nil {
				t.Skipf("no %s here", hl.lib)
			}
			if _, err := os.Stat(hl.client); err != nil {
				t.Skipf("no %s here", hl.client)
			}
			if err := rlimit.RemoveMemlock(); err != nil {
				t.Skipf("cannot raise memlock: %v", err)
			}
			tr, err := NewTracer()
			if err != nil {
				t.Skipf("cannot load the podtrace object here: %v", err)
			}
			t.Cleanup(func() { _ = tr.Stop() })
			exe, err := link.OpenExecutable(hl.lib)
			if err != nil {
				t.Fatal(err)
			}
			for _, symbol := range hl.symbols {
				for _, ret := range []bool{false, true} {
					name, attach := "uprobe_"+symbol, exe.Uprobe
					if ret {
						name, attach = "uretprobe_"+symbol, exe.Uretprobe
					}
					l, err := attach(symbol, tr.collection.Programs[name], nil)
					if err != nil {
						t.Fatalf("attach %s: %v", name, err)
					}
					t.Cleanup(func() { _ = l.Close() })
				}
			}

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

			refused := hl.command(hl.client, notTLSServer(t))
			refusedOut, err := refused.CombinedOutput()
			if err == nil {
				t.Fatalf("a handshake with a server that does not speak TLS succeeded: %s", refusedOut)
			}
			t.Logf("refused client: %s", refusedOut)
			accepted := hl.command(hl.client, tlsServer(t))
			out, err := accepted.CombinedOutput()
			if err != nil {
				t.Fatalf("the handshake with a TLS server failed: %v %s", err, out)
			}
			t.Logf("client: %s", out)
			time.Sleep(2 * time.Second)

			mu.Lock()
			defer mu.Unlock()
			failed := byPID[uint32(refused.Process.Pid)]
			if len(failed) != 1 || failed[0] >= 0 {
				t.Errorf("the failed handshake reported %v, want one handshake with a negative error", failed)
			}
			ok := byPID[uint32(accepted.Process.Pid)]
			if len(ok) != 1 || ok[0] != 0 {
				t.Errorf("the successful handshake reported %v, want exactly one, without an error", ok)
			}
		})
	}
}
