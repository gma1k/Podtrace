//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/events"
)

const (
	goTLSWorkerOK    = "PODTRACE_GO_TLS_WORKER_OK"
	goTLSWorkerPlain = "PODTRACE_GO_TLS_WORKER_PLAIN"
)

func TestKernelGoTLSWorker(t *testing.T) {
	ok, plain := os.Getenv(goTLSWorkerOK), os.Getenv(goTLSWorkerPlain)
	if ok == "" {
		t.Skip("only runs as the child of the Go TLS handshake kernel test")
	}
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{InsecureSkipVerify: true}
	c, err := tls.Dial("tcp", ok, cfg)
	if err != nil {
		t.Fatalf("handshake with the TLS server: %v", err)
	}
	_ = c.Close()
	if c, err := tls.Dial("tcp", plain, cfg); err == nil {
		_ = c.Close()
		t.Fatal("a handshake with a server that does not speak TLS succeeded")
	}
	fmt.Println("done")
}

func TestKernelAGoTLSHandshakeIsCountedByItsOutcome(t *testing.T) {
	w := newFSWorker(t, "go-tls")
	tr := fsTracer(t, "fentry", w)
	if err := tr.SetKernelAggregationMode(kernelagg.ModeBypass); err != nil {
		t.Fatal(err)
	}
	links := probes.AttachGoTLSProbes(tr.collection, uint32(os.Getpid()))
	t.Cleanup(func() {
		for _, l := range links {
			_ = l.Close()
		}
	})

	runInCgroup(t, w.cgroup, "TestKernelGoTLSWorker",
		goTLSWorkerOK+"="+tlsServer(t), goTLSWorkerPlain+"="+notTLSServer(t))
	time.Sleep(200 * time.Millisecond)

	rows, err := tr.DrainKernelMetrics()
	if err != nil {
		t.Fatal(err)
	}
	var handshakes, failed uint64
	for _, r := range rows {
		if r.Key.CgroupID != w.id || events.EventType(r.Key.EventType) != events.EventTLSHandshake {
			continue
		}
		handshakes += r.Value.Count
		if kernelagg.DecodeVariant(r.Key.Variant).IsError {
			failed += r.Value.Count
		}
	}
	if handshakes != 2 || failed != 1 {
		t.Errorf("%d Go handshakes, %d failed, want 2 and 1 (%d links attached)", handshakes, failed, len(links))
	}
}
