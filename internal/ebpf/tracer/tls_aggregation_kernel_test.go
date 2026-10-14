//go:build bpf_loadtest && linux

package tracer

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func TestKernelAFailedHandshakeReachesTheAggregatedRows(t *testing.T) {
	hl := handshakeLibraries[0]
	if _, err := os.Stat(hl.lib); err != nil {
		t.Skipf("no %s here", hl.lib)
	}
	if _, err := os.Stat(hl.client); err != nil {
		t.Skipf("no %s here", hl.client)
	}
	for _, mode := range []kernelagg.Mode{kernelagg.ModeOn, kernelagg.ModeBypass} {
		t.Run(mode.String(), func(t *testing.T) {
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
				for _, ret := range []bool{true, false} {
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
			if err := tr.SetKernelAggregationMode(mode); err != nil {
				t.Fatal(err)
			}

			if out, err := hl.command(hl.client, notTLSServer(t)).CombinedOutput(); err == nil {
				t.Fatalf("a handshake with a server that does not speak TLS succeeded: %s", out)
			}
			if out, err := hl.command(hl.client, tlsServer(t)).CombinedOutput(); err != nil {
				t.Fatalf("the handshake with a TLS server failed: %v %s", err, out)
			}

			rows, err := tr.DrainKernelMetrics()
			if err != nil {
				t.Fatal(err)
			}
			cgroup := ownCgroupID(t)
			var handshakes, failed, latencyNS uint64
			for _, r := range rows {
				if r.Key.CgroupID != cgroup || events.EventType(r.Key.EventType) != events.EventTLSHandshake {
					continue
				}
				handshakes += r.Value.Count
				latencyNS += r.Value.SumNS
				if kernelagg.DecodeVariant(r.Key.Variant).IsError {
					failed += r.Value.Count
				}
			}
			if handshakes != 2 || failed != 1 {
				t.Errorf("%d handshakes, %d failed, want 2 and 1: the plane reads failures from the error bit "+
					"of these rows and handshakes from their count", handshakes, failed)
			}
			if latencyNS == 0 {
				t.Error("the handshakes carry no duration")
			}
		})
	}
}
