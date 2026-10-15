package tracer

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func TestFailedCgroupAttachIsRetriedOnTheNextSync(t *testing.T) {
	attempts := 0
	swapAttach(t, &attachHTTP3Probes, func(*ebpf.Collection, []string) []link.Link {
		attempts++
		if attempts == 1 {
			return nil
		}
		return []link.Link{&fakeLink{}}
	})
	tr := reconcileTracer()

	tr.syncHTTP3Probes([]string{"/cg/a"})
	if _, ok := tr.http3Links["/cg/a"]; ok {
		t.Fatal("a cgroup whose attach failed was recorded as attached")
	}
	tr.syncHTTP3Probes([]string{"/cg/a"})
	if attempts != 2 || len(tr.http3Links["/cg/a"]) != 1 {
		t.Fatalf("attempts=%d links=%d, want the failed attach retried once and recorded",
			attempts, len(tr.http3Links["/cg/a"]))
	}
	tr.syncHTTP3Probes([]string{"/cg/a"})
	if attempts != 2 {
		t.Fatalf("an attached cgroup was attached again: %d attempts", attempts)
	}
}

func TestRoundUpPow2_DoesNotOverflow(t *testing.T) {
	for _, n := range []uint32{1<<31 + 1, 3 << 30, ^uint32(0)} {
		if got := roundUpPow2(n); got != 1<<31 {
			t.Errorf("roundUpPow2(%d) = %d, want %d", n, got, uint32(1<<31))
		}
	}
	if got := roundUpPow2(1 << 31); got != 1<<31 {
		t.Errorf("roundUpPow2(1<<31) = %d", got)
	}
}
