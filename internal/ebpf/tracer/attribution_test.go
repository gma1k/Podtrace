package tracer

import (
	"os"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/attribution"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/cache"
	"github.com/gma1k/podtrace/internal/events"
)

func newAttributionTestTracer() *Tracer {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	return &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
		attributionTable: attribution.New(time.Minute, 64),
	}
}

func TestAttributeProcessName_EventCommWins(t *testing.T) {
	tracer := newAttributionTestTracer()
	ev := &events.Event{PID: 42, CgroupID: 7, ProcessName: "curl"}
	if source := tracer.attributeProcessName(ev); source != attributionSourceEventComm {
		t.Fatalf("source = %q, want event_comm", source)
	}
	if ev.ProcessName != "curl" {
		t.Fatalf("ProcessName mutated to %q", ev.ProcessName)
	}
}

func TestAttributeProcessName_CorrelatorFillsEmptyComm(t *testing.T) {
	tracer := newAttributionTestTracer()

	feeder := &events.Event{PID: 4194200, CgroupID: 7, ProcessName: "nslookup", Type: events.EventUDPSend}
	tracer.recordAttributionOutcome(feeder, tracer.attributeProcessName(feeder))

	dns := &events.Event{PID: 4194200, CgroupID: 7, Type: events.EventDNSQuery}
	if source := tracer.attributeProcessName(dns); source != attributionSourceCorrelator {
		t.Fatalf("source = %q, want correlator", source)
	}
	if dns.ProcessName != "nslookup" {
		t.Fatalf("ProcessName = %q, want nslookup", dns.ProcessName)
	}
}

func TestAttributeProcessName_ProcFallbackForUnknownPid(t *testing.T) {
	swapProcCgroupID(t, func(uint32) (uint64, bool) { return 7, true })
	tracer := newAttributionTestTracer()
	self := &events.Event{PID: uint32(os.Getpid()), CgroupID: 7, Type: events.EventDNSQuery}
	source := tracer.attributeProcessName(self)
	if source != attributionSourceProcFallback {
		t.Fatalf("source = %q, want proc_fallback", source)
	}
	if self.ProcessName == "" {
		t.Fatal("proc fallback produced no name for a live pid")
	}
}

func TestAttributeProcessName_NoneForDeadPid(t *testing.T) {
	tracer := newAttributionTestTracer()
	dead := &events.Event{PID: 4194303, CgroupID: 7, Type: events.EventDNSQuery}
	if source := tracer.attributeProcessName(dead); source != attributionSourceNone {
		t.Fatalf("source = %q, want none", source)
	}
	if dead.ProcessName != "" {
		t.Fatalf("ProcessName = %q, want empty", dead.ProcessName)
	}
}

func TestAttributeProcessName_CgroupMismatchMisses(t *testing.T) {
	tracer := newAttributionTestTracer()
	feeder := &events.Event{PID: 4194201, CgroupID: 7, ProcessName: "victim", Type: events.EventUDPSend}
	tracer.recordAttributionOutcome(feeder, tracer.attributeProcessName(feeder))

	otherPod := &events.Event{PID: 4194201, CgroupID: 99, Type: events.EventDNSQuery}
	if source := tracer.attributeProcessName(otherPod); source == attributionSourceCorrelator {
		t.Fatal("correlator attributed across cgroups (pid reuse hazard)")
	}
	if otherPod.ProcessName == "victim" {
		t.Fatal("stale identity leaked across cgroups")
	}
}

func TestRecordAttributionOutcome_DoesNotFeedFromCorrelatorOrProc(t *testing.T) {
	tracer := newAttributionTestTracer()

	ev := &events.Event{PID: 4194202, CgroupID: 7, ProcessName: "from-proc"}
	tracer.recordAttributionOutcome(ev, attributionSourceProcFallback)
	if _, ok, _ := tracer.attributionTable.Lookup(4194202, 7); ok {
		t.Fatal("proc-derived name was recorded into the attribution table")
	}

	ev2 := &events.Event{PID: 4194203, CgroupID: 7, ProcessName: "from-table"}
	tracer.recordAttributionOutcome(ev2, attributionSourceCorrelator)
	if _, ok, _ := tracer.attributionTable.Lookup(4194203, 7); ok {
		t.Fatal("correlator-derived name was recorded into the attribution table")
	}
}

func TestAttributionEventKind(t *testing.T) {
	cases := []struct {
		typ  events.EventType
		want string
	}{
		{events.EventDNS, "dns"},
		{events.EventDNSQuery, "dns"},
		{events.EventHTTP3, "quic"},
		{events.EventConnect, "other"},
		{events.EventExec, "other"},
	}
	for _, c := range cases {
		if got := attributionEventKind(c.typ); got != c.want {
			t.Errorf("attributionEventKind(%v) = %q, want %q", c.typ, got, c.want)
		}
	}
}

func TestHaveSkStorageCrossContext(t *testing.T) {
	first := HaveSkStorageCrossContext()
	second := HaveSkStorageCrossContext()
	if first != second {
		t.Fatalf("probe not stable: first=%v second=%v", first, second)
	}
}
