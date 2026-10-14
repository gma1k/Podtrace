//go:build bpf_loadtest && linux

package tracer

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
	"github.com/gma1k/podtrace/internal/events"
)

func onCPUCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	specs := map[string]*ebpf.MapSpec{
		oncpu.EnabledMapName:  {Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1},
		oncpu.CountsMapName:   {Type: ebpf.Hash, KeySize: 24, ValueSize: 8, MaxEntries: 16},
		oncpu.StacksMapName:   {Type: ebpf.StackTrace, KeySize: 4, ValueSize: 8 * 64, MaxEntries: 16},
		oncpu.RequestsMapName: {Type: ebpf.LRUHash, KeySize: 8, ValueSize: 16, MaxEntries: 16},
		oncpu.LostMapName:     {Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 2},
	}
	coll := &ebpf.Collection{Maps: map[string]*ebpf.Map{}, Programs: map[string]*ebpf.Program{}}
	for name, spec := range specs {
		m, err := ebpf.NewMap(spec)
		if err != nil {
			t.Skipf("cannot create %s (needs privileges): %v", name, err)
		}
		coll.Maps[name] = m
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.PerfEvent,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		t.Skipf("cannot load a perf_event program (needs privileges): %v", err)
	}
	coll.Programs[oncpu.ProgramName] = prog
	t.Cleanup(coll.Close)
	return coll
}

func enabledValue(t *testing.T, coll *ebpf.Collection) uint32 {
	t.Helper()
	var v uint32
	if err := coll.Maps[oncpu.EnabledMapName].Lookup(uint32(0), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestKernelTheTracerStartsDrainsAndStopsTheSampler(t *testing.T) {
	coll := onCPUCollection(t)
	tr := &Tracer{collection: coll}

	cpus, err := tr.StartOnCPUSampler()
	if err != nil || cpus == 0 {
		t.Fatalf("StartOnCPUSampler = %d, %v", cpus, err)
	}
	if enabledValue(t, coll) != 1 {
		t.Error("the sampler runs but the hooks were not switched on")
	}
	if again, err := tr.StartOnCPUSampler(); err != nil || again != cpus {
		t.Errorf("a second start = %d, %v; it must reuse the running sampler", again, err)
	}
	if _, err := tr.DrainOnCPUSamples(); err != nil {
		t.Errorf("DrainOnCPUSamples: %v", err)
	}

	tr.stopOnCPUSampler()
	if tr.onCPUSampler != nil || enabledValue(t, coll) != 0 {
		t.Error("stopping left the sampler attached or the hooks on")
	}
}

func TestKernelASwitchThatCannotBeSetDetachesTheSampler(t *testing.T) {
	coll := onCPUCollection(t)
	wide, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Skipf("cannot create a map: %v", err)
	}
	t.Cleanup(func() { _ = wide.Close() })
	_ = coll.Maps[oncpu.EnabledMapName].Close()
	coll.Maps[oncpu.EnabledMapName] = wide

	tr := &Tracer{collection: coll}
	if _, err := tr.StartOnCPUSampler(); err == nil {
		t.Fatal("the sampler started although its hooks could not be switched on")
	}
	if tr.onCPUSampler != nil {
		t.Error("a sampler whose hooks are off was kept attached")
	}
}

func TestKernelANewTracerKeepsTheTaskRegsSamplerWhereTheKernelHasIt(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	_, kept := tr.collection.Programs[oncpu.TaskRegsProgramName]
	if kept != taskPtRegsAvailable() {
		t.Errorf("task-regs sampler loaded=%v, kernel has bpf_task_pt_regs=%v", kept, taskPtRegsAvailable())
	}
}

func TestKernelTheReadersCarryLiveHTTP2Traffic(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	tr.attachGlobalProtocolProbesOnce()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan *events.Event, 4096)
	if err := tr.Start(ctx, ch); err != nil {
		t.Fatalf("Start: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h2c := new(http.Protocols)
	h2c.SetUnencryptedHTTP2(true)
	srv := &http.Server{Protocols: h2c, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close() })
	client := &http.Client{Transport: &http.Transport{Protocols: h2c}}

	sawH2 := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := client.Get("http://" + lis.Addr().String() + "/x"); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		for drained := false; !drained; {
			select {
			case ev := <-ch:
				if ev.Type == events.EventHTTPResp && ev.TCPState == 2 {
					sawH2 = true
				}
			default:
				drained = true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sawH2 {
		t.Error("no decoded HTTP/2 response reached the event stream")
	}
}
