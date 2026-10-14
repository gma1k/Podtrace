//go:build bpf_loadtest && linux

package tracer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

const (
	fsWorkerEnv   = "PODTRACE_FS_WORKER"
	fsWorkerFile  = "PODTRACE_FS_WORKER_FILE"
	fsReads       = 100
	fsWrites      = 10
	fsOpens       = 20
	fsOther       = 100
	fsBlock       = 4096
	fsOtherLength = 333
)

func TestKernelFSWorker(t *testing.T) {
	mode := os.Getenv(fsWorkerEnv)
	if mode == "" {
		t.Skip("only runs as the child of the filesystem kernel tests")
	}
	path := os.Getenv(fsWorkerFile)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	block := make([]byte, fsBlock)
	switch mode {
	case "mixed":
		for i := 0; i < fsReads; i++ {
			if _, err := f.ReadAt(block, 0); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < fsWrites; i++ {
			if _, err := f.WriteAt(block, 0); err != nil {
				t.Fatal(err)
			}
		}
		other := make([]byte, fsOtherLength)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		null, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < fsOther; i++ {
			_, _ = w.Write(other)
			_, _ = r.Read(other)
			_, _ = syscall.Write(pair[0], other)
			_, _ = syscall.Read(pair[1], other)
			_, _ = null.Write(other)
		}
		_ = r.Close()
		_ = w.Close()
		_ = syscall.Close(pair[0])
		_ = syscall.Close(pair[1])
		_ = null.Close()
		for i := 0; i < fsOpens; i++ {
			g, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			_ = g.Close()
			for _, notAFile := range []string{"/dev/null", filepath.Dir(path)} {
				h, err := os.Open(notAFile)
				if err != nil {
					t.Fatal(err)
				}
				_ = h.Close()
			}
			if _, err := os.Open(path + ".missing"); err == nil {
				t.Fatal("opened a file that does not exist")
			}
			if _, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
				t.Fatal("exclusively created a file that exists")
			}
		}
	case "reads":
		for i := 0; i < fsReads; i++ {
			if _, err := f.ReadAt(block, 0); err != nil {
				t.Fatal(err)
			}
		}
	case "fsync":
		big := make([]byte, 4<<20)
		for i := 0; i < 5; i++ {
			if _, err := f.WriteAt(big, 0); err != nil {
				t.Fatal(err)
			}
			if err := f.Sync(); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Fdatasync(int(f.Fd())); err != nil {
				t.Fatal(err)
			}
		}
	}
	fmt.Println("done")
}

type fsWorker struct {
	cgroup string
	id     uint64
	file   string
}

func newFSWorker(t *testing.T, name string) fsWorker {
	t.Helper()
	dir := fmt.Sprintf("/sys/fs/cgroup/podtrace-fs-%s-%d", name, os.Getpid())
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Skipf("cannot create a cgroup for the worker: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	tmp, err := os.MkdirTemp("/var/tmp", "podtrace-fs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	file := filepath.Join(tmp, "podtrace-fs-"+name+".dat")
	if err := os.WriteFile(file, make([]byte, fsBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	return fsWorker{cgroup: dir, id: st.Ino, file: file}
}

func (w fsWorker) run(t *testing.T, mode string) {
	t.Helper()
	runInCgroup(t, w.cgroup, "TestKernelFSWorker", fsWorkerEnv+"="+mode, fsWorkerFile+"="+w.file)
}

func runInCgroup(t *testing.T, cgroup, worker string, env ...string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+worker+"$")
	cmd.Env = append(os.Environ(), env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(out)
	if !sc.Scan() || sc.Text() != "ready" {
		_ = cmd.Process.Kill()
		t.Fatalf("worker %s did not start: %q", worker, sc.Text())
	}
	if err := os.WriteFile(cgroup+"/cgroup.procs", []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("move the worker into its cgroup: %v", err)
	}
	if _, err := stdin.Write([]byte("go\n")); err != nil {
		t.Fatal(err)
	}
	for sc.Scan() {
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("worker %s: %v", worker, err)
	}
}

func fsTracer(t *testing.T, mechanism string, targets ...fsWorker) *Tracer {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	if mechanism == "kprobe" {
		orig := tracingProgramsAvailable
		tracingProgramsAvailable = func() bool { return false }
		t.Cleanup(func() { tracingProgramsAvailable = orig })
	}
	tr, err := NewTracer()
	if err != nil {
		t.Skipf("cannot load the podtrace object here: %v", err)
	}
	t.Cleanup(func() { _ = tr.Stop() })
	_, hasFentry := tr.collection.Programs["fentry_vfs_read"]
	if hasFentry != (mechanism == "fentry") {
		t.Fatalf("mechanism %s: fentry programs loaded = %v", mechanism, hasFentry)
	}
	var paths []string
	for _, w := range targets {
		paths = append(paths, w.cgroup)
	}
	if err := tr.SetCgroups(paths); err != nil {
		t.Fatal(err)
	}
	return tr
}

type fsCounts map[events.EventType]kernelagg.Value

func fsRows(rows []kernelagg.Row, cgroup uint64) fsCounts {
	out := fsCounts{}
	for _, r := range rows {
		if r.Key.CgroupID != cgroup {
			continue
		}
		v := out[events.EventType(r.Key.EventType)]
		v.Count += r.Value.Count
		v.SumNS += r.Value.SumNS
		v.Bytes += r.Value.Bytes
		out[events.EventType(r.Key.EventType)] = v
	}
	return out
}

func forEachMechanism(t *testing.T, test func(t *testing.T, mechanism string)) {
	for _, m := range []string{"fentry", "kprobe"} {
		t.Run(m, func(t *testing.T) { test(t, m) })
	}
}

func TestKernelOnlyRegularFileIOIsCounted(t *testing.T) {
	forEachMechanism(t, func(t *testing.T, mechanism string) {
		w := newFSWorker(t, "mixed-"+mechanism)
		tr := fsTracer(t, mechanism, w)
		if err := tr.SetKernelAggregationMode(kernelagg.ModeBypass); err != nil {
			t.Fatal(err)
		}
		w.run(t, "mixed")
		rows, err := tr.DrainKernelMetrics()
		if err != nil {
			t.Fatal(err)
		}
		got := fsRows(rows, w.id)

		if r := got[events.EventRead]; r.Count != fsReads || r.Bytes != fsReads*fsBlock {
			t.Errorf("reads = %d of %d bytes, want %d of %d: only the regular file's reads count, "+
				"not the pipe's or the socket's", r.Count, r.Bytes, fsReads, fsReads*fsBlock)
		}
		if wr := got[events.EventWrite]; wr.Count != fsWrites || wr.Bytes != fsWrites*fsBlock {
			t.Errorf("writes = %d of %d bytes, want %d of %d: writes to a pipe, a socket and "+
				"/dev/null are not filesystem I/O", wr.Count, wr.Bytes, fsWrites, fsWrites*fsBlock)
		}
		if c := got[events.EventClose]; c.Count != fsOpens {
			t.Errorf("closes = %d, want the %d of the regular file; closing pipes, sockets and "+
				"/dev/null is not a filesystem close", c.Count, fsOpens)
		}
		if o := got[events.EventOpen]; o.Count != 3*fsOpens {
			t.Errorf("opens = %d, want %d: the regular file's %d and the 2x%d that failed, not those of "+
				"/dev/null or a directory", o.Count, 3*fsOpens, fsOpens, fsOpens)
		}
		var failedOpens uint64
		for _, r := range rows {
			if r.Key.CgroupID == w.id && events.EventType(r.Key.EventType) == events.EventOpen &&
				kernelagg.DecodeVariant(r.Key.Variant).IsError {
				failedOpens += r.Value.Count
			}
		}
		if failedOpens != fsOpens {
			t.Errorf("failed opens = %d, want the %d that found the file already there: open returns an int, "+
				"so its error is in the low 32 bits, and one that found no file is not an error", failedOpens, fsOpens)
		}
	})
}

func TestKernelFastOperationsAreCountedWithoutKernelAggregation(t *testing.T) {
	forEachMechanism(t, func(t *testing.T, mechanism string) {
		w := newFSWorker(t, "reads-"+mechanism)
		tr := fsTracer(t, mechanism, w)
		if err := tr.CountFastFilesystemOps(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ch := make(chan *events.Event, 1<<14)
		if err := tr.Start(ctx, ch); err != nil {
			t.Fatal(err)
		}
		if err := tr.SetCgroups([]string{w.cgroup}); err != nil {
			t.Fatal(err)
		}
		w.run(t, "reads")
		time.Sleep(300 * time.Millisecond)

		slow := 0
		for done := false; !done; {
			select {
			case ev := <-ch:
				if ev.Type == events.EventRead && ev.CgroupID == w.id {
					slow++
				}
			default:
				done = true
			}
		}
		rows, err := tr.DrainFastFilesystemOps()
		if err != nil {
			t.Fatal(err)
		}
		fast := fsRows(rows, w.id)[events.EventRead]
		if int(fast.Count)+slow != fsReads {
			t.Errorf("%d fast reads counted in the kernel + %d read events = %d, want every one of %d",
				fast.Count, slow, int(fast.Count)+slow, fsReads)
		}
		if fast.Count > 0 && fast.SumNS/fast.Count >= 1_000_000 {
			t.Errorf("fast reads average %dns, but only operations under 1ms are counted there", fast.SumNS/fast.Count)
		}
	})
}

func TestKernelAnUntargetedCgroupIsNotTraced(t *testing.T) {
	forEachMechanism(t, func(t *testing.T, mechanism string) {
		targeted := newFSWorker(t, "targeted-"+mechanism)
		other := newFSWorker(t, "other-"+mechanism)
		tr := fsTracer(t, mechanism, targeted)
		if err := tr.SetKernelAggregationMode(kernelagg.ModeBypass); err != nil {
			t.Fatal(err)
		}
		other.run(t, "reads")
		targeted.run(t, "reads")
		rows, err := tr.DrainKernelMetrics()
		if err != nil {
			t.Fatal(err)
		}
		if n := len(fsRows(rows, other.id)); n != 0 {
			t.Errorf("an untargeted cgroup produced %d filesystem rows", n)
		}
		if r := fsRows(rows, targeted.id)[events.EventRead]; r.Count != fsReads {
			t.Errorf("the targeted cgroup's reads = %d, want %d", r.Count, fsReads)
		}
	})
}

func TestKernelASlowOperationBecomesAnEventWithItsFile(t *testing.T) {
	forEachMechanism(t, func(t *testing.T, mechanism string) {
		w := newFSWorker(t, "fsync-"+mechanism)
		tr := fsTracer(t, mechanism, w)
		if err := tr.SetKernelAggregationMode(kernelagg.ModeOn); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ch := make(chan *events.Event, 1<<14)
		if err := tr.Start(ctx, ch); err != nil {
			t.Fatal(err)
		}
		if err := tr.SetCgroups([]string{w.cgroup}); err != nil {
			t.Fatal(err)
		}
		if err := tr.SetKernelAggregationMode(kernelagg.ModeOn); err != nil {
			t.Fatal(err)
		}
		w.run(t, "fsync")
		time.Sleep(300 * time.Millisecond)
		var fsync *events.Event
		for done := false; !done; {
			select {
			case ev := <-ch:
				if ev.Type == events.EventFsync && ev.CgroupID == w.id && fsync == nil {
					fsync = ev
				}
			default:
				done = true
			}
		}
		rows, err := tr.DrainKernelMetrics()
		if err != nil {
			t.Fatal(err)
		}
		if n := fsRows(rows, w.id)[events.EventFsync].Count; n != 10 {
			t.Errorf("%d fsyncs counted, want the worker's 5 fsync and 5 fdatasync calls", n)
		}
		if fsync == nil {
			t.Skip("no fsync took 1ms or longer on this disk")
		}
		if fsync.Target != filepath.Base(w.file) {
			t.Errorf("the fsync event names %q, want the file %q", fsync.Target, filepath.Base(w.file))
		}
		if !fsync.KernelAggregated {
			t.Error("an event kernel aggregation already counted is not marked, so the sink would count it twice")
		}
		if fsync.LatencyNS < 1_000_000 {
			t.Errorf("an fsync event of %dns; only operations of 1ms or more become events", fsync.LatencyNS)
		}
	})
}

func TestKernelAFastOpsSwitchThatCannotBeSetIsReported(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock: %v", err)
	}
	wide, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Skipf("cannot create a map: %v", err)
	}
	t.Cleanup(func() { _ = wide.Close() })
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{fsFastOpsEnabledMapName: wide}}}
	if err := tr.CountFastFilesystemOps(); err == nil {
		t.Error("CountFastFilesystemOps reported a switch the map refused as set")
	}
}
