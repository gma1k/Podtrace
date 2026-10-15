package tracer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/procfs"
)

func swapProcCgroupID(t *testing.T, fn func(uint32) (uint64, bool)) {
	t.Helper()
	orig := procCgroupID
	procCgroupID = fn
	t.Cleanup(func() { procCgroupID = orig })
}

func TestProcFallbackRefusesAPidFromAnotherCgroup(t *testing.T) {
	swapProcCgroupID(t, func(uint32) (uint64, bool) { return 99, true })
	tracer := newAttributionTestTracer()
	ev := &events.Event{PID: uint32(os.Getpid()), CgroupID: 7, Type: events.EventDNS}
	if source := tracer.attributeProcessName(ev); source != attributionSourceNone {
		t.Fatalf("source = %q, want none", source)
	}
	if ev.ProcessName != "" {
		t.Fatalf("event named after a process in another cgroup: %q", ev.ProcessName)
	}
}

func TestProcFallbackAcceptsAPidFromTheEventCgroup(t *testing.T) {
	swapProcCgroupID(t, func(uint32) (uint64, bool) { return 7, true })
	tracer := newAttributionTestTracer()
	ev := &events.Event{PID: uint32(os.Getpid()), CgroupID: 7, Type: events.EventDNS}
	if source := tracer.attributeProcessName(ev); source != attributionSourceProcFallback {
		t.Fatalf("source = %q, want proc_fallback", source)
	}
}

func TestProcFallbackKeptWhenTheCgroupIsUnverifiable(t *testing.T) {
	swapProcCgroupID(t, func(uint32) (uint64, bool) { return 0, false })
	tracer := newAttributionTestTracer()
	ev := &events.Event{PID: uint32(os.Getpid()), CgroupID: 7, Type: events.EventDNS}
	if source := tracer.attributeProcessName(ev); source != attributionSourceProcFallback {
		t.Fatalf("source = %q, want proc_fallback", source)
	}
}

func fakeProcCgroup(t *testing.T, pid, content string) (cgroupRoot string) {
	t.Helper()
	procRoot := t.TempDir()
	cgroupRoot = t.TempDir()
	if content != "" {
		dir := filepath.Join(procRoot, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	previousProc, previousCgroup := config.ProcBasePath, config.CgroupBasePath
	config.SetProcBasePath(procRoot)
	config.SetCgroupBasePath(cgroupRoot)
	procfs.ResetForTesting()
	t.Cleanup(func() {
		config.SetProcBasePath(previousProc)
		config.SetCgroupBasePath(previousCgroup)
		procfs.ResetForTesting()
	})
	return cgroupRoot
}

func TestProcCgroupIDResolvesTheCgroupV2Directory(t *testing.T) {
	root := fakeProcCgroup(t, "4242", "0::/kubepods.slice/pod-a\n")
	dir := filepath.Join(root, "kubepods.slice", "pod-a")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	want, err := getCgroupIDFromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := procCgroupID(4242)
	if !ok || got != want {
		t.Fatalf("procCgroupID = %d, %v; want %d", got, ok, want)
	}
}

func TestProcCgroupIDUnverifiable(t *testing.T) {
	cases := map[string]string{
		"no process":            "",
		"cgroup v1 only":        "4:memory:/kubepods/pod-a\n",
		"outside the namespace": "0::/../../kubepods.slice/pod-a\n",
		"directory gone":        "0::/kubepods.slice/missing\n",
		"relative path":         "0::kubepods.slice\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			fakeProcCgroup(t, "4243", content)
			if id, ok := procCgroupID(4243); ok {
				t.Fatalf("procCgroupID = %d, want unverifiable", id)
			}
		})
	}
}

func TestPidInEventCgroupSkipsEventsWithoutACgroup(t *testing.T) {
	swapProcCgroupID(t, func(uint32) (uint64, bool) {
		t.Fatal("cgroup looked up for an event without one")
		return 0, false
	})
	if !pidInEventCgroup(&events.Event{PID: 1}) {
		t.Fatal("event without a cgroup refused")
	}
}
