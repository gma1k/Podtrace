package tracer

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gma1k/podtrace/internal/events"
)

func TestResourceMonitorManager_ActivateAssignsFactoryAndActivates(t *testing.T) {
	m := newResourceMonitorManager()
	limits := &ebpf.Map{}
	alerts := &ebpf.Map{}

	m.activate(context.Background(), nil, limits, alerts, nil)

	if !m.active {
		t.Error("manager not active after activate with non-nil maps")
	}
	m.mu.Lock()
	factorySet := m.startMonitor != nil
	m.mu.Unlock()
	if !factorySet {
		t.Error("activate did not install a startMonitor factory")
	}
	if got := m.runningCount(); got != 0 {
		t.Fatalf("running monitors with empty desired set = %d, want 0", got)
	}
}

func TestResourceMonitorManager_ReconcileSkipsFailedMonitors(t *testing.T) {
	m := newResourceMonitorManager()
	m.mu.Lock()
	m.startMonitor = func(path string, _ CgroupOwner) (resourceMonitorHandle, error) {
		if path == "/cg/bad" {
			return nil, fmt.Errorf("cannot start monitor for %s", path)
		}
		return &fakeMonitor{}, nil
	}
	m.active = true
	m.mu.Unlock()

	m.reconcile([]string{"/cg/good", "/cg/bad"})

	if got := m.runningCount(); got != 1 {
		t.Fatalf("running monitors = %d, want 1 (failed monitor must be skipped)", got)
	}
}

func TestResourceMonitorManager_ActivateStartsRealMonitorsOnlyForReadableCgroups(t *testing.T) {
	m := newResourceMonitorManager()
	existing := t.TempDir()
	missing := existing + "/gone"
	m.setOwners(map[string]CgroupOwner{existing: {PodName: "web-0", Namespace: "shop"}})
	m.reconcile([]string{existing, missing})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.activate(ctx, make(chan *events.Event, 1), &ebpf.Map{}, &ebpf.Map{}, &ebpf.Map{})
	defer m.stopAll()

	if got := m.runningCount(); got != 1 {
		t.Fatalf("running monitors = %d, want 1 (the unreadable cgroup must be skipped)", got)
	}
	m.mu.Lock()
	_, started := m.running[existing]
	_, startedMissing := m.running[missing]
	m.mu.Unlock()
	if !started || startedMissing {
		t.Fatalf("running = existing:%v missing:%v, want only the existing cgroup", started, startedMissing)
	}
}
