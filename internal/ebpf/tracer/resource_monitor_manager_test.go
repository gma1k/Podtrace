package tracer

import (
	"context"
	"sync"
	"testing"
)

// fakeMonitor records Stop calls; substitutes resource.ResourceMonitor so the
// manager can be exercised without a live BPF collection.
type fakeMonitor struct {
	mu      sync.Mutex
	stopped bool
}

func (f *fakeMonitor) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
}

func (f *fakeMonitor) SetPodIdentity(string, string) {}

func (f *fakeMonitor) isStopped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopped
}

// activateWithFakes flips the manager active and installs a factory that hands
// out (and records) fakeMonitors, mirroring what activate() does in production
// minus the real ResourceMonitor wiring.
func activateWithFakes(m *resourceMonitorManager) map[string]*fakeMonitor {
	created := map[string]*fakeMonitor{}
	m.mu.Lock()
	m.startMonitor = func(path string, _ CgroupOwner) (resourceMonitorHandle, error) {
		f := &fakeMonitor{}
		created[path] = f
		return f, nil
	}
	m.active = true
	m.reconcileLocked()
	m.mu.Unlock()
	return created
}

func TestResourceMonitorManager_ReconcileBeforeActivateOnlyRecords(t *testing.T) {
	m := newResourceMonitorManager()
	m.reconcile([]string{"/cg/a", "/cg/b"})

	if got := m.runningCount(); got != 0 {
		t.Fatalf("running monitors before activate = %d, want 0", got)
	}

	created := activateWithFakes(m)
	if got := m.runningCount(); got != 2 {
		t.Fatalf("running monitors after activate = %d, want 2", got)
	}
	if len(created) != 2 || created["/cg/a"] == nil || created["/cg/b"] == nil {
		t.Fatalf("expected monitors for /cg/a and /cg/b, got %v", created)
	}
}

func TestResourceMonitorManager_ReconcileAddsAndRemoves(t *testing.T) {
	m := newResourceMonitorManager()

	created := map[string]*fakeMonitor{}
	m.mu.Lock()
	m.startMonitor = func(path string, _ CgroupOwner) (resourceMonitorHandle, error) {
		f := &fakeMonitor{}
		created[path] = f
		return f, nil
	}
	m.active = true
	m.mu.Unlock()

	m.reconcile([]string{"/cg/a", "/cg/b"})
	if got := m.runningCount(); got != 2 {
		t.Fatalf("after add: running = %d, want 2", got)
	}

	bBefore := created["/cg/b"]
	m.reconcile([]string{"/cg/b", "/cg/c"})
	if got := m.runningCount(); got != 2 {
		t.Fatalf("after swap: running = %d, want 2", got)
	}
	if !created["/cg/a"].isStopped() {
		t.Error("monitor for removed cgroup /cg/a was not stopped")
	}
	if created["/cg/b"] != bBefore {
		t.Error("monitor for retained cgroup /cg/b was recreated")
	}
	if created["/cg/b"].isStopped() {
		t.Error("monitor for retained cgroup /cg/b was wrongly stopped")
	}
	if created["/cg/c"] == nil || created["/cg/c"].isStopped() {
		t.Error("monitor for added cgroup /cg/c not started")
	}
}

func TestResourceMonitorManager_StopAll(t *testing.T) {
	m := newResourceMonitorManager()
	m.reconcile([]string{"/cg/a", "/cg/b"})
	created := activateWithFakes(m)

	m.stopAll()

	if got := m.runningCount(); got != 0 {
		t.Fatalf("running after stopAll = %d, want 0", got)
	}
	for path, f := range created {
		if !f.isStopped() {
			t.Errorf("monitor for %s not stopped by stopAll", path)
		}
	}
	if m.active {
		t.Error("manager still active after stopAll")
	}
}

func TestResourceMonitorManager_ActivateRequiresMaps(t *testing.T) {
	m := newResourceMonitorManager()
	m.reconcile([]string{"/cg/a"})
	m.activate(context.Background(), nil, nil, nil, nil)
	if m.active {
		t.Error("manager activated despite nil maps")
	}
	if got := m.runningCount(); got != 0 {
		t.Fatalf("running with nil maps = %d, want 0", got)
	}
}
