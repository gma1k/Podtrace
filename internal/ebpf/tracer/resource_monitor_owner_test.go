package tracer

import (
	"sync"
	"testing"
)

type identityMonitor struct {
	mu        sync.Mutex
	podName   string
	namespace string
}

func (m *identityMonitor) Stop() {}

func (m *identityMonitor) SetPodIdentity(podName, namespace string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.podName = podName
	m.namespace = namespace
}

func (m *identityMonitor) identity() CgroupOwner {
	m.mu.Lock()
	defer m.mu.Unlock()
	return CgroupOwner{PodName: m.podName, Namespace: m.namespace}
}

func activateWithIdentityMonitors(m *resourceMonitorManager) map[string]*identityMonitor {
	created := map[string]*identityMonitor{}
	m.mu.Lock()
	m.startMonitor = func(path string, owner CgroupOwner) (resourceMonitorHandle, error) {
		mon := &identityMonitor{}
		mon.SetPodIdentity(owner.PodName, owner.Namespace)
		created[path] = mon
		return mon, nil
	}
	m.active = true
	m.mu.Unlock()
	return created
}

func TestResourceMonitorManagerStartsMonitorsWithOwningPod(t *testing.T) {
	m := newResourceMonitorManager()
	created := activateWithIdentityMonitors(m)
	m.setOwners(map[string]CgroupOwner{
		"/sys/fs/cgroup/kubepods/pod-a":        {PodName: "web-0", Namespace: "shop"},
		"/sys/fs/cgroup/kubepods/pod-b/ctr-b1": {PodName: "api-0", Namespace: "billing"},
	})

	m.reconcile([]string{
		"/sys/fs/cgroup/kubepods/pod-a/container",
		"/sys/fs/cgroup/kubepods/pod-b/ctr-b1",
		"/sys/fs/cgroup/kubepods/pod-c",
	})

	want := map[string]CgroupOwner{
		"/sys/fs/cgroup/kubepods/pod-a/container": {PodName: "web-0", Namespace: "shop"},
		"/sys/fs/cgroup/kubepods/pod-b/ctr-b1":    {PodName: "api-0", Namespace: "billing"},
		"/sys/fs/cgroup/kubepods/pod-c":           {},
	}
	for path, owner := range want {
		mon := created[path]
		if mon == nil {
			t.Fatalf("no monitor started for %s", path)
		}
		if got := mon.identity(); got != owner {
			t.Errorf("monitor %s identity = %+v, want %+v", path, got, owner)
		}
	}
}

func TestResourceMonitorManagerRelabelsRunningMonitorsOnOwnerChange(t *testing.T) {
	m := newResourceMonitorManager()
	created := activateWithIdentityMonitors(m)
	m.reconcile([]string{"/cg/pod-a"})

	mon := created["/cg/pod-a"]
	if got := mon.identity(); got != (CgroupOwner{}) {
		t.Fatalf("identity before owners known = %+v, want empty", got)
	}

	m.setOwners(map[string]CgroupOwner{"/cg/pod-a": {PodName: "web-0", Namespace: "shop"}})
	if got := mon.identity(); got != (CgroupOwner{PodName: "web-0", Namespace: "shop"}) {
		t.Errorf("identity after setOwners = %+v, want shop/web-0", got)
	}
	if created["/cg/pod-a"] != mon {
		t.Error("setOwners restarted a running monitor")
	}

	m.setOwners(nil)
	if got := mon.identity(); got != (CgroupOwner{}) {
		t.Errorf("identity after owner removed = %+v, want empty", got)
	}
}

func TestResourceMonitorManagerIgnoresIncompleteOwners(t *testing.T) {
	m := newResourceMonitorManager()
	created := activateWithIdentityMonitors(m)
	m.setOwners(map[string]CgroupOwner{
		"/cg/pod-a": {PodName: "web-0"},
		"/cg/pod-b": {Namespace: "shop"},
		"":          {PodName: "x", Namespace: "y"},
	})

	m.reconcile([]string{"/cg/pod-a", "/cg/pod-b"})

	for _, path := range []string{"/cg/pod-a", "/cg/pod-b"} {
		if got := created[path].identity(); got != (CgroupOwner{}) {
			t.Errorf("monitor %s identity = %+v, want empty for an incomplete owner", path, got)
		}
	}
}

func TestTracerSetCgroupOwnersReachesResourceMonitors(t *testing.T) {
	tr := &Tracer{resourceMgr: newResourceMonitorManager()}
	created := activateWithIdentityMonitors(tr.resourceMgr)
	tr.SetCgroupOwners(map[string]CgroupOwner{"/cg/pod-a": {PodName: "web-0", Namespace: "shop"}})

	tr.resourceMgr.reconcile([]string{"/cg/pod-a"})

	if got := created["/cg/pod-a"].identity(); got != (CgroupOwner{PodName: "web-0", Namespace: "shop"}) {
		t.Errorf("identity = %+v, want shop/web-0", got)
	}

	(&Tracer{}).SetCgroupOwners(map[string]CgroupOwner{"/cg/pod-a": {PodName: "web-0", Namespace: "shop"}})
}
