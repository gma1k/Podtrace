package tracer_test

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/pkg/tracer"
)

func TestCgroupSnapshotCarriesOwningPod(t *testing.T) {
	backend := &snapshotBackend{mockBackend: &mockBackend{}}
	targets := runEngineWith(t, backend, nil)

	targets <- tracer.TargetSet{
		{PodName: "web-0", Namespace: "shop", CgroupPath: "/cg/a", ContainerID: "a"},
		{PodName: "api-0", Namespace: "billing", CgroupPath: "/cg/b", ContainerID: "b"},
	}
	waitUntil(t, 2*time.Second, func() bool { return len(backend.lastSnapshot()) == 2 })

	want := map[string][2]string{"/cg/a": {"web-0", "shop"}, "/cg/b": {"api-0", "billing"}}
	for _, ct := range backend.lastSnapshot() {
		w, ok := want[ct.CgroupPath]
		if !ok {
			t.Fatalf("unexpected cgroup %q in snapshot", ct.CgroupPath)
		}
		if ct.PodName != w[0] || ct.Namespace != w[1] {
			t.Errorf("snapshot %s = %s/%s, want %s/%s", ct.CgroupPath, ct.Namespace, ct.PodName, w[1], w[0])
		}
	}
}
