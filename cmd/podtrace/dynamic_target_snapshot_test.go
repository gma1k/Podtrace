package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func snapshotPod(t *testing.T) (*kubernetes.PodInfo, uint64) {
	t.Helper()
	cgroup := t.TempDir()
	id, err := cgroupIDFromPath(cgroup)
	if err != nil {
		t.Fatalf("cgroupIDFromPath: %v", err)
	}
	return &kubernetes.PodInfo{PodName: "web-1", Namespace: "shop", ContainerID: "c-new", CgroupPath: cgroup}, id
}

func TestApplyDynamicTargetSnapshotRetargetsTracerAndIndex(t *testing.T) {
	pod, id := snapshotPod(t)
	rec := &ownerRecordingTracer{}
	index := newSourcePodIndex(nil)

	applyDynamicTargetSnapshot(rec, index, []*kubernetes.PodInfo{pod})

	if rec.attachArg != pod.CgroupPath || rec.containerIDArg != "c-new" {
		t.Errorf("attached %q with container %q, want %q and c-new", rec.attachArg, rec.containerIDArg, pod.CgroupPath)
	}
	if rec.owners[pod.CgroupPath] != (ebpf.CgroupOwner{PodName: "web-1", Namespace: "shop"}) {
		t.Errorf("owners = %+v, want the cgroup owned by shop/web-1", rec.owners)
	}
	if got := index.Resolve(&events.Event{CgroupID: id}); got == nil || got.PodName != "web-1" {
		t.Errorf("index resolves %+v, want web-1", got)
	}
}

func TestApplyDynamicTargetSnapshotKeepsPreviousTargetsWhenEmpty(t *testing.T) {
	pod, id := snapshotPod(t)
	rec := &ownerRecordingTracer{}
	index := newSourcePodIndex([]*kubernetes.PodInfo{pod})

	applyDynamicTargetSnapshot(rec, index, nil)

	if rec.owners != nil || rec.attachArg != "" || rec.containerIDArg != "" {
		t.Errorf("tracer was retargeted on an empty snapshot: %+v", rec)
	}
	if got := index.Resolve(&events.Event{CgroupID: id}); got == nil {
		t.Error("index dropped the previous targets on an empty snapshot")
	}
}

func TestApplyDynamicTargetSnapshotLeavesIndexWhenAttachFails(t *testing.T) {
	pod, id := snapshotPod(t)
	rec := &ownerRecordingTracer{fakeTracer: fakeTracer{attachErr: errors.New("attach refused")}}
	index := newSourcePodIndex(nil)

	applyDynamicTargetSnapshot(rec, index, []*kubernetes.PodInfo{pod})

	if rec.containerIDArg != "" {
		t.Errorf("container IDs set to %q after a failed attach", rec.containerIDArg)
	}
	if got := index.Resolve(&events.Event{CgroupID: id}); got != nil {
		t.Errorf("index resolves %+v after a failed attach, want nil", got)
	}
}

func TestApplyDynamicTargetSnapshotStillIndexesWhenContainerIDsFail(t *testing.T) {
	pod, id := snapshotPod(t)
	rec := &ownerRecordingTracer{fakeTracer: fakeTracer{containerIDErr: errors.New("uprobe refused")}}
	index := newSourcePodIndex(nil)

	applyDynamicTargetSnapshot(rec, index, []*kubernetes.PodInfo{pod})

	if got := index.Resolve(&events.Event{CgroupID: id}); got == nil || got.PodName != "web-1" {
		t.Errorf("index resolves %+v, want web-1", got)
	}
}

func TestApplyTargetUpdatesAppliesEachSnapshotUntilCancelled(t *testing.T) {
	pod, id := snapshotPod(t)
	rec := &ownerRecordingTracer{}
	index := newSourcePodIndex(nil)
	updates := make(chan []*kubernetes.PodInfo, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		applyTargetUpdates(ctx, updates, rec, index)
		close(done)
	}()

	updates <- []*kubernetes.PodInfo{pod}
	deadline := time.Now().Add(5 * time.Second)
	for index.Resolve(&events.Event{CgroupID: id}) == nil {
		if time.Now().After(deadline) {
			t.Fatal("snapshot was never applied to the source index")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("applyTargetUpdates did not return after cancellation")
	}
	if rec.attachArg != pod.CgroupPath {
		t.Errorf("attached %q, want %q", rec.attachArg, pod.CgroupPath)
	}
}

func TestFollowTargetRegistryIgnoresStaticTargets(t *testing.T) {
	rec := &ownerRecordingTracer{}
	followTargetRegistry(context.Background(), nil, rec, newSourcePodIndex(nil))
	if rec.attachArg != "" || rec.owners != nil {
		t.Errorf("tracer retargeted without a registry: %+v", rec)
	}
}

func TestFollowTargetRegistryStopsWithItsContext(t *testing.T) {
	registry := kubernetes.NewTargetRegistry(fake.NewSimpleClientset(), kubernetes.TargetSelection{AllInNamespace: true, DefaultNamespace: "shop"})
	rec := &ownerRecordingTracer{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	followTargetRegistry(ctx, registry, rec, newSourcePodIndex(nil))

	if rec.attachArg != "" || rec.owners != nil {
		t.Errorf("tracer retargeted without an update: %+v", rec)
	}
}
