package main

import (
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf"
	"github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/pkg/tracer"
)

type ownerRecordingTracer struct {
	fakeTracer
	owners       map[string]ebpf.CgroupOwner
	ownersBefore bool
}

func (o *ownerRecordingTracer) SetCgroupOwners(owners map[string]ebpf.CgroupOwner) {
	o.owners = owners
	o.ownersBefore = o.setCgroupsArg == nil
}

func TestEbpfBackendAdapterHandsPodOwnersToTracerBeforeAttaching(t *testing.T) {
	fake := &ownerRecordingTracer{}
	adapter := &ebpfBackendAdapter{tr: fake}

	err := adapter.SetCgroups([]tracer.CgroupTarget{
		{CgroupPath: "/cg/pod-a", PodName: "web-0", Namespace: "shop"},
		{CgroupPath: "/cg/pod-b", PodName: "api-0"},
		{CgroupPath: "", PodName: "ghost", Namespace: "shop"},
	})
	if err != nil {
		t.Fatalf("SetCgroups: %v", err)
	}

	if !fake.ownersBefore {
		t.Error("owners were set after the cgroups, so new monitors start without a pod")
	}
	want := map[string]ebpf.CgroupOwner{"/cg/pod-a": {PodName: "web-0", Namespace: "shop"}}
	if len(fake.owners) != len(want) || fake.owners["/cg/pod-a"] != want["/cg/pod-a"] {
		t.Errorf("owners = %+v, want %+v", fake.owners, want)
	}
}

func TestTargetCgroupOwnersMapsEveryContainerCgroupToItsPod(t *testing.T) {
	infos := []*kubernetes.PodInfo{
		{
			PodName:   "web-0",
			Namespace: "shop",
			Containers: []kubernetes.ContainerTarget{
				{Name: "app", ID: "c1", CgroupPath: "/cg/pod-a/c1"},
				{Name: "sidecar", ID: "c2", CgroupPath: "/cg/pod-a/c2"},
				{Name: "pending", ID: "c3"},
			},
		},
		{PodName: "api-0", Namespace: "billing", ContainerID: "c4", CgroupPath: "/cg/pod-b/c4"},
		{PodName: "nameless-ns", CgroupPath: "/cg/pod-c"},
		nil,
	}

	got := targetCgroupOwners(infos)

	want := map[string]ebpf.CgroupOwner{
		"/cg/pod-a/c1": {PodName: "web-0", Namespace: "shop"},
		"/cg/pod-a/c2": {PodName: "web-0", Namespace: "shop"},
		"/cg/pod-b/c4": {PodName: "api-0", Namespace: "billing"},
	}
	if len(got) != len(want) {
		t.Fatalf("owners = %+v, want %+v", got, want)
	}
	for path, owner := range want {
		if got[path] != owner {
			t.Errorf("owner[%s] = %+v, want %+v", path, got[path], owner)
		}
	}
}

func TestSetTracerCgroupOwnersSkipsTracersWithoutOwnerSupport(t *testing.T) {
	setTracerCgroupOwners(&fakeTracer{}, map[string]ebpf.CgroupOwner{"/cg": {PodName: "p", Namespace: "n"}})

	rec := &ownerRecordingTracer{}
	setTracerCgroupOwners(rec, map[string]ebpf.CgroupOwner{"/cg": {PodName: "p", Namespace: "n"}})
	if rec.owners["/cg"] != (ebpf.CgroupOwner{PodName: "p", Namespace: "n"}) {
		t.Errorf("owners = %+v, want /cg -> n/p", rec.owners)
	}
}
