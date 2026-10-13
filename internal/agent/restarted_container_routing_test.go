package agent

import (
	"context"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

const (
	podCgroup       = uint64(500)
	oldContainer    = uint64(501)
	restarted       = uint64(777)
	otherPodCgroup  = uint64(600)
	otherRestarted  = uint64(888)
	unrelatedCgroup = uint64(999)
)

func inheritedParents(id uint64) (uint64, bool) {
	switch id {
	case restarted:
		return podCgroup, true
	case otherRestarted:
		return otherPodCgroup, true
	}
	return 0, false
}

func TestMatchRuleFollowsAContainerRestartedUnderTheCRsPod(t *testing.T) {
	rule := mkRule("ns", "pt", []uint64{podCgroup, oldContainer}, nil, &recExp{})
	cases := []struct {
		name     string
		cgroup   uint64
		parentOf func(uint64) (uint64, bool)
		want     bool
	}{
		{"listed container", oldContainer, inheritedParents, true},
		{"restarted under the CR's pod", restarted, inheritedParents, true},
		{"restarted under another pod", otherRestarted, inheritedParents, false},
		{"unrelated cgroup", unrelatedCgroup, inheritedParents, false},
		{"restarted, but no resolver", restarted, nil, false},
	}
	for _, tc := range cases {
		if got := matchRule(&rule, &events.Event{CgroupID: tc.cgroup}, tc.parentOf); got != tc.want {
			t.Errorf("%s: matchRule = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestMatchRuleStillAppliesFiltersToARestartedContainer(t *testing.T) {
	rule := mkRule("ns", "pt", []uint64{podCgroup}, []events.EventType{events.EventDNS}, &recExp{})
	if matchRule(&rule, &events.Event{CgroupID: restarted, Type: events.EventOOMKill}, inheritedParents) {
		t.Error("the CR's filters must still apply to a restarted container's events")
	}
	if !matchRule(&rule, &events.Event{CgroupID: restarted, Type: events.EventDNS}, inheritedParents) {
		t.Error("an allowed event type from a restarted container must match")
	}
}

func TestEnricherAttributesARestartedContainerToItsPod(t *testing.T) {
	e := NewPodEnricher()
	pod := newPodWithOwner("ns", "oomer", "u1", "n", "Deployment", "oomer", "oomer-6c5")
	e.Snapshot([]PodCgroupEntry{{CgroupID: podCgroup, Pod: pod}, {CgroupID: oldContainer, Pod: pod, ContainerName: "stress"}})

	if _, ok := e.Lookup(restarted); ok {
		t.Fatal("without the tracer's view an unknown cgroup must stay unattributed")
	}
	e.FollowRestartedContainers(inheritedParents)
	meta, ok := e.Lookup(restarted)
	if !ok || meta.PodName != "oomer" || meta.PodUID != "u1" {
		t.Fatalf("restarted container resolved to %+v, %v; want pod oomer", meta, ok)
	}
	if meta.ContainerName != "" {
		t.Errorf("a restarted container must not inherit another container's name: %q", meta.ContainerName)
	}
	if _, ok := e.Lookup(otherRestarted); ok {
		t.Error("a container under an untracked pod was attributed")
	}
	var none *PodEnricher
	none.FollowRestartedContainers(inheritedParents)
}

func TestRouterDeliversARestartedContainersOOMKillWithItsPod(t *testing.T) {
	exp := &recExp{name: "sink"}
	enricher := NewPodEnricher()
	pod := newPodWithOwner("ns", "oomer", "u1", "n", "Deployment", "oomer", "oomer-6c5")
	enricher.Snapshot([]PodCgroupEntry{{CgroupID: podCgroup, Pod: pod}})
	r := NewRouter(nil).WithEnricher(enricher)
	r.Publish([]CRRule{mkRule("ns", "pt", []uint64{podCgroup, oldContainer}, nil, exp)})

	batch := func() []*events.Event {
		return []*events.Event{{CgroupID: restarted, Type: events.EventOOMKill}}
	}
	if err := r.Export(context.Background(), batch()); err != nil {
		t.Fatal(err)
	}
	if exp.count() != 0 {
		t.Fatal("before the tracer's view is wired the router has no way to know the cgroup")
	}

	r.FollowRestartedContainers(inheritedParents)
	enricher.FollowRestartedContainers(inheritedParents)
	if err := r.Export(context.Background(), batch()); err != nil {
		t.Fatal(err)
	}
	if exp.count() != 1 {
		t.Fatalf("exporter got %d events, want the restarted container's OOM kill", exp.count())
	}
	if got := exp.events[0].K8s; got == nil || got.PodName != "oomer" {
		t.Errorf("the OOM kill reached the exporter without its pod: %+v", got)
	}
}

type inheritingBackend struct{ *NoopBackend }

func (inheritingBackend) InheritedCgroupParent(id uint64) (uint64, bool) { return inheritedParents(id) }

func TestFollowRestartedContainersWiresTheBackendsRecord(t *testing.T) {
	router := NewRouter(nil)
	enricher := NewPodEnricher()
	followRestartedContainers(NewNoopBackend(), router, enricher)
	if router.parentOf != nil || enricher.parentOf != nil {
		t.Fatal("a backend without the record must leave both without a resolver")
	}

	followRestartedContainers(inheritingBackend{NewNoopBackend()}, router, enricher)
	rule := mkRule("ns", "pt", []uint64{podCgroup}, nil, &recExp{})
	if !matchRule(&rule, &events.Event{CgroupID: restarted}, router.parentOf) {
		t.Error("the router did not get the backend's record")
	}
	if p, ok := enricher.parentOf(restarted); !ok || p != podCgroup {
		t.Error("the enricher did not get the backend's record")
	}
}
