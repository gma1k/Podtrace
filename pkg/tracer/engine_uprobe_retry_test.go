package tracer_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/pkg/tracer"
)

type flakyReconcilerBackend struct {
	*mockBackend
	fmu      sync.Mutex
	failures int
	calls    int
	last     []string
}

func (b *flakyReconcilerBackend) SetContainerTargets(targets []tracer.ContainerUprobeTarget) error {
	b.fmu.Lock()
	defer b.fmu.Unlock()
	b.calls++
	b.last = nil
	for _, t := range targets {
		b.last = append(b.last, t.ContainerID)
	}
	if b.failures > 0 {
		b.failures--
		return errors.New("uprobe attach failed")
	}
	return nil
}

func (b *flakyReconcilerBackend) callCount() int {
	b.fmu.Lock()
	defer b.fmu.Unlock()
	return b.calls
}

type flakyPerIDBackend struct {
	*mockBackend
	fmu   sync.Mutex
	fail  map[string]int
	calls map[string]int
}

func (b *flakyPerIDBackend) SetContainerID(id string) error {
	b.fmu.Lock()
	defer b.fmu.Unlock()
	b.calls[id]++
	if b.fail[id] > 0 {
		b.fail[id]--
		return errors.New("uprobe attach failed")
	}
	return nil
}

func (b *flakyPerIDBackend) callsFor(id string) int {
	b.fmu.Lock()
	defer b.fmu.Unlock()
	return b.calls[id]
}

func TestFailedUprobeAttachIsRetriedOnIdenticalTargetSet(t *testing.T) {
	backend := &flakyReconcilerBackend{mockBackend: &mockBackend{}, failures: 1}
	obs := &targetErrObserver{}
	targets := runEngineWith(t, backend, obs)

	set := tracer.TargetSet{{CgroupPath: "/cg/a", ContainerID: "a", ContainerPID: 1}}
	targets <- set
	waitUntil(t, 2*time.Second, func() bool { return backend.callCount() == 1 })

	targets <- set
	waitUntil(t, 2*time.Second, func() bool { return backend.callCount() == 2 })

	targets <- set
	time.Sleep(100 * time.Millisecond)
	if got := backend.callCount(); got != 2 {
		t.Errorf("SetContainerTargets calls = %d, want 2", got)
	}

	backend.mu.Lock()
	setCalls := backend.setCalls
	backend.mu.Unlock()
	if setCalls != 1 {
		t.Errorf("SetCgroups calls = %d, want 1", setCalls)
	}
}

func TestSuccessfulUprobeAttachIsNotRepeated(t *testing.T) {
	backend := &flakyReconcilerBackend{mockBackend: &mockBackend{}}
	targets := runEngineWith(t, backend, nil)

	set := tracer.TargetSet{{CgroupPath: "/cg/a", ContainerID: "a", ContainerPID: 1}}
	targets <- set
	waitUntil(t, 2*time.Second, func() bool { return backend.callCount() == 1 })
	targets <- set
	targets <- set
	time.Sleep(100 * time.Millisecond)
	if got := backend.callCount(); got != 1 {
		t.Errorf("SetContainerTargets calls = %d, want 1", got)
	}
}

func TestFailedUprobeRetryIsDroppedWhenContainerLeaves(t *testing.T) {
	backend := &flakyReconcilerBackend{mockBackend: &mockBackend{}, failures: 1}
	targets := runEngineWith(t, backend, nil)

	targets <- tracer.TargetSet{{CgroupPath: "/cg/a", ContainerID: "a", ContainerPID: 1}}
	waitUntil(t, 2*time.Second, func() bool { return backend.callCount() == 1 })

	other := tracer.TargetSet{{CgroupPath: "/cg/b", ContainerID: "b", ContainerPID: 2}}
	targets <- other
	waitUntil(t, 2*time.Second, func() bool { return backend.callCount() == 2 })
	targets <- other
	time.Sleep(100 * time.Millisecond)
	if got := backend.callCount(); got != 2 {
		t.Errorf("SetContainerTargets calls = %d, want 2", got)
	}
}

func TestPerIDFallbackRetriesOnlyAfterAFailure(t *testing.T) {
	backend := &flakyPerIDBackend{
		mockBackend: &mockBackend{},
		fail:        map[string]int{"bad": 1},
		calls:       map[string]int{},
	}
	targets := runEngineWith(t, backend, nil)

	set := tracer.TargetSet{
		{CgroupPath: "/cg/good", ContainerID: "good"},
		{CgroupPath: "/cg/bad", ContainerID: "bad"},
	}
	targets <- set
	waitUntil(t, 2*time.Second, func() bool { return backend.callsFor("bad") == 1 })
	targets <- set
	waitUntil(t, 2*time.Second, func() bool { return backend.callsFor("bad") == 2 })
	targets <- set
	time.Sleep(100 * time.Millisecond)
	if got := backend.callsFor("bad"); got != 2 {
		t.Errorf("bad attach calls = %d, want 2", got)
	}
}
