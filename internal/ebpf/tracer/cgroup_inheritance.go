package tracer

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

const (
	targetParentCgroupMapName = "target_parent_cgroup_ids"
	inheritedCgroupMapName    = "inherited_cgroup_ids"
	cgroupMkdirProgramName    = "raw_tracepoint_cgroup_mkdir"
)

// podUIDPattern matches a pod-level cgroup directory name (cgroupfs
// "pod<uid>" or systemd "...-pod<uid>.slice"), never a broader slice such as
// "kubepods" or "kubepods-besteffort.slice".
var podUIDPattern = regexp.MustCompile(`pod[0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12}`)

// podCgroupParents returns the pod cgroups a container restart creates new
// container cgroups under: the parent of each targeted container cgroup, or
// the path itself when the target is a pod cgroup.
func podCgroupParents(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	var out []string
	add := func(p string) {
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range paths {
		switch {
		case podUIDPattern.MatchString(filepath.Base(p)):
			add(p)
		case podUIDPattern.MatchString(filepath.Base(filepath.Dir(p))):
			add(filepath.Dir(p))
		}
	}
	return out
}

// syncCgroupInheritance tells the kernel which pod cgroups to watch, so a
// container that restarts is traced from its first instruction instead of
// from whenever the pod watch reports it, which a container that dies within
// a second never reaches.
func (t *Tracer) syncCgroupInheritance(paths []string) {
	if t.collection == nil {
		return
	}
	parents := t.collection.Maps[targetParentCgroupMapName]
	inherited := t.collection.Maps[inheritedCgroupMapName]
	if parents == nil || inherited == nil {
		return
	}
	want := make(map[uint64]struct{})
	for _, p := range podCgroupParents(paths) {
		if id, err := getCgroupIDFromPath(p); err == nil && id != 0 {
			want[id] = struct{}{}
		}
	}
	if err := syncParentCgroups(parents, inherited, want); err != nil {
		logger.Warn("Restarted containers will be traced only once the pod watch reports them", zap.Error(err))
		return
	}
	t.inheritedCache.Range(func(k, v any) bool {
		if _, ok := want[v.(uint64)]; !ok {
			t.inheritedCache.Delete(k)
		}
		return true
	})
	t.ensureCgroupMkdirHook()
}

func syncParentCgroups(parents, inherited *ebpf.Map, want map[uint64]struct{}) error {
	var key uint64
	var flag uint8
	var stale []uint64
	iter := parents.Iterate()
	for iter.Next(&key, &flag) {
		if _, ok := want[key]; !ok {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", targetParentCgroupMapName, err)
	}
	for _, k := range stale {
		if err := parents.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	one := uint8(1)
	for id := range want {
		if err := parents.Update(&id, &one, ebpf.UpdateAny); err != nil {
			return err
		}
	}

	var child, parent uint64
	var orphans []uint64
	citer := inherited.Iterate()
	for citer.Next(&child, &parent) {
		if _, ok := want[parent]; !ok {
			orphans = append(orphans, child)
		}
	}
	if err := citer.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", inheritedCgroupMapName, err)
	}
	for _, k := range orphans {
		if err := inherited.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func (t *Tracer) ensureCgroupMkdirHook() {
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	if t.cgroupMkdirAttached || t.probesClosed {
		return
	}
	prog := t.collection.Programs[cgroupMkdirProgramName]
	if prog == nil {
		return
	}
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "cgroup_mkdir", Program: prog})
	if err != nil {
		logger.Warn("Restarted containers will be traced only once the pod watch reports them", zap.Error(err))
		return
	}
	t.links = append(t.links, l)
	t.cgroupMkdirAttached = true
}

// InheritedCgroupParent reports the targeted pod cgroup a container cgroup
// was created under after targeting began, so its events are kept and
// attributed to that pod before the pod watch catches up.
func (t *Tracer) InheritedCgroupParent(id uint64) (uint64, bool) {
	if t == nil || id == 0 {
		return 0, false
	}
	if v, ok := t.inheritedCache.Load(id); ok {
		return v.(uint64), true
	}
	if t.collection == nil {
		return 0, false
	}
	m := t.collection.Maps[inheritedCgroupMapName]
	if m == nil {
		return 0, false
	}
	var parent uint64
	if err := m.Lookup(&id, &parent); err != nil || parent == 0 {
		return 0, false
	}
	t.inheritedCache.Store(id, parent)
	return parent, true
}
