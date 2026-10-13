package agent

import (
	"sync"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/podworkload"
)

// PodEnricher maps kernel cgroup inode IDs to a frozen, six-attribute
// Kubernetes metadata bundle used to enrich exported spans.
type PodEnricher struct {
	mu       sync.RWMutex
	byCgroup map[uint64]events.K8sMetadata
	parentOf func(uint64) (uint64, bool)

	hits          atomic.Int64
	misses        atomic.Int64
	snapshots     atomic.Int64
	ownerResolved atomic.Int64
	ownerOrphaned atomic.Int64
}

// NewPodEnricher returns an empty enricher.
func NewPodEnricher() *PodEnricher {
	return &PodEnricher{
		byCgroup: map[uint64]events.K8sMetadata{},
	}
}

// Lookup returns the metadata for cgroupID and whether it was found.
func (e *PodEnricher) Lookup(cgroupID uint64) (events.K8sMetadata, bool) {
	if e == nil {
		return events.K8sMetadata{}, false
	}
	e.mu.RLock()
	meta, ok := e.byCgroup[cgroupID]
	parentOf := e.parentOf
	if !ok && parentOf != nil {
		if parent, inherited := parentOf(cgroupID); inherited {
			meta, ok = e.byCgroup[parent]
		}
	}
	e.mu.RUnlock()
	if ok {
		e.hits.Add(1)
	} else {
		e.misses.Add(1)
	}
	return meta, ok
}

// FollowRestartedContainers lets Lookup attribute a container cgroup the
// kernel started tracing because it was created under a targeted pod, before
// the next reconcile lists it.
func (e *PodEnricher) FollowRestartedContainers(parentOf func(uint64) (uint64, bool)) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.parentOf = parentOf
	e.mu.Unlock()
}

// PodFor returns the name of a pod of the given workload that this node is
// tracking, and whether one was found.
func (e *PodEnricher) PodFor(namespace, workload string) (string, bool) {
	if e == nil || namespace == "" || workload == "" {
		return "", false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	best := ""
	for _, meta := range e.byCgroup {
		if meta.Namespace != namespace || meta.WorkloadName != workload || meta.PodName == "" {
			continue
		}
		if best == "" || meta.PodName < best {
			best = meta.PodName
		}
	}
	return best, best != ""
}

// Snapshot atomically replaces the cache with metas.
func (e *PodEnricher) Snapshot(entries []PodCgroupEntry) {
	if e == nil {
		return
	}
	next := make(map[uint64]events.K8sMetadata, len(entries))
	seenPods := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Pod == nil {
			continue
		}
		next[entry.CgroupID] = buildK8sMetadata(entry)

		uid := string(entry.Pod.UID)
		if uid == "" {
			continue
		}
		if _, dup := seenPods[uid]; dup {
			continue
		}
		seenPods[uid] = struct{}{}
		if podworkload.ControllerOwnerRef(entry.Pod.OwnerReferences) == nil {
			e.ownerOrphaned.Add(1)
		} else {
			e.ownerResolved.Add(1)
		}
	}
	e.mu.Lock()
	e.byCgroup = next
	e.mu.Unlock()
	e.snapshots.Add(1)
}

// Size returns the number of cached cgroup IDs. Used by the metrics
// refresh path and tests.
func (e *PodEnricher) Size() int {
	if e == nil {
		return 0
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.byCgroup)
}

// EnricherStats is the read-only snapshot the metrics path consumes.
type EnricherStats struct {
	Hits          int64
	Misses        int64
	Snapshots     int64
	OwnerResolved int64
	OwnerOrphaned int64
	CacheSize     int
}

// Stats returns the counters atomically. Safe to call concurrently
// with Lookup and Snapshot.
func (e *PodEnricher) Stats() EnricherStats {
	if e == nil {
		return EnricherStats{}
	}
	return EnricherStats{
		Hits:          e.hits.Load(),
		Misses:        e.misses.Load(),
		Snapshots:     e.snapshots.Load(),
		OwnerResolved: e.ownerResolved.Load(),
		OwnerOrphaned: e.ownerOrphaned.Load(),
		CacheSize:     e.Size(),
	}
}

// enrichBatch stamps each event in batch with its matching
// K8sMetadata.
func enrichBatch(e *PodEnricher, batch []*events.Event) {
	if e == nil {
		return
	}
	var memo map[uint64]*events.K8sMetadata
	for _, ev := range batch {
		if ev == nil || ev.K8s != nil {
			continue
		}
		if memo == nil {
			memo = make(map[uint64]*events.K8sMetadata, 8)
		}
		if cached, ok := memo[ev.CgroupID]; ok {
			ev.K8s = cached
			continue
		}
		meta, found := e.Lookup(ev.CgroupID)
		if !found {
			memo[ev.CgroupID] = nil
			continue
		}
		m := meta
		memo[ev.CgroupID] = &m
		ev.K8s = &m
	}
}

// PodCgroupEntry is the unit of input to PodEnricher.Snapshot.
type PodCgroupEntry struct {
	CgroupID      uint64
	CgroupPath    string
	Pod           *corev1.Pod
	ContainerName string
	ContainerID   string
	ContainerPID  uint32
}

// buildK8sMetadata projects a PodCgroupEntry onto the frozen v1
// metadata schema.
func buildK8sMetadata(entry PodCgroupEntry) events.K8sMetadata {
	pod := entry.Pod
	meta := events.K8sMetadata{
		Namespace:     pod.Namespace,
		PodName:       pod.Name,
		PodUID:        string(pod.UID),
		NodeName:      pod.Spec.NodeName,
		ContainerName: entry.ContainerName,
	}
	kind, name := podworkload.Of(pod)
	meta.WorkloadKind = kind
	meta.WorkloadName = name
	return meta
}
