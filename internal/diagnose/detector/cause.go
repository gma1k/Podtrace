package detector

import "sort"

// Which active issue explains which.
//
// Two issues are linked only when the table below says one can cause the
// other and both are active at the same time. Activation order is not
// consulted: every rule holds for the same time, so which of two co-active
// issues activated first is mostly which evaluation saw it first.
type IssueRef struct {
	ID        ID     `json:"id"`
	Namespace string `json:"namespace"`
	Workload  string `json:"workload"`
}

// Ref is the issue's workload-level identity.
func (i Issue) Ref() IssueRef {
	return IssueRef{ID: i.ID, Namespace: i.Subject.Namespace, Workload: i.Subject.Workload}
}

// SameWorkload reports whether two references share a workload.
func (r IssueRef) SameWorkload(o IssueRef) bool {
	return r.Namespace == o.Namespace && r.Workload == o.Workload
}

func (r IssueRef) String() string {
	return string(r.ID) + " on " + r.Namespace + "/" + r.Workload
}

// Cause is a likely root cause of an issue. Via lists the issues between the
// symptom and the root, nearest the symptom first.
type Cause struct {
	IssueRef
	Via []IssueRef `json:"via,omitempty"`
}

func (c Cause) String() string {
	s := c.IssueRef.String()
	for i := len(c.Via) - 1; i >= 0; i-- {
		s += ", through " + c.Via[i].String()
	}
	return s
}

// LocalCauses lists, per issue, the issues on the same workload that can
// explain it. Every pair is a mechanism, not a coincidence:
//
//   - requests wait on a saturated pool, a slow acquire, a starved CPU, a
//     saturated resource, slow name lookups, slow file I/O or a slow network;
//   - requests fail when names do not resolve, handshakes fail, connections
//     are refused, or the pool has no connection to hand out;
//   - acquiring a connection is slow because the pool is saturated.
var LocalCauses = map[ID][]ID{
	IDL7LatencyDegraded: {
		IDDBPoolSaturated,
		IDDBAcquireSlow,
		IDCPUContention,
		IDResourceSaturation,
		IDDNSSlowLookupRate,
		IDFSSlowOperations,
		IDRTTSpikeRate,
	},
	IDL7ErrorRate: {
		IDDNSFailureRate,
		IDTLSHandshakeFailureRate,
		IDConnectionFailureRate,
		IDDBPoolSaturated,
	},
	IDDBAcquireSlow: {
		IDDBPoolSaturated,
	},
}

var DependencyCauses = map[ID][]ID{
	IDL7LatencyDegraded: {IDL7LatencyDegraded},
	IDL7ErrorRate:       {IDL7ErrorRate},
}

const maxCauseDepth = 6

// RootCauses returns, for every active issue that something explains, its
// likely root causes.
func RootCauses(active []IssueRef, dependsOn func(namespace, workload string) []IssueRef) map[IssueRef][]Cause {
	set := map[IssueRef]bool{}
	byWorkload := map[[2]string][]IssueRef{}
	for _, ref := range active {
		if set[ref] {
			continue
		}
		set[ref] = true
		key := [2]string{ref.Namespace, ref.Workload}
		byWorkload[key] = append(byWorkload[key], ref)
	}

	direct := func(s IssueRef) []IssueRef {
		var out []IssueRef
		for _, id := range LocalCauses[s.ID] {
			c := IssueRef{ID: id, Namespace: s.Namespace, Workload: s.Workload}
			if set[c] {
				out = append(out, c)
			}
		}
		if dependsOn != nil {
			for _, dep := range dependsOn(s.Namespace, s.Workload) {
				if dep.SameWorkload(s) {
					continue
				}
				for _, id := range DependencyCauses[s.ID] {
					c := IssueRef{ID: id, Namespace: dep.Namespace, Workload: dep.Workload}
					if set[c] {
						out = append(out, c)
					}
				}
			}
		}
		sortRefs(out)
		return out
	}

	memo := map[IssueRef][]IssueRef{}
	cached := func(s IssueRef) []IssueRef {
		if c, ok := memo[s]; ok {
			return c
		}
		c := direct(s)
		memo[s] = c
		return c
	}

	out := map[IssueRef][]Cause{}
	for ref := range set {
		causes := walkToRoots(ref, cached)
		if len(causes) == 0 {
			for _, c := range cached(ref) {
				causes = append(causes, Cause{IssueRef: c})
			}
		}
		if len(causes) == 0 {
			continue
		}
		sort.Slice(causes, func(i, j int) bool {
			if len(causes[i].Via) != len(causes[j].Via) {
				return len(causes[i].Via) < len(causes[j].Via)
			}
			return causes[i].IssueRef.String() < causes[j].IssueRef.String()
		})
		out[ref] = causes
	}
	return out
}

// walkToRoots follows causes breadth first, so every issue is reached by its
// shortest chain and visited once: the walk is linear in the links, however
// densely the workloads call each other.
func walkToRoots(symptom IssueRef, direct func(IssueRef) []IssueRef) []Cause {
	parent := map[IssueRef]IssueRef{}
	depth := map[IssueRef]int{symptom: 0}
	queue := []IssueRef{symptom}

	pathTo := func(node IssueRef) []IssueRef {
		var via []IssueRef
		for p := parent[node]; p != symptom; p = parent[p] {
			via = append([]IssueRef{p}, via...)
		}
		return via
	}
	isAncestor := func(node, candidate IssueRef) bool {
		for p := node; ; p = parent[p] {
			if p == candidate {
				return true
			}
			if p == symptom {
				return false
			}
		}
	}

	var causes []Cause
	var visited []IssueRef
	links := map[IssueRef][]IssueRef{}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		visited = append(visited, node)

		var open []IssueRef
		for _, c := range direct(node) {
			if !isAncestor(node, c) {
				open = append(open, c)
			}
		}
		if node != symptom && (len(open) == 0 || depth[node] >= maxCauseDepth) {
			causes = append(causes, Cause{IssueRef: node, Via: pathTo(node)})
			continue
		}
		links[node] = open
		for _, c := range open {
			if _, seen := depth[c]; seen {
				continue
			}
			depth[c] = depth[node] + 1
			parent[c] = node
			queue = append(queue, c)
		}
	}
	return append(causes, closedLoops(symptom, visited, links, causes, pathTo)...)
}

// closedLoops returns the issues the walk passed through whose every cause
// leads back among themselves, never to a root: two issues that each list the
// other.
func closedLoops(symptom IssueRef, visited []IssueRef, links map[IssueRef][]IssueRef, roots []Cause, pathTo func(IssueRef) []IssueRef) []Cause {
	explainedBy := map[IssueRef][]IssueRef{}
	for from, to := range links {
		for _, c := range to {
			explainedBy[c] = append(explainedBy[c], from)
		}
	}
	reaches := map[IssueRef]bool{}
	var queue []IssueRef
	for _, r := range roots {
		reaches[r.IssueRef] = true
		queue = append(queue, r.IssueRef)
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for _, p := range explainedBy[node] {
			if !reaches[p] {
				reaches[p] = true
				queue = append(queue, p)
			}
		}
	}

	var out []Cause
	for _, node := range visited {
		if node != symptom && !reaches[node] {
			out = append(out, Cause{IssueRef: node, Via: pathTo(node)})
		}
	}
	return out
}

func sortRefs(refs []IssueRef) {
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
}
