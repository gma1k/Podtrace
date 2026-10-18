package nodespawn

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/logger"
	"go.uber.org/zap"
)

// ContainerRef identifies one running container of a pre-resolved pod.
type ContainerRef struct {
	ID   string
	Name string
}

// PodRef holds everything the workstation pre-resolves about a target pod so
// the spawned binary can build its PodInfo without a single K8s API call.
type PodRef struct {
	Namespace     string
	Name          string
	PodIP         string
	ContainerID   string
	ContainerName string
	Containers    []ContainerRef
}

// String returns the "namespace/name" form ResolvePod accepts.
func (r PodRef) String() string {
	return r.Namespace + "/" + r.Name
}

// PreResolved returns one "ns/name/containerID/containerName/podIP" string per
// traced container, each accepted by --preresolved-pod.
func (r PodRef) PreResolved() []string {
	containers := r.Containers
	if len(containers) == 0 && r.ContainerID != "" {
		containers = []ContainerRef{{ID: r.ContainerID, Name: r.ContainerName}}
	}
	out := make([]string, 0, len(containers))
	for _, c := range containers {
		if c.ID == "" {
			continue
		}
		ref := r.Namespace + "/" + r.Name + "/" + c.ID + "/" + c.Name
		if r.PodIP != "" {
			ref += "/" + r.PodIP
		}
		out = append(out, ref)
	}
	return out
}

// NodeTargets groups the resolved target pods by the node they run on.
// One ephemeral pod will be spawned per key.
type NodeTargets struct {
	ByNode            map[string][]PodRef
	NodeNames         []string
	TolerationsByNode map[string][]corev1.Toleration
}

// Empty reports whether ResolveTargetNodes returned no pods at all.
func (t NodeTargets) Empty() bool { return len(t.NodeNames) == 0 }

// ResolveTargetNodes walks the TargetSelection, lists pods that match, and
// groups them by node. It selects with the same predicate as the local
// TargetRegistry, so a spawn and a --local run trace the same pods.
func ResolveTargetNodes(ctx context.Context, clientset kubernetes.Interface, sel pkgkube.TargetSelection) (NodeTargets, error) {
	if clientset == nil {
		return NodeTargets{}, fmt.Errorf("nodespawn: clientset is nil")
	}
	matches, err := sel.Matcher()
	if err != nil {
		return NodeTargets{}, fmt.Errorf("nodespawn: %w", err)
	}

	byNode := map[string][]PodRef{}
	tolByNode := map[string][]corev1.Toleration{}
	tolSeen := map[string]map[string]struct{}{}
	unscheduled := []PodRef{}
	missingContainer := []PodRef{}
	notRunning := []PodRef{}
	selectorMismatch := []PodRef{}
	seen := map[string]struct{}{}

	add := func(pod *corev1.Pod) {
		ref := PodRef{Namespace: pod.Namespace, Name: pod.Name, PodIP: pod.Status.PodIP}
		if _, dup := seen[ref.String()]; dup {
			return
		}
		seen[ref.String()] = struct{}{}
		if pod.Spec.NodeName == "" {
			unscheduled = append(unscheduled, ref)
			return
		}
		statuses := pickRunningContainers(pod, sel.ContainerName)
		if sel.ContainerName != "" && len(statuses) == 0 {
			missingContainer = append(missingContainer, ref)
			return
		}
		if len(statuses) > 0 {
			for _, cs := range statuses {
				if idx := indexAfterScheme(cs.ContainerID); idx >= 0 && cs.ContainerID[idx:] != "" {
					ref.Containers = append(ref.Containers, ContainerRef{ID: cs.ContainerID[idx:], Name: cs.Name})
				}
			}
		}
		if len(ref.Containers) == 0 {
			notRunning = append(notRunning, ref)
			return
		}
		ref.ContainerID = ref.Containers[0].ID
		ref.ContainerName = ref.Containers[0].Name
		node := pod.Spec.NodeName
		byNode[node] = append(byNode[node], ref)
		if tolSeen[node] == nil {
			tolSeen[node] = map[string]struct{}{}
		}
		for _, t := range pod.Spec.Tolerations {
			k := tolerationKey(t)
			if _, dup := tolSeen[node][k]; dup {
				continue
			}
			tolSeen[node][k] = struct{}{}
			tolByNode[node] = append(tolByNode[node], t)
		}
	}

	if refs := sel.PodRefSet(); len(refs) > 0 {
		for ns, names := range refs {
			if ns == "" {
				return NodeTargets{}, fmt.Errorf("nodespawn: pod refs %s need a namespace", joinNames(names))
			}
			for name := range names {
				pod, err := clientset.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
				if err != nil {
					return NodeTargets{}, fmt.Errorf("nodespawn: get pod %s/%s: %w", ns, name, err)
				}
				if !matches(pod) {
					selectorMismatch = append(selectorMismatch, PodRef{Namespace: pod.Namespace, Name: pod.Name})
					continue
				}
				add(pod)
			}
		}
	} else if sel.PodSelector != "" || sel.AllInNamespace || len(sel.Namespaces) > 1 {
		listOpts := metav1.ListOptions{LabelSelector: sel.PodSelector}
		for _, ns := range sel.WatchNamespaces() {
			list, err := clientset.CoreV1().Pods(ns).List(ctx, listOpts)
			if err != nil {
				return NodeTargets{}, fmt.Errorf("nodespawn: list pods in %q: %w", ns, err)
			}
			for i := range list.Items {
				pod := &list.Items[i]
				if pod.DeletionTimestamp != nil || !matches(pod) {
					continue
				}
				add(pod)
			}
		}
	}

	if len(missingContainer) > 0 && len(byNode) == 0 {
		return NodeTargets{}, fmt.Errorf("nodespawn: no matched pod has a running container named %q: %s",
			sel.ContainerName, joinRefs(missingContainer))
	}
	if len(unscheduled) > 0 && len(byNode) == 0 {
		return NodeTargets{}, fmt.Errorf("nodespawn: %d target pod(s) are not yet scheduled to a node: %s",
			len(unscheduled), joinRefs(unscheduled))
	}
	if len(notRunning) > 0 && len(byNode) == 0 {
		return NodeTargets{}, fmt.Errorf("nodespawn: %d target pod(s) have no running container yet: %s",
			len(notRunning), joinRefs(notRunning))
	}
	if len(selectorMismatch) > 0 && len(byNode) == 0 {
		return NodeTargets{}, fmt.Errorf("nodespawn: no named pod matches --pod-selector %q: %s",
			sel.PodSelector, joinRefs(selectorMismatch))
	}
	if len(missingContainer) > 0 {
		logger.Warn("Skipping target pod(s) with no running container matching the requested name",
			zap.String("container", sel.ContainerName),
			zap.Int("skipped", len(missingContainer)),
			zap.String("pods", joinRefs(missingContainer)))
	}
	if len(unscheduled) > 0 {
		logger.Warn("Skipping unscheduled target pod(s)",
			zap.Int("skipped", len(unscheduled)),
			zap.String("pods", joinRefs(unscheduled)))
	}
	if len(notRunning) > 0 {
		logger.Warn("Skipping target pod(s) with no running container yet",
			zap.Int("skipped", len(notRunning)),
			zap.String("pods", joinRefs(notRunning)))
	}
	if len(selectorMismatch) > 0 {
		logger.Warn("Skipping named pod(s) that do not match --pod-selector",
			zap.String("selector", sel.PodSelector),
			zap.Int("skipped", len(selectorMismatch)),
			zap.String("pods", joinRefs(selectorMismatch)))
	}

	out := NodeTargets{ByNode: byNode, TolerationsByNode: tolByNode}
	for n := range byNode {
		out.NodeNames = append(out.NodeNames, n)
	}
	sort.Strings(out.NodeNames)
	for n := range byNode {
		sort.Slice(byNode[n], func(i, j int) bool {
			a, b := byNode[n][i], byNode[n][j]
			if a.Namespace != b.Namespace {
				return a.Namespace < b.Namespace
			}
			return a.Name < b.Name
		})
	}
	return out, nil
}

// pickRunningContainers returns every running container with a container ID,
// regular, restartable-init (sidecar), and ephemeral, when name is empty,
// or exactly the named one.
func pickRunningContainers(pod *corev1.Pod, name string) []corev1.ContainerStatus {
	if pod == nil {
		return nil
	}
	var out []corev1.ContainerStatus
	add := func(list []corev1.ContainerStatus) {
		for i := range list {
			cs := list[i]
			if cs.State.Running == nil || cs.ContainerID == "" {
				continue
			}
			if name != "" && cs.Name != name {
				continue
			}
			out = append(out, cs)
		}
	}
	add(pod.Status.ContainerStatuses)
	add(pod.Status.InitContainerStatuses)
	add(pod.Status.EphemeralContainerStatuses)
	return out
}

// indexAfterScheme returns the offset right after "://" in a containerID like
// "containerd://abc123" so the caller can slice off the runtime prefix.
func indexAfterScheme(s string) int {
	i := strings.Index(s, "://")
	if i < 0 {
		return -1
	}
	return i + 3
}

// tolerationKey is a stable string used to dedupe Tolerations across the
// target pods on one node.
func tolerationKey(t corev1.Toleration) string {
	sec := "nil"
	if t.TolerationSeconds != nil {
		sec = fmt.Sprintf("%d", *t.TolerationSeconds)
	}
	return string(t.Effect) + "|" + t.Key + "|" + string(t.Operator) + "|" + t.Value + "|" + sec
}

func joinRefs(refs []PodRef) string {
	s := make([]string, len(refs))
	for i, r := range refs {
		s[i] = r.String()
	}
	return strings.Join(s, ", ")
}

func joinNames(names map[string]struct{}) string {
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
