package operator

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/fleet"
)

// errNoTracerConfig reports that nothing resolved for a node.
type errNoTracerConfig struct {
	node    string
	pinned  string
	reason  string
	configs []string
	refused bool
}

func (e *errNoTracerConfig) Error() string {
	if e.refused {
		return fmt.Sprintf("the TracerConfig for node %q is refused: %s", e.node, e.reason)
	}
	if e.pinned != "" {
		return fmt.Sprintf("spec.tracerConfigRef %q: %s", e.pinned, e.reason)
	}
	return fmt.Sprintf(
		"no TracerConfig resolves for node %q: %s. Existing configs: %v. "+
			"Either label the node into a fleet, create a TracerConfig named %q, "+
			"or pin one with spec.tracerConfigRef",
		e.node, e.reason, e.configs, DefaultTracerConfigName)
}

// sessionTracerConfigs holds the per-node resolution for one session.
type sessionTracerConfigs struct {
	byNode     map[string]*podtracev1alpha1.TracerConfig
	namespaces []string
}

// forNode returns the config resolved for a node, or nil when the node was
// not part of the resolution.
func (s sessionTracerConfigs) forNode(node string) *podtracev1alpha1.TracerConfig {
	if s.byNode == nil {
		return nil
	}
	return s.byNode[node]
}

// namespaceForNode returns the system namespace a node's Job belongs in.
func (s sessionTracerConfigs) namespaceForNode(node, fallback string) string {
	return systemNamespaceForSession(s.forNode(node), fallback)
}

// resolveSessionTracerConfigs works out which TracerConfig governs each of a
// session's target nodes.
//
// Order per node:
//
//  1. spec.tracerConfigRef, when set — an explicit pin wins everywhere, so a
//     session can be made reproducible regardless of where its pods land.
//  2. The fleet whose scheduling constraints target that node, taken from
//     the same partition the TracerConfig reconciler reports on. When two
//     fleets contest a node, the partition's precedence rule (priority, then
//     age, then name) picks one — the same answer the Conflict condition
//     advertises, so the session agrees with what the operator told the user.
//  3. The config named "default".
//
// Exhausting all three is an error, not a nil config: a Job built without a
// TracerConfig has no image.
func (r *PodTraceSessionReconciler) resolveSessionTracerConfigs(
	ctx context.Context,
	s *podtracev1alpha1.PodTraceSession,
	nodes []string,
) (sessionTracerConfigs, error) {
	out := sessionTracerConfigs{byNode: map[string]*podtracev1alpha1.TracerConfig{}}

	if ref := s.Spec.TracerConfigRef; ref != nil && ref.Name != "" {
		var pinned podtracev1alpha1.TracerConfig
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, &pinned); err != nil {
			if apierrors.IsNotFound(err) {
				return out, &errNoTracerConfig{pinned: ref.Name, reason: "TracerConfig not found"}
			}
			return out, fmt.Errorf("get TracerConfig %q: %w", ref.Name, err)
		}
		if !podtracev1alpha1.TracerConfigAllowsSessionFrom(&pinned, s.Namespace, r.SystemNamespace) {
			return out, &errNoTracerConfig{
				pinned: ref.Name,
				reason: fmt.Sprintf("not entitled: TracerConfig %q does not grant sessions from namespace %q (set annotation %s on the config)",
					ref.Name, s.Namespace, podtracev1alpha1.AllowSessionsFromAnnotation),
			}
		}
		for _, node := range nodes {
			out.byNode[node] = &pinned
		}
		out.namespaces = distinctNamespaces(out.byNode, r.SystemNamespace)
		return out, refuseInvalidSystemNamespaces(out)
	}

	var configs podtracev1alpha1.TracerConfigList
	if err := r.List(ctx, &configs); err != nil {
		return out, fmt.Errorf("list TracerConfigs: %w", err)
	}
	byName := map[string]*podtracev1alpha1.TracerConfig{}
	names := make([]string, 0, len(configs.Items))
	for i := range configs.Items {
		byName[configs.Items[i].Name] = &configs.Items[i]
		names = append(names, configs.Items[i].Name)
	}
	sort.Strings(names)

	// Node objects are only needed to run the partition. Losing the read is
	// not fatal: fall through to "default", which is what every release
	// before per-node resolution did.
	winner := map[string]string{}
	var nodeList corev1.NodeList
	if err := r.List(ctx, &nodeList); err == nil {
		winner = fleet.ComputePartition(configs.Items, nodeList.Items).Winner
	}

	for _, node := range nodes {
		if name, ok := winner[node]; ok {
			if tc := byName[name]; tc != nil {
				out.byNode[node] = tc
				continue
			}
		}
		if tc := byName[DefaultTracerConfigName]; tc != nil {
			out.byNode[node] = tc
			continue
		}
		reason := "no fleet targets it and there is no default TracerConfig"
		if len(names) == 0 {
			reason = "the cluster has no TracerConfig at all"
		}
		return out, &errNoTracerConfig{node: node, reason: reason, configs: names}
	}

	out.namespaces = distinctNamespaces(out.byNode, r.SystemNamespace)
	return out, refuseInvalidSystemNamespaces(out)
}

// refuseInvalidSystemNamespaces fails resolution when a node's TracerConfig
// names a system namespace the operator refuses, so no Job, bundle or
// credential copy is ever placed there.
func refuseInvalidSystemNamespaces(out sessionTracerConfigs) error {
	nodes := make([]string, 0, len(out.byNode))
	for node := range out.byNode {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	for _, node := range nodes {
		tc := out.byNode[node]
		if err := podtracev1alpha1.ValidateSystemNamespace(tc.Spec.SystemNamespace); err != nil {
			return &errNoTracerConfig{node: node, refused: true, reason: fmt.Sprintf("TracerConfig %q: %v", tc.Name, err)}
		}
	}
	return nil
}

// distinctNamespaces returns the sorted set of system namespaces the
// resolved configs map to.
func distinctNamespaces(byNode map[string]*podtracev1alpha1.TracerConfig, fallback string) []string {
	seen := map[string]struct{}{}
	for _, tc := range byNode {
		seen[systemNamespaceForSession(tc, fallback)] = struct{}{}
	}
	if len(seen) == 0 {
		seen[fallback] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for ns := range seen {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// primary returns the config used for session-wide decisions that are not
// per-node, such as the concurrency cap. Deterministic: the config of the
// lowest-sorted node.
func (s sessionTracerConfigs) primary() *podtracev1alpha1.TracerConfig {
	nodes := make([]string, 0, len(s.byNode))
	for node := range s.byNode {
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return nil
	}
	sort.Strings(nodes)
	return s.byNode[nodes[0]]
}
