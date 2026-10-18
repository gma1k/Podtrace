package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"k8s.io/client-go/kubernetes"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/sanitize"
	"go.uber.org/zap"
)

// podEvents groups the Kubernetes events collected for one target pod.
type podEvents struct {
	pod    string
	events []*pkgkube.K8sEvent
}

// startWorkstationEventCorrelation watches Kubernetes Events for the
// pre-resolved target pods using the workstation's clientset (the user's
// kubeconfig).
func startWorkstationEventCorrelation(ctx context.Context, clientset kubernetes.Interface, pods []nodespawn.PodRef, out io.Writer) func() {
	if clientset == nil || len(pods) == 0 {
		return func() {}
	}

	type key struct{ ns, name string }
	seen := map[key]bool{}
	uniq := make([]nodespawn.PodRef, 0, len(pods))
	for _, p := range pods {
		k := key{p.Namespace, p.Name}
		if p.Name == "" || seen[k] {
			continue
		}
		seen[k] = true
		uniq = append(uniq, p)
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i].String() < uniq[j].String() })

	correlators := make([]*pkgkube.EventsCorrelator, 0, len(uniq))
	refs := make([]nodespawn.PodRef, 0, len(uniq))
	for _, p := range uniq {
		ec := pkgkube.NewEventsCorrelator(clientset, p.Name, p.Namespace)
		if err := ec.Start(ctx); err != nil {
			if pkgkube.IsPermissionError(err) {
				logger.Info("Kubernetes event correlation skipped: your kubeconfig cannot watch events in namespace " + p.Namespace + ". Tracing is unaffected.")
				for _, c := range correlators {
					c.Stop()
				}
				return func() {}
			}
			logger.Debug("event correlator failed to start (non-fatal)", zap.Error(err))
			continue
		}
		correlators = append(correlators, ec)
		refs = append(refs, p)
	}
	if len(correlators) == 0 {
		return func() {}
	}

	return func() {
		var groups []podEvents
		for i, ec := range correlators {
			ec.Stop()
			evs := ec.GetEvents()
			if len(evs) == 0 {
				continue
			}
			groups = append(groups, podEvents{pod: refs[i].String(), events: evs})
		}
		if section := formatK8sEventsSection(groups); section != "" {
			_, _ = fmt.Fprint(out, section)
		}
	}
}

// formatK8sEventsSection renders collected pod events into a human-readable
// section.
func formatK8sEventsSection(groups []podEvents) string {
	if len(groups) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n=== Kubernetes Events (observed during trace) ===\n\n")
	for _, g := range groups {
		evs := make([]*pkgkube.K8sEvent, len(g.events))
		copy(evs, g.events)
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].Timestamp.Before(evs[j].Timestamp) })

		fmt.Fprintf(&b, "  %s:\n", g.pod)
		for _, e := range evs {
			count := ""
			if e.Count > 1 {
				count = fmt.Sprintf(" (x%d)", e.Count)
			}
			fmt.Fprintf(&b, "    %s  %-7s %-22s %s%s\n",
				e.Timestamp.Format("15:04:05"), sanitize.TerminalLine(e.Type),
				sanitize.TerminalLine(e.Reason), sanitize.TerminalLine(e.Message), count)
		}
		b.WriteString("\n")
	}
	return b.String()
}
