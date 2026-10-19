package operator

import (
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// Reasons for the Exported condition, also used on Degraded when no span
// reached the backend.
const (
	ReasonExportDelivered       = "Delivered"
	ReasonExporterUnreachable   = "ExporterUnreachable"
	ReasonExportPartiallyFailed = "ExportPartiallyFailed"
)

// exportTally is one exporter's delivery record summed over the nodes.
type exportTally struct {
	succeeded int64
	failed    int64
	lastError string
}

// applySessionExportConditions turns the session Jobs' export records into
// the Exported condition.
func applySessionExportConditions(s *podtracev1alpha1.PodTraceSession, summaryByNode map[string]sessionSummaryJSON) {
	tallies := map[string]*exportTally{}
	nodes := make([]string, 0, len(summaryByNode))
	for node := range summaryByNode {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	for _, node := range nodes {
		for _, e := range summaryByNode[node].Exports {
			if e.Exporter == "" {
				continue
			}
			t, ok := tallies[e.Exporter]
			if !ok {
				t = &exportTally{}
				tallies[e.Exporter] = t
			}
			t.succeeded += e.Succeeded
			t.failed += e.Failed
			if e.LastError != "" {
				t.lastError = e.LastError
			}
		}
	}
	if len(tallies) == 0 {
		return
	}

	names := make([]string, 0, len(tallies))
	for name := range tallies {
		names = append(names, name)
	}
	sort.Strings(names)

	var unreachable, partial, delivered []string
	for _, name := range names {
		t := tallies[name]
		total := t.succeeded + t.failed
		switch {
		case t.failed > 0 && t.succeeded == 0:
			unreachable = append(unreachable, fmt.Sprintf("%s: none of %d export batches delivered; last error: %s", name, total, t.lastError))
		case t.failed > 0:
			partial = append(partial, fmt.Sprintf("%s: %d of %d export batches failed; last error: %s", name, t.failed, total, t.lastError))
		default:
			delivered = append(delivered, fmt.Sprintf("%s: %d export batches delivered", name, t.succeeded))
		}
	}

	status, reason := metav1.ConditionTrue, ReasonExportDelivered
	var message []string
	switch {
	case len(unreachable) > 0:
		status, reason = metav1.ConditionFalse, ReasonExporterUnreachable
		message = append(append(append(message, unreachable...), partial...), delivered...)
	case len(partial) > 0:
		status, reason = metav1.ConditionFalse, ReasonExportPartiallyFailed
		message = append(append(message, partial...), delivered...)
	default:
		message = delivered
	}
	text := strings.Join(message, "; ")
	s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
		Type:               ConditionExported,
		Status:             status,
		Reason:             reason,
		Message:            text,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: s.Generation,
	})
	if reason == ReasonExporterUnreachable {
		s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
			Type:               ConditionDegraded,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonExporterUnreachable,
			Message:            text,
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: s.Generation,
		})
	}
}
