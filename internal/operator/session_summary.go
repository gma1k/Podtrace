package operator

import (
	"context"
	"encoding/json"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// sessionSummaryJSON mirrors the SessionSummary shape the CLI writes to
// /dev/termination-log. Kept as a dedicated operator-side struct so the
// controller does not take a compile-time dependency on cmd/podtrace.
type sessionSummaryJSON struct {
	TotalEvents    int64  `json:"totalEvents"`
	DNSEvents      int64  `json:"dnsEvents,omitempty"`
	NetEvents      int64  `json:"netEvents,omitempty"`
	FSEvents       int64  `json:"fsEvents,omitempty"`
	CPUEvents      int64  `json:"cpuEvents,omitempty"`
	ProcEvents     int64  `json:"procEvents,omitempty"`
	ErrorsDetected int32  `json:"errorsDetected,omitempty"`
	DurationMS     int64  `json:"durationMs,omitempty"`
	Node           string `json:"node,omitempty"`

	Exports []sessionExportJSON `json:"exports,omitempty"`
}

// sessionExportJSON is one exporter's delivery record as a session Job
// reports it (cmd/podtrace SessionExportStatus).
type sessionExportJSON struct {
	Exporter  string `json:"exporter"`
	Succeeded int64  `json:"succeeded,omitempty"`
	Failed    int64  `json:"failed,omitempty"`
	LastError string `json:"lastError,omitempty"`
}

// populateSessionSummaries walks the session's child Jobs, reads the
// matching Pod's terminationMessage, and rolls the per-Job counts up
// into the session's status.Summary plus per-Job status.jobs[i].eventCount.
func populateSessionSummaries(ctx context.Context, c client.Client, session *podtracev1alpha1.PodTraceSession, jobs []batchv1.Job) error {
	if session == nil {
		return nil
	}
	summaryByNode, err := collectSessionSummaries(ctx, c, jobs)
	if err != nil {
		return err
	}
	applySessionSummaries(session, summaryByNode)
	return nil
}

// collectSessionSummaries reads the termination summary of every finished
// session Job, keyed by node.
func collectSessionSummaries(ctx context.Context, c client.Client, jobs []batchv1.Job) (map[string]sessionSummaryJSON, error) {
	summaryByNode := map[string]sessionSummaryJSON{}
	for i := range jobs {
		j := &jobs[i]
		summary, err := readTerminationSummaryForJob(ctx, c, j)
		if err != nil {
			return nil, err
		}
		if summary == nil {
			continue
		}
		node := j.Labels[LabelNodeName]
		if node == "" {
			node = summary.Node
		}
		summaryByNode[node] = *summary
	}
	return summaryByNode, nil
}

// applySessionSummaries rolls per-node summaries up into status.Summary and
// the per-Job event counts.
func applySessionSummaries(session *podtracev1alpha1.PodTraceSession, summaryByNode map[string]sessionSummaryJSON) {
	for i := range session.Status.Jobs {
		ref := &session.Status.Jobs[i]
		if s, ok := summaryByNode[ref.Node]; ok {
			ref.TotalEvents = s.TotalEvents
		}
	}

	session.Status.Summary = aggregateSessionSummary(summaryByNode)
}

// readTerminationSummaryForJob locates the Pod created by a session
// Job, reads its terminationMessage, and decodes the JSON into
// sessionSummaryJSON.
func readTerminationSummaryForJob(ctx context.Context, c client.Client, job *batchv1.Job) (*sessionSummaryJSON, error) {
	if job.Status.CompletionTime == nil && job.Status.Failed == 0 {
		return nil, nil
	}
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(job.Namespace), client.MatchingLabels{
		"job-name": job.Name,
	}); err != nil {
		return nil, fmt.Errorf("list pods for Job %s: %w", job.Name, err)
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Name != "podtrace" {
				continue
			}
			if cs.State.Terminated == nil {
				continue
			}
			raw := cs.State.Terminated.Message
			if raw == "" {
				return nil, nil
			}
			var s sessionSummaryJSON
			if err := json.Unmarshal([]byte(raw), &s); err != nil {
				return nil, nil
			}
			return &s, nil
		}
	}
	return nil, nil
}

// aggregateSessionSummary reduces per-Job summaries to the cluster-wide
// SessionSummary the CRD exposes on status.summary.
func aggregateSessionSummary(byNode map[string]sessionSummaryJSON) *podtracev1alpha1.SessionSummary {
	if len(byNode) == 0 {
		return nil
	}
	out := &podtracev1alpha1.SessionSummary{}
	byFilter := map[string]int64{}
	for _, s := range byNode {
		out.TotalEvents += s.TotalEvents
		out.ErrorsDetected += s.ErrorsDetected
		byFilter[string(podtracev1alpha1.FilterDNS)] += s.DNSEvents
		byFilter[string(podtracev1alpha1.FilterNet)] += s.NetEvents
		byFilter[string(podtracev1alpha1.FilterFS)] += s.FSEvents
		byFilter[string(podtracev1alpha1.FilterCPU)] += s.CPUEvents
		byFilter[string(podtracev1alpha1.FilterProc)] += s.ProcEvents
	}
	for name, count := range byFilter {
		if count == 0 {
			delete(byFilter, name)
		}
	}
	if len(byFilter) > 0 {
		out.EventsByFilter = byFilter
	}
	return out
}
