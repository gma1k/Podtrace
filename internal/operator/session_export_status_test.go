package operator

import (
	"context"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func condition(s *podtracev1alpha1.PodTraceSession, condType string) *metav1.Condition {
	for i := range s.Status.Conditions {
		if s.Status.Conditions[i].Type == condType {
			return &s.Status.Conditions[i]
		}
	}
	return nil
}

func reconciledSession() *podtracev1alpha1.PodTraceSession {
	s := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"}}
	s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
		Type: ConditionDegraded, Status: metav1.ConditionFalse, Reason: "Reconciled",
	})
	return s
}

func TestExportConditionUnreachableMarksTheSessionDegraded(t *testing.T) {
	s := reconciledSession()
	applySessionExportConditions(s, map[string]sessionSummaryJSON{
		"node-a": {Exports: []sessionExportJSON{{Exporter: "otlp", Failed: 8, LastError: "lookup recv: no such host"}}},
	})

	exported := condition(s, ConditionExported)
	if exported == nil || exported.Status != metav1.ConditionFalse || exported.Reason != ReasonExporterUnreachable {
		t.Fatalf("Exported = %+v, want False/%s", exported, ReasonExporterUnreachable)
	}
	if !strings.Contains(exported.Message, "otlp: none of 8 export batches delivered") || !strings.Contains(exported.Message, "no such host") {
		t.Fatalf("Exported message does not explain the failure: %q", exported.Message)
	}
	degraded := condition(s, ConditionDegraded)
	if degraded == nil || degraded.Status != metav1.ConditionTrue || degraded.Reason != ReasonExporterUnreachable {
		t.Fatalf("Degraded = %+v, want True/%s", degraded, ReasonExporterUnreachable)
	}
}

func TestExportConditionPartialFailureDoesNotDegrade(t *testing.T) {
	s := reconciledSession()
	applySessionExportConditions(s, map[string]sessionSummaryJSON{
		"node-a": {Exports: []sessionExportJSON{{Exporter: "otlp", Succeeded: 6, Failed: 2, LastError: "status 503"}}},
	})

	exported := condition(s, ConditionExported)
	if exported == nil || exported.Status != metav1.ConditionFalse || exported.Reason != ReasonExportPartiallyFailed {
		t.Fatalf("Exported = %+v, want False/%s", exported, ReasonExportPartiallyFailed)
	}
	if !strings.Contains(exported.Message, "otlp: 2 of 8 export batches failed") {
		t.Fatalf("unexpected message %q", exported.Message)
	}
	if degraded := condition(s, ConditionDegraded); degraded.Status != metav1.ConditionFalse {
		t.Fatalf("Degraded = %+v, want it left False", degraded)
	}
}

func TestExportConditionDeliveredIsTrue(t *testing.T) {
	s := reconciledSession()
	applySessionExportConditions(s, map[string]sessionSummaryJSON{
		"node-a": {Exports: []sessionExportJSON{{Exporter: "zipkin", Succeeded: 3}}},
	})

	exported := condition(s, ConditionExported)
	if exported == nil || exported.Status != metav1.ConditionTrue || exported.Reason != ReasonExportDelivered {
		t.Fatalf("Exported = %+v, want True/%s", exported, ReasonExportDelivered)
	}
	if exported.Message != "zipkin: 3 export batches delivered" {
		t.Fatalf("unexpected message %q", exported.Message)
	}
}

func TestExportConditionSumsNodesSoOneDeliveringNodeIsPartial(t *testing.T) {
	s := reconciledSession()
	applySessionExportConditions(s, map[string]sessionSummaryJSON{
		"node-a": {Exports: []sessionExportJSON{{Exporter: "otlp", Failed: 4, LastError: "timeout"}}},
		"node-b": {Exports: []sessionExportJSON{{Exporter: "otlp", Succeeded: 4}}},
	})

	if exported := condition(s, ConditionExported); exported.Reason != ReasonExportPartiallyFailed {
		t.Fatalf("Exported reason = %s, want %s", exported.Reason, ReasonExportPartiallyFailed)
	}
}

func TestExportConditionNamesEveryUnreachableExporterFirst(t *testing.T) {
	s := reconciledSession()
	applySessionExportConditions(s, map[string]sessionSummaryJSON{
		"node-a": {Exports: []sessionExportJSON{
			{Exporter: "zipkin", Succeeded: 2},
			{Exporter: "otlp", Failed: 3, LastError: "refused"},
		}},
	})

	exported := condition(s, ConditionExported)
	if exported.Reason != ReasonExporterUnreachable {
		t.Fatalf("Exported reason = %s, want %s", exported.Reason, ReasonExporterUnreachable)
	}
	if !strings.HasPrefix(exported.Message, "otlp: none of 3") || !strings.Contains(exported.Message, "zipkin: 2 export batches delivered") {
		t.Fatalf("unexpected message %q", exported.Message)
	}
}

func TestExportConditionAbsentWithoutExportRecords(t *testing.T) {
	s := reconciledSession()
	applySessionExportConditions(s, map[string]sessionSummaryJSON{"node-a": {TotalEvents: 10}})
	applySessionExportConditions(s, nil)

	if exported := condition(s, ConditionExported); exported != nil {
		t.Fatalf("Exported = %+v, want no condition", exported)
	}
}

func TestCollectSessionSummariesCarriesExportRecords(t *testing.T) {
	now := metav1.Now()
	job := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "pts-s-a", Namespace: "podtrace-system", Labels: map[string]string{LabelNodeName: "node-a"}},
		Status:     batchv1.JobStatus{Succeeded: 1, CompletionTime: &now},
	}
	pod := podWithTerminationSummary("pts-s-a-xyz", "podtrace-system", "pts-s-a", sessionSummaryJSON{
		TotalEvents: 5,
		Exports:     []sessionExportJSON{{Exporter: "otlp", Failed: 2, LastError: "no such host"}},
	})
	c := fake.NewClientBuilder().WithScheme(newSummaryScheme(t)).WithObjects(pod).Build()

	byNode, err := collectSessionSummaries(context.Background(), c, []batchv1.Job{job})
	if err != nil {
		t.Fatal(err)
	}
	got := byNode["node-a"].Exports
	if len(got) != 1 || got[0].Exporter != "otlp" || got[0].Failed != 2 || got[0].LastError != "no such host" {
		t.Fatalf("export records = %+v", got)
	}
}

func TestExportConditionIgnoresUnnamedExporterRecords(t *testing.T) {
	s := reconciledSession()
	applySessionExportConditions(s, map[string]sessionSummaryJSON{
		"node-a": {Exports: []sessionExportJSON{{Failed: 9, LastError: "anonymous failure"}}},
	})
	if got := condition(s, ConditionExported); got != nil {
		t.Fatalf("Exported = %+v, want no condition from an unnamed exporter record", got)
	}

	applySessionExportConditions(s, map[string]sessionSummaryJSON{
		"node-a": {Exports: []sessionExportJSON{{Failed: 9, LastError: "anonymous failure"}, {Exporter: "otlp", Succeeded: 3}}},
	})
	exported := condition(s, ConditionExported)
	if exported == nil || exported.Status != metav1.ConditionTrue || exported.Reason != ReasonExportDelivered {
		t.Fatalf("Exported = %+v, want True/%s", exported, ReasonExportDelivered)
	}
	if strings.Contains(exported.Message, "anonymous failure") {
		t.Fatalf("Exported message leaked the unnamed record: %q", exported.Message)
	}
}
