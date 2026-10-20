package chart_test

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	policyv1 "k8s.io/api/policy/v1"
)

func TestOperatorRolloutNeverLeavesTheWebhookWithoutAReadyPod(t *testing.T) {
	var deploy appsv1.Deployment
	mustFindObject(t, renderChart(t, "webhook.enabled=true"), "Deployment", "podtrace-operator").decode(t, &deploy)

	rolling := deploy.Spec.Strategy.RollingUpdate
	if rolling == nil || rolling.MaxUnavailable == nil || rolling.MaxUnavailable.IntValue() != 0 {
		t.Errorf("maxUnavailable = %v; with one replica and failurePolicy Fail, any value "+
			"above 0 rejects every podtrace.io write until the new pod is Ready", rolling)
	}
	if rolling == nil || rolling.MaxSurge == nil || rolling.MaxSurge.IntValue() < 1 {
		t.Errorf("maxSurge = %v; with maxUnavailable 0 the rollout cannot progress without a surge", rolling)
	}
}

func TestOperatorDisruptionBudgetOnlyWithSeveralReplicas(t *testing.T) {
	if _, ok := findObject(t, renderChart(t), "PodDisruptionBudget", "podtrace-operator"); ok {
		t.Error("a budget over a single replica blocks node drains")
	}

	var pdb policyv1.PodDisruptionBudget
	mustFindObject(t, renderChart(t, "operator.replicas=2"), "PodDisruptionBudget", "podtrace-operator").decode(t, &pdb)
	if pdb.Spec.MaxUnavailable == nil || pdb.Spec.MaxUnavailable.IntValue() != 1 {
		t.Errorf("maxUnavailable = %v, want 1", pdb.Spec.MaxUnavailable)
	}
	if pdb.Spec.Selector.MatchLabels["app.kubernetes.io/component"] != "operator" {
		t.Errorf("selector %v does not select the operator", pdb.Spec.Selector.MatchLabels)
	}
}

func TestNotesNameTheRealBootstrapNamespaceAndChartReference(t *testing.T) {
	notes := string(readRepoFile(t, "deploy", "charts", "podtrace", "templates", "NOTES.txt"))
	if strings.Contains(notes, "kube-system") {
		t.Error("NOTES still says the bootstrap Job runs in kube-system; it runs in the release namespace")
	}
	if !strings.Contains(notes, "oci://ghcr.io/gma1k/charts/podtrace") {
		t.Error("NOTES suggests an upgrade with a bare chart name that resolves to nothing")
	}
}
