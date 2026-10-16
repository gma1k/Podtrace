package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/event"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
)

func readyAgentPod(namespace, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{LabelComponent: ComponentAgent}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			PodIP:      "10.0.0.1",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
}

func TestIssueCorrelatorAgents_ReadsEveryFleetNamespaceOnly(t *testing.T) {
	fleetB := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "fleet-b"},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "fleet-b-system"},
	}
	c, _ := newCorrelator(t,
		&podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName}},
		fleetB,
		readyAgentPod("podtrace-system", "agent-a"),
		readyAgentPod("fleet-b-system", "agent-b"),
		readyAgentPod("tenant", "impostor"),
	)

	agents, err := c.agents(context.Background())
	if err != nil {
		t.Fatalf("agents: %v", err)
	}
	got := map[string]bool{}
	for _, p := range agents {
		got[p.Namespace+"/"+p.Name] = true
	}
	if !got["podtrace-system/agent-a"] || !got["fleet-b-system/agent-b"] {
		t.Errorf("want agents of both fleets, got %v", got)
	}
	if got["tenant/impostor"] {
		t.Error("a tenant pod carrying the agent label must not be read")
	}
}

func TestSessionStateChangedPredicate(t *testing.T) {
	p := sessionStateChangedPredicate()
	running := &podtracev1alpha1.PodTraceSession{Status: podtracev1alpha1.PodTraceSessionStatus{State: podtracev1alpha1.SessionStateRunning}}
	stillRunning := running.DeepCopy()
	stillRunning.Status.Conditions = []metav1.Condition{{Type: ConditionReconciled}}
	completed := running.DeepCopy()
	completed.Status.State = podtracev1alpha1.SessionStateCompleted

	if p.Update(event.UpdateEvent{ObjectOld: running, ObjectNew: stillRunning}) {
		t.Error("a status write that keeps the state must not re-reconcile every fleet")
	}
	if !p.Update(event.UpdateEvent{ObjectOld: running, ObjectNew: completed}) {
		t.Error("a state transition changes the active-session count")
	}
	if !p.Create(event.CreateEvent{Object: running}) || !p.Delete(event.DeleteEvent{Object: running}) {
		t.Error("create and delete change the active-session count")
	}
}

func TestAlertEventFieldSelector(t *testing.T) {
	sel := alertEventFieldSelector()
	if !sel.Matches(fields.Set{"reason": alerting.EventReasonAlert}) {
		t.Error("the Event cache must keep podtrace alert Events")
	}
	if sel.Matches(fields.Set{"reason": "Scheduled"}) {
		t.Error("the Event cache must drop every other Event")
	}
}
