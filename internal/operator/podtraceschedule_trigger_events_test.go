package operator

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
)

func triggerSchedule(name, namespace string, mutators ...func(*podtracev1alpha1.TriggerSpec)) *podtracev1alpha1.PodTraceSchedule {
	trigger := &podtracev1alpha1.TriggerSpec{
		Sources: []podtracev1alpha1.TriggerSource{
			{Kind: podtracev1alpha1.TriggerSourceResourceAlert, MinSeverity: "warning"},
		},
	}
	for _, m := range mutators {
		m(trigger)
	}
	return &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       podtracev1alpha1.PodTraceScheduleSpec{Trigger: trigger},
	}
}

func cronSchedule(name, namespace string) *podtracev1alpha1.PodTraceSchedule {
	return &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       podtracev1alpha1.PodTraceScheduleSpec{Schedule: "*/5 * * * *"},
	}
}

func labelledPod(namespace, name string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
	}
}

func resourceAlertFor(namespace, pod string) alertEvent {
	return alertEvent{
		Namespace: namespace,
		PodName:   pod,
		Kind:      podtracev1alpha1.TriggerSourceResourceAlert,
		Severity:  "critical",
	}
}

func podtraceAlertEvent(namespace, pod string) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alert-" + pod,
			Namespace: namespace,
			Annotations: map[string]string{
				alerting.AnnotationAlertSource:   alerting.AlertSourceResourceMonitor,
				alerting.AnnotationAlertSeverity: "critical",
			},
		},
		Reason:         alerting.EventReasonAlert,
		Source:         corev1.EventSource{Component: alerting.EventComponent},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: namespace, Name: pod},
	}
}

func triggerReconciler(t *testing.T, objects ...client.Object) *PodTraceScheduleReconciler {
	t.Helper()
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	return &PodTraceScheduleReconciler{Client: c, Scheme: scheme}
}

func eventPodNames(events []alertEvent) []string {
	names := make([]string, 0, len(events))
	for _, ev := range events {
		names = append(names, ev.PodName)
	}
	return names
}

func TestFilterEligibleEvents_SelectorDropsNonMatchingPods(t *testing.T) {
	r := triggerReconciler(t,
		labelledPod("prod", "checkout-1", map[string]string{"app": "checkout"}),
		labelledPod("prod", "billing-1", map[string]string{"app": "billing"}),
	)
	sch := triggerSchedule("fr", "obs", func(tr *podtracev1alpha1.TriggerSpec) {
		tr.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "checkout"}}
	})

	got, err := r.filterEligibleEvents(context.Background(), sch, []alertEvent{
		resourceAlertFor("prod", "checkout-1"),
		resourceAlertFor("prod", "billing-1"),
	})
	if err != nil {
		t.Fatalf("filterEligibleEvents: %v", err)
		return
	}
	if len(got) != 1 || got[0].PodName != "checkout-1" {
		t.Errorf("selector must keep only the matching pod, got %v", eventPodNames(got))
	}
}

func TestFilterEligibleEvents_SelectorDropsAlertsForMissingPods(t *testing.T) {
	r := triggerReconciler(t, labelledPod("prod", "checkout-1", map[string]string{"app": "checkout"}))
	sch := triggerSchedule("fr", "obs", func(tr *podtracev1alpha1.TriggerSpec) {
		tr.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "checkout"}}
	})

	got, err := r.filterEligibleEvents(context.Background(), sch, []alertEvent{
		resourceAlertFor("prod", "checkout-1"),
		resourceAlertFor("prod", "already-deleted"),
	})
	if err != nil {
		t.Fatalf("a vanished pod must not fail the pass: %v", err)
		return
	}
	if len(got) != 1 || got[0].PodName != "checkout-1" {
		t.Errorf("got %v, want only checkout-1", eventPodNames(got))
	}
}

func TestFilterEligibleEvents_EmptySelectorKeepsEveryPodInScope(t *testing.T) {
	r := triggerReconciler(t)
	sch := triggerSchedule("fr", "obs")

	got, err := r.filterEligibleEvents(context.Background(), sch, []alertEvent{
		resourceAlertFor("prod", "checkout-1"),
		resourceAlertFor("prod", "billing-1"),
	})
	if err != nil {
		t.Fatalf("filterEligibleEvents: %v", err)
		return
	}
	if len(got) != 2 {
		t.Errorf("nil selector must keep every source-matching alert, got %v", eventPodNames(got))
	}
}

func TestFilterEligibleEvents_DropsAlertsBelowMinSeverity(t *testing.T) {
	r := triggerReconciler(t)
	sch := triggerSchedule("fr", "obs", func(tr *podtracev1alpha1.TriggerSpec) {
		tr.Sources = []podtracev1alpha1.TriggerSource{
			{Kind: podtracev1alpha1.TriggerSourceResourceAlert, MinSeverity: "critical"},
		}
	})

	warning := resourceAlertFor("prod", "checkout-1")
	warning.Severity = "warning"

	got, err := r.filterEligibleEvents(context.Background(), sch, []alertEvent{
		warning,
		resourceAlertFor("prod", "billing-1"),
	})
	if err != nil {
		t.Fatalf("filterEligibleEvents: %v", err)
		return
	}
	if len(got) != 1 || got[0].PodName != "billing-1" {
		t.Errorf("warning below minSeverity=critical must drop, got %v", eventPodNames(got))
	}
}

func TestFilterEligibleEvents_DropsUnconfiguredSourceKinds(t *testing.T) {
	r := triggerReconciler(t)
	sch := triggerSchedule("fr", "obs")

	oom := resourceAlertFor("prod", "doomed-1")
	oom.Kind = podtracev1alpha1.TriggerSourceOOMKill

	got, err := r.filterEligibleEvents(context.Background(), sch, []alertEvent{oom})
	if err != nil {
		t.Fatalf("filterEligibleEvents: %v", err)
		return
	}
	if len(got) != 0 {
		t.Errorf("OOMKill must not fire a ResourceAlert-only trigger, got %v", eventPodNames(got))
	}
}

func TestFilterEligibleEvents_MalformedSelectorErrors(t *testing.T) {
	r := triggerReconciler(t)
	sch := triggerSchedule("fr", "obs", func(tr *podtracev1alpha1.TriggerSpec) {
		tr.Selector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "app", Operator: "Bogus", Values: []string{"x"}},
			},
		}
	})

	_, err := r.filterEligibleEvents(context.Background(), sch, []alertEvent{resourceAlertFor("prod", "checkout-1")})
	if err == nil {
		t.Fatal("expected an error for a malformed selector")
		return
	}
	if !strings.Contains(err.Error(), "spec.trigger.selector") {
		t.Errorf("error %q should name spec.trigger.selector", err.Error())
	}
}

func TestFilterEligibleEvents_PodLookupFailurePropagates(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Pod); ok {
					return errors.New("apiserver down")
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: scheme}
	sch := triggerSchedule("fr", "obs", func(tr *podtracev1alpha1.TriggerSpec) {
		tr.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "checkout"}}
	})

	_, err := r.filterEligibleEvents(context.Background(), sch, []alertEvent{resourceAlertFor("prod", "checkout-1")})
	if err == nil {
		t.Fatal("a failing pod lookup must not be silently treated as a non-match")
		return
	}
	if !strings.Contains(err.Error(), "apiserver down") {
		t.Errorf("error %q should wrap the client failure", err.Error())
	}
}

func TestMapEventToTriggerSchedules_EnqueuesOnlyTriggerModeSchedules(t *testing.T) {
	r := triggerReconciler(t,
		triggerSchedule("flight-recorder", "obs"),
		cronSchedule("nightly", "obs"),
		triggerSchedule("other-ns-recorder", "team-a"),
	)

	reqs := r.mapEventToTriggerSchedules(context.Background(), podtraceAlertEvent("prod", "checkout-1"))
	if len(reqs) != 2 {
		t.Fatalf("want the 2 trigger-mode schedules, got %d: %v", len(reqs), reqs)
		return
	}
	names := map[string]bool{}
	for _, req := range reqs {
		names[req.Namespace+"/"+req.Name] = true
	}
	if !names["obs/flight-recorder"] || !names["team-a/other-ns-recorder"] {
		t.Errorf("unexpected enqueued set: %v", names)
	}
	if names["obs/nightly"] {
		t.Error("a cron-mode schedule must not be woken by an alert Event")
	}
}

func TestMapEventToTriggerSchedules_IgnoresNonAlertInput(t *testing.T) {
	r := triggerReconciler(t, triggerSchedule("flight-recorder", "obs"))

	scheduled := podtraceAlertEvent("prod", "checkout-1")
	scheduled.Reason = "Scheduled"

	cases := map[string]client.Object{
		"not an Event":     labelledPod("prod", "checkout-1", nil),
		"unrelated reason": scheduled,
	}
	for name, obj := range cases {
		t.Run(name, func(t *testing.T) {
			if reqs := r.mapEventToTriggerSchedules(context.Background(), obj); len(reqs) != 0 {
				t.Errorf("expected no requests, got %v", reqs)
			}
		})
	}
}

func TestMapEventToTriggerSchedules_ScheduleListFailureEnqueuesNothing(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(triggerSchedule("flight-recorder", "obs")).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.PodTraceScheduleList); ok {
					return errors.New("apiserver down")
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: scheme}

	if reqs := r.mapEventToTriggerSchedules(context.Background(), podtraceAlertEvent("prod", "checkout-1")); len(reqs) != 0 {
		t.Errorf("a failed list must enqueue nothing, got %v", reqs)
	}
}

func TestAlertEventPredicate_AcceptsOnlyPodtraceAlertEvents(t *testing.T) {
	p := alertEventPredicate()

	scheduled := podtraceAlertEvent("prod", "checkout-1")
	scheduled.Reason = "Scheduled"

	cases := []struct {
		name string
		obj  client.Object
		want bool
	}{
		{"podtrace alert Event", podtraceAlertEvent("prod", "checkout-1"), true},
		{"unrelated Event reason", scheduled, false},
		{"not an Event", labelledPod("prod", "checkout-1", nil), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Create(event.CreateEvent{Object: tc.obj}); got != tc.want {
				t.Errorf("Create() = %v, want %v", got, tc.want)
			}
			if got := p.Update(event.UpdateEvent{ObjectNew: tc.obj}); got != tc.want {
				t.Errorf("Update() = %v, want %v", got, tc.want)
			}
		})
	}
}
