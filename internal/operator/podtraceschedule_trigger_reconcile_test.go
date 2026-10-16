package operator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func triggerScheduleWithTemplate(name, namespace string, mutate func(*podtracev1alpha1.PodTraceSchedule)) *podtracev1alpha1.PodTraceSchedule {
	sch := triggerSchedule(name, namespace)
	sch.Spec.SessionTemplate = podtracev1alpha1.PodTraceSessionTemplateSpec{
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "tgt"}},
			Duration:    metav1.Duration{Duration: 20 * time.Second},
			ExporterRef: corev1.LocalObjectReference{Name: "sch-otlp"},
		},
	}
	if mutate != nil {
		mutate(sch)
	}
	return sch
}

func consentNamespace(name, grant string, labels map[string]string) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
	if grant != "" {
		ns.Annotations = map[string]string{podtracev1alpha1.AllowTracingFromAnnotation: grant}
	}
	return ns
}

func ownedSession(name, namespace string, sch *podtracev1alpha1.PodTraceSchedule) podtracev1alpha1.PodTraceSession {
	controller := true
	return podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: podtracev1alpha1.GroupVersion.String(),
				Kind:       "PodTraceSchedule",
				Name:       sch.Name,
				UID:        sch.UID,
				Controller: &controller,
			}},
		},
	}
}

func reconcileTriggerFixture(t *testing.T, sch *podtracev1alpha1.PodTraceSchedule, funcs interceptor.Funcs, extra ...client.Object) *PodTraceScheduleReconciler {
	t.Helper()
	scheme := newOperatorScheme(t)
	objects := append([]client.Object{sch}, extra...)
	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithObjects(objects...)
	if funcs.Get != nil || funcs.List != nil || funcs.Create != nil || funcs.Delete != nil {
		builder = builder.WithInterceptorFuncs(funcs)
	}
	return &PodTraceScheduleReconciler{Client: builder.Build(), Scheme: scheme}
}

func storedAlertEvent(namespace, pod, uid string, at time.Time) *corev1.Event {
	ev := podtraceAlertEvent(namespace, pod)
	ev.UID = types.UID(uid)
	ev.LastTimestamp = metav1.NewTime(at)
	return ev
}

func TestReconcileTrigger_InvalidNamespaceSelectorDegrades(t *testing.T) {
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.NamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "tier", Operator: "Bogus", Values: []string{"prod"}},
			},
		}
	})
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{})

	res, err := r.reconcileTrigger(context.Background(), sch, nil, nil, nil, time.Now())
	if err != nil {
		t.Fatalf("an invalid selector must degrade, not error out: %v", err)
	}
	if res.RequeueAfter != triggerResyncInterval {
		t.Errorf("requeueAfter = %v, want %v", res.RequeueAfter, triggerResyncInterval)
	}
	cond := findCondition(sch.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "NamespaceSelectorInvalid" {
		t.Errorf("want Degraded=True/NamespaceSelectorInvalid, got %+v", cond)
	}
}

func TestReconcileTrigger_DeniedNamespacesSurfaceOnCondition(t *testing.T) {
	prod := map[string]string{"tier": "prod"}
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.NamespaceSelector = &metav1.LabelSelector{MatchLabels: prod}
	})
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{},
		consentNamespace("obs", "", nil),
		consentNamespace("team-a", "obs", prod),
		consentNamespace("team-b", "", prod),
	)

	if _, err := r.reconcileTrigger(context.Background(), sch, nil, nil, nil, time.Now()); err != nil {
		t.Fatalf("reconcileTrigger: %v", err)
	}
	cond := findCondition(sch.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "SomeNamespacesDenied" {
		t.Fatalf("want Degraded=False/SomeNamespacesDenied, got %+v", cond)
		return
	}
	if !strings.Contains(cond.Message, "team-b") {
		t.Errorf("message should name the non-consenting namespace, got %q", cond.Message)
	}
	if strings.Contains(cond.Message, "team-a") {
		t.Errorf("consenting namespace must not be reported as denied: %q", cond.Message)
	}
}

func TestReconcileTrigger_EventListFailurePropagates(t *testing.T) {
	sch := triggerScheduleWithTemplate("fr", "obs", nil)
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.EventList); ok {
				return errors.New("apiserver down")
			}
			return cl.List(ctx, list, opts...)
		},
	})

	_, err := r.reconcileTrigger(context.Background(), sch, nil, nil, nil, time.Now())
	if err == nil {
		t.Fatal("a failed Event list must surface as a reconcile error")
		return
	}
	if !strings.Contains(err.Error(), "list events in obs") {
		t.Errorf("error %q should name the namespace it failed to list", err.Error())
	}
}

func TestReconcileTrigger_InvalidPodSelectorPropagates(t *testing.T) {
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.Selector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "app", Operator: "Bogus", Values: []string{"x"}},
			},
		}
	})
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{})

	_, err := r.reconcileTrigger(context.Background(), sch, nil, nil, nil, time.Now())
	if err == nil {
		t.Fatal("a malformed pod selector must surface as a reconcile error")
		return
	}
	if !strings.Contains(err.Error(), "spec.trigger.selector") {
		t.Errorf("error %q should name spec.trigger.selector", err.Error())
	}
}

func TestReconcileTrigger_HistoryLimitFailurePropagates(t *testing.T) {
	limit := int32(0)
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.SuccessfulSessionsHistoryLimit = &limit
	})
	succeeded := []podtracev1alpha1.PodTraceSession{ownedSession("old-session", "obs", sch)}
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			return errors.New("apiserver down")
		},
	}, &succeeded[0])

	_, err := r.reconcileTrigger(context.Background(), sch, nil, succeeded, nil, time.Now())
	if err == nil {
		t.Fatal("a failed history GC must surface as a reconcile error")
		return
	}
	if !strings.Contains(err.Error(), "gc successful") {
		t.Errorf("error %q should identify the history-limit GC", err.Error())
	}
}

func TestReconcileTrigger_ReplaceDeleteFailurePropagates(t *testing.T) {
	now := time.Now()
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.ConcurrencyPolicy = podtracev1alpha1.ReplaceConcurrent
	})
	active := []podtracev1alpha1.PodTraceSession{ownedSession("running", "obs", sch)}
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			return errors.New("apiserver down")
		},
	}, &active[0], storedAlertEvent("obs", "hog-a", "uid-a", now.Add(-time.Minute)))

	_, err := r.reconcileTrigger(context.Background(), sch, active, nil, nil, now)
	if err == nil {
		t.Fatal("a failed Replace delete must surface as a reconcile error")
		return
	}
	if !strings.Contains(err.Error(), "replace: delete active session running") {
		t.Errorf("error %q should name the session it could not replace", err.Error())
	}
}

func TestReconcileTrigger_ReplaceKeepsActiveSessionWithoutNewAlert(t *testing.T) {
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.ConcurrencyPolicy = podtracev1alpha1.ReplaceConcurrent
	})
	active := []podtracev1alpha1.PodTraceSession{ownedSession("running", "obs", sch)}
	deletes := 0
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			deletes++
			return cl.Delete(ctx, obj, opts...)
		},
	}, &active[0])

	if _, err := r.reconcileTrigger(context.Background(), sch, active, nil, nil, time.Now()); err != nil {
		t.Fatalf("reconcileTrigger: %v", err)
	}
	if deletes != 0 {
		t.Errorf("a pass with nothing to fire deleted %d active session(s)", deletes)
	}
}

func TestReconcileTrigger_ReplaceKeepsSessionItJustFired(t *testing.T) {
	now := time.Now()
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.ConcurrencyPolicy = podtracev1alpha1.ReplaceConcurrent
	})
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{},
		storedAlertEvent("obs", "hog-a", "uid-a", now.Add(-time.Minute)))

	if _, err := r.reconcileTrigger(context.Background(), sch, nil, nil, nil, now); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(context.Background(), &sessions, client.InNamespace("obs")); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Items) != 1 {
		t.Fatalf("want 1 fired session, got %d", len(sessions.Items))
	}

	if _, err := r.reconcileTrigger(context.Background(), sch, sessions.Items, nil, nil, now.Add(5*time.Second)); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if err := r.List(context.Background(), &sessions, client.InNamespace("obs")); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Items) != 1 {
		t.Errorf("the resync after firing must keep the fired session, got %d", len(sessions.Items))
	}
}

func TestReconcileTrigger_ReplaceToleratesAlreadyDeletedSession(t *testing.T) {
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.ConcurrencyPolicy = podtracev1alpha1.ReplaceConcurrent
	})
	active := []podtracev1alpha1.PodTraceSession{ownedSession("running", "obs", sch)}
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			return apierrors.NewNotFound(schema.GroupResource{Group: "podtrace.io", Resource: "podtracesessions"}, "running")
		},
	}, &active[0])

	if _, err := r.reconcileTrigger(context.Background(), sch, active, nil, nil, time.Now()); err != nil {
		t.Errorf("a session already gone must not fail the pass: %v", err)
	}
}

func TestReconcileTrigger_SessionCreateFailureSkipsEvent(t *testing.T) {
	now := time.Now()
	sch := triggerScheduleWithTemplate("fr", "obs", nil)
	creates := 0
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
				creates++
				if creates == 1 {
					return errors.New("admission webhook rejected")
				}
			}
			return cl.Create(ctx, obj, opts...)
		},
	},
		storedAlertEvent("obs", "hog-a", "uid-a", now.Add(-2*time.Minute)),
		storedAlertEvent("obs", "hog-b", "uid-b", now.Add(-time.Minute)))

	if _, err := r.reconcileTrigger(context.Background(), sch, nil, nil, nil, now); err != nil {
		t.Fatalf("one rejected event must not fail the pass: %v", err)
	}
	cond := findCondition(sch.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "CreateSession" {
		t.Errorf("want Degraded=True/CreateSession, got %+v", cond)
	}
	firings := triggerFirings(sch)
	if len(firings) != 1 || firings[0].PodName != "hog-b" {
		t.Errorf("the alert queued behind the rejected one must still fire, got %+v", firings)
	}
}

func TestReconcileTrigger_TerminatingNamespaceStopsQuietly(t *testing.T) {
	now := time.Now()
	sch := triggerScheduleWithTemplate("fr", "obs", nil)
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
				return apierrors.NewForbidden(
					schema.GroupResource{Group: "podtrace.io", Resource: "podtracesessions"},
					"fr-session",
					errors.New("unable to create new content in namespace obs because it is being terminated"))
			}
			return cl.Create(ctx, obj, opts...)
		},
	}, storedAlertEvent("obs", "hog-a", "uid-a", now.Add(-time.Minute)))

	res, err := r.reconcileTrigger(context.Background(), sch, nil, nil, nil, now)
	if err != nil {
		t.Errorf("a terminating namespace must not be retried as an error: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("requeueAfter = %v, want no requeue for a terminating namespace", res.RequeueAfter)
	}
}

func TestReconcileTrigger_ForbidWithoutPriorFiringsInitialisesStatus(t *testing.T) {
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.ConcurrencyPolicy = podtracev1alpha1.ForbidConcurrent
	})
	active := []podtracev1alpha1.PodTraceSession{ownedSession("running", "obs", sch)}
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{}, &active[0])

	if _, err := r.reconcileTrigger(context.Background(), sch, active, nil, nil, time.Now()); err != nil {
		t.Fatalf("reconcileTrigger: %v", err)
	}
	if sch.Status.Trigger == nil {
		t.Fatal("an early Forbid return must still initialise status.trigger")
		return
	}
	if len(sch.Status.Trigger.RecentFirings) != 0 {
		t.Errorf("recentFirings = %+v, want empty", sch.Status.Trigger.RecentFirings)
	}
	cond := findCondition(sch.Status.Conditions, ConditionReconciled)
	if cond == nil || cond.Reason != "Forbidden" {
		t.Errorf("want Reconciled/Forbidden, got %+v", cond)
	}
}

func TestReconcileTrigger_TemplateMetadataMergesIntoSession(t *testing.T) {
	now := time.Now()
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.SessionTemplate.Metadata = podtracev1alpha1.PodTraceSessionTemplateMetadata{
			Labels:      map[string]string{"team": "payments"},
			Annotations: map[string]string{"runbook": "https://example.invalid/oom"},
		}
	})
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{},
		storedAlertEvent("obs", "hog-a", "uid-a", now.Add(-time.Minute)))

	if _, err := r.reconcileTrigger(context.Background(), sch, nil, nil, nil, now); err != nil {
		t.Fatalf("reconcileTrigger: %v", err)
	}

	var list podtracev1alpha1.PodTraceSessionList
	if err := r.List(context.Background(), &list, client.InNamespace("obs")); err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("want 1 session, got %d", len(list.Items))
		return
	}
	session := list.Items[0]
	if session.Labels["team"] != "payments" {
		t.Errorf("template label lost, labels = %v", session.Labels)
	}
	if session.Labels["podtrace.io/schedule"] != "fr" {
		t.Errorf("operator label missing, labels = %v", session.Labels)
	}
	if session.Annotations["runbook"] != "https://example.invalid/oom" {
		t.Errorf("template annotation lost, annotations = %v", session.Annotations)
	}
	if session.Annotations["podtrace.io/triggered-by"] != string(podtracev1alpha1.TriggerSourceResourceAlert) {
		t.Errorf("trigger annotation missing, annotations = %v", session.Annotations)
	}
}

func TestListAlertEvents_SkipsNonAlertsAndDeduplicates(t *testing.T) {
	now := time.Now()
	sch := triggerScheduleWithTemplate("fr", "obs", nil)

	scheduled := podtraceAlertEvent("obs", "hog-b")
	scheduled.Name = "scheduled-hog-b"
	scheduled.Reason = "Scheduled"

	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{},
		storedAlertEvent("obs", "hog-a", "uid-a", now),
		scheduled,
	)

	got, err := r.listAlertEvents(context.Background(), []string{"obs", "obs"})
	if err != nil {
		t.Fatalf("listAlertEvents: %v", err)
		return
	}
	if len(got) != 1 || got[0].PodName != "hog-a" {
		t.Errorf("want a single deduplicated hog-a alert, got %v", eventPodNames(got))
	}
}

func TestListAlertEvents_DeduplicatesEventsWithoutUID(t *testing.T) {
	now := time.Now()
	sch := triggerScheduleWithTemplate("fr", "obs", nil)

	first := podtraceAlertEvent("obs", "hog-a")
	first.Name = "alert-hog-a-1"
	first.LastTimestamp = metav1.NewTime(now)
	second := podtraceAlertEvent("obs", "hog-a")
	second.Name = "alert-hog-a-2"
	second.LastTimestamp = metav1.NewTime(now)

	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{}, first, second)

	got, err := r.listAlertEvents(context.Background(), []string{"obs"})
	if err != nil {
		t.Fatalf("listAlertEvents: %v", err)
		return
	}
	if len(got) != 1 {
		t.Errorf("identical UID-less alerts must collapse to one, got %v", eventPodNames(got))
	}
}

func TestTriggerNamespaces_SelectorAlwaysIncludesOwnNamespace(t *testing.T) {
	prod := map[string]string{"tier": "prod"}
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.NamespaceSelector = &metav1.LabelSelector{MatchLabels: prod}
	})
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{},
		consentNamespace("obs", "", nil),
		consentNamespace("team-a", "obs", prod),
		consentNamespace("team-b", "", prod),
	)

	allowed, denied, err := r.triggerNamespaces(context.Background(), sch)
	if err != nil {
		t.Fatalf("triggerNamespaces: %v", err)
		return
	}
	if !containsString(allowed, "obs") {
		t.Errorf("the schedule's own namespace must always be allowed, got %v", allowed)
	}
	if !containsString(allowed, "team-a") {
		t.Errorf("consenting namespace missing from allowed, got %v", allowed)
	}
	if containsString(allowed, "team-b") {
		t.Errorf("non-consenting namespace must not be allowed, got %v", allowed)
	}
	if !containsString(denied, "team-b") {
		t.Errorf("non-consenting namespace must be reported denied, got %v", denied)
	}
}

func TestTriggerNamespaces_WithoutSelectorIsOwnNamespaceOnly(t *testing.T) {
	sch := triggerScheduleWithTemplate("fr", "obs", nil)
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{}, consentNamespace("team-a", "obs", nil))

	allowed, denied, err := r.triggerNamespaces(context.Background(), sch)
	if err != nil {
		t.Fatalf("triggerNamespaces: %v", err)
		return
	}
	if len(allowed) != 1 || allowed[0] != "obs" {
		t.Errorf("allowed = %v, want only obs", allowed)
	}
	if len(denied) != 0 {
		t.Errorf("denied = %v, want none", denied)
	}
}

func TestTriggerNamespaces_InvalidSelectorErrors(t *testing.T) {
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.NamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "tier", Operator: "Bogus", Values: []string{"prod"}},
			},
		}
	})
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{})

	if _, _, err := r.triggerNamespaces(context.Background(), sch); err == nil {
		t.Error("expected an error for a malformed namespace selector")
	}
}

func TestReconcileTrigger_ReplaceKeepsSessionWhenFiringNotYetCached(t *testing.T) {
	now := time.Now()
	sch := triggerScheduleWithTemplate("fr", "obs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Trigger.ConcurrencyPolicy = podtracev1alpha1.ReplaceConcurrent
	})
	alert := storedAlertEvent("obs", "hog-a", "uid-a", now.Add(-time.Minute))
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{}, alert)

	if _, err := r.reconcileTrigger(context.Background(), sch, nil, nil, nil, now); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(context.Background(), &sessions, client.InNamespace("obs")); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Items) != 1 {
		t.Fatalf("want 1 fired session, got %d", len(sessions.Items))
	}
	sessions.Items[0].Finalizers = []string{FinalizerCleanup}
	if err := r.Update(context.Background(), &sessions.Items[0]); err != nil {
		t.Fatal(err)
	}

	stale := sch.DeepCopy()
	stale.Status.Trigger = nil
	if _, err := r.reconcileTrigger(context.Background(), stale, sessions.Items, nil, nil, now.Add(time.Second)); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	var after podtracev1alpha1.PodTraceSessionList
	if err := r.List(context.Background(), &after, client.InNamespace("obs")); err != nil {
		t.Fatal(err)
	}
	if len(after.Items) != 1 || after.Items[0].DeletionTimestamp != nil {
		t.Errorf("a pass that has not yet seen its own firing must not delete the session it started, got %+v", after.Items)
	}
}
