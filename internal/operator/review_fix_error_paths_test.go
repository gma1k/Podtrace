package operator

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestApplySecret_DefaultsTypeToOpaque(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build()
	desired := desiredBundleSecret("v1")
	desired.Type = ""
	if err := applySecret(context.Background(), c, c, desired); err != nil {
		t.Fatal(err)
	}
	var got corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(desired), &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != corev1.SecretTypeOpaque {
		t.Errorf("type = %q, want Opaque", got.Type)
	}
}

func TestApplySecret_MissingLabelTriggersUpdate(t *testing.T) {
	writes := &secretWrites{}
	live := desiredBundleSecret("v1")
	live.Labels = nil
	c := secretApplyClient(t, writes, false, live)
	if err := applySecret(context.Background(), c, c, desiredBundleSecret("v1")); err != nil {
		t.Fatal(err)
	}
	if writes.updates != 1 {
		t.Errorf("a Secret missing a desired label must be updated, got %+v", writes)
	}
}

func TestApplySecret_ErrorsSurface(t *testing.T) {
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "bundle", errors.New("no update"))
	cases := map[string]interceptor.Funcs{
		"read": {Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errInternal()
		}},
		"replace delete": {
			Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error { return forbidden },
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				return errInternal()
			},
		},
		"replace create": {
			Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error { return forbidden },
			Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
				return errInternal()
			},
		},
	}
	for name, funcs := range cases {
		t.Run(name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(desiredBundleSecret("v1")).WithInterceptorFuncs(funcs).Build()
			if err := applySecret(context.Background(), c, c, desiredBundleSecret("v2")); err == nil {
				t.Errorf("a failed %s must be surfaced", name)
			}
		})
	}
}

func TestPodTraceReconcile_FleetListErrorIsReturned(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(ptMoreTrace(nil), ptMoreExporterConfig()).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.TracerConfigList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	if _, err := ptMoreReconcile(t, r); err == nil || !strings.Contains(err.Error(), "list TracerConfigs") {
		t.Fatalf("an unknown fleet set must not be written to; got %v", err)
	}
}

func TestPodTraceReconcile_WithdrawalFailureIsReturned(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := ptMoreTrace(nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(append([]client.Object{pt}, existingBundle(pt, ptMoreSysNS)...)...).
		WithInterceptorFuncs(failDeleteOf[*corev1.ConfigMap]()).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	if _, err := ptMoreReconcile(t, r); err == nil || !strings.Contains(err.Error(), "withdraw bundle") {
		t.Fatalf("a bundle that could not be withdrawn must be retried; got %v", err)
	}
}

func TestPodTraceReconcile_StaleCredentialSecretIsPruned(t *testing.T) {
	pt := ptMoreTrace(nil)
	r := newWithdrawalReconciler(t, append([]client.Object{pt, ptMoreExporterConfig()}, existingBundle(pt, ptMoreSysNS)...)...)
	if _, err := ptMoreReconcile(t, r); err != nil {
		t.Fatal(err)
	}
	var secret corev1.Secret
	if err := r.Get(context.Background(), client.ObjectKey{Namespace: ptMoreSysNS, Name: ExporterBundleName(pt.UID)}, &secret); err == nil {
		t.Error("an ExporterConfig that no longer references credentials must not leave the old ones in the bundle Secret")
	}
}

func TestPodTraceReconcile_StaleCredentialPruneErrorDegrades(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := ptMoreTrace(nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ptMoreExporterConfig()).WithInterceptorFuncs(failDeleteOf[*corev1.Secret]()).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	if _, err := ptMoreReconcile(t, r); err != nil {
		t.Fatal(err)
	}
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pt), &got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "BundleSync" || !strings.Contains(cond.Message, "prune stale bundle Secret") {
		t.Errorf("degraded condition = %+v, want BundleSync naming the prune", cond)
	}
}

func TestBundlePolicyError_Unwraps(t *testing.T) {
	inner := errors.New("spec.otlp is required")
	if err := error(&bundlePolicyError{err: inner}); !errors.Is(err, inner) {
		t.Error("bundlePolicyError must unwrap to the render error")
	}
}

func TestScheduleReconcile_NameTooLongStatusErrorIsReturned(t *testing.T) {
	name := strings.Repeat("s", 64)
	sch := cronSchedule(name, "default")
	r := newSchBranchReconciler(t, failStatusUpdate, sch)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("a status write that failed must be retried")
	}
}

func TestReplaceActiveSessions_KeepsWantedWhileReplacingOthers(t *testing.T) {
	now := metav1.Now().Time
	sch := triggerScheduleWithTemplate("fr", "obs", nil)
	ev := resourceAlertFor("obs", "hog-new")
	ev.At = now
	wanted := ownedSession(triggeredSessionName(sch.Name, ev.Namespace, ev.PodName, ev.At), "obs", sch)
	older := ownedSession("older", "obs", sch)
	other := resourceAlertFor("obs", "hog-other")
	other.At = now
	r := reconcileTriggerFixture(t, sch, interceptor.Funcs{}, &wanted, &older)

	if err := r.replaceActiveSessions(context.Background(), sch, []podtracev1alpha1.PodTraceSession{wanted, older}, []alertEvent{ev, other}); err != nil {
		t.Fatal(err)
	}
	var left podtracev1alpha1.PodTraceSessionList
	if err := r.List(context.Background(), &left, client.InNamespace("obs")); err != nil {
		t.Fatal(err)
	}
	if len(left.Items) != 1 || left.Items[0].Name != wanted.Name {
		t.Errorf("want only the session this pass keeps, got %d session(s)", len(left.Items))
	}
}

func TestSessionStateChangedPredicate_ForeignObjectsPass(t *testing.T) {
	pod := &corev1.Pod{}
	if !sessionStateChangedPredicate().Update(event.UpdateEvent{ObjectOld: pod, ObjectNew: pod}) {
		t.Error("an object that is not a session must not be filtered out")
	}
}
