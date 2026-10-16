package operator

import (
	"context"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func interceptedSessionReconciler(t *testing.T, funcs interceptor.Funcs, objects ...client.Object) *PodTraceSessionReconciler {
	t.Helper()
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objects...).WithInterceptorFuncs(funcs).Build()
	return &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
}

func TestSessionReconcile_SecretSinkStagesBeforeFanOut(t *testing.T) {
	s := secretReportSession()
	r := frozenTargetsReconciler(t, append(sessMoreFanOutObjects(), s)...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var staged corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: SessionReportStagingName(s.UID, "n1"), Namespace: sessMoreSysNS}, &staged); err != nil {
		t.Fatalf("staging Secret for n1: %v", err)
	}
	var role rbacv1.Role
	if err := r.Get(context.Background(), types.NamespacedName{Name: SessionReportStagingRoleName(s.UID), Namespace: sessMoreSysNS}, &role); err != nil {
		t.Fatalf("staging Role: %v", err)
	}
	var report corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "report", Namespace: s.Namespace}, &report); err == nil {
		t.Error("the tenant Secret must not exist before the session ends")
	}
	var job batchv1.Job
	if err := r.Get(context.Background(), types.NamespacedName{Name: SessionJobName(s.UID, "n1"), Namespace: sessMoreSysNS}, &job); err != nil {
		t.Fatalf("session Job: %v", err)
	}
	if args := strings.Join(job.Spec.Template.Spec.Containers[0].Args, " "); !strings.Contains(args, "secret/$(POD_NAMESPACE)/"+SessionReportStagingName(s.UID, "n1")) {
		t.Errorf("Job reports to the wrong target: %s", args)
	}
}

func TestSessionReconcile_SecretSinkNamingForeignSecretFails(t *testing.T) {
	s := secretReportSession()
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "report", Namespace: s.Namespace}}
	r := frozenTargetsReconciler(t, append(sessMoreFanOutObjects(), s, foreign)...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if got.Status.State != podtracev1alpha1.SessionStateFailed || cond == nil || cond.Reason != "ReportObjectConflict" {
		t.Fatalf("state %q condition %+v, want Failed/ReportObjectConflict", got.Status.State, cond)
	}
}

func TestSessionReconcile_SecretSinkTargetLookupErrorRequeues(t *testing.T) {
	s := secretReportSession()
	r := interceptedSessionReconciler(t, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok && key.Name == "report" {
				return errInternal()
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	}, append(sessMoreFanOutObjects(), s)...)

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed lookup of the report target must be retried, not ignored")
	}
}

func TestSessionReconcile_SecretSinkStagingErrorDegrades(t *testing.T) {
	s := secretReportSession()
	r := interceptedSessionReconciler(t, interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				return errInternal()
			}
			return cl.Create(ctx, obj, opts...)
		},
	}, append(sessMoreFanOutObjects(), s)...)

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed staging setup must be returned for a retry")
	}
	got := (&fakeGetter{r: r}).session(t)
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "SessionRBAC" {
		t.Errorf("degraded condition = %+v, want SessionRBAC", cond)
	}
}

func terminalSecretSession() *podtracev1alpha1.PodTraceSession {
	s := secretReportSession()
	completed := metav1.Now()
	s.Status.State = podtracev1alpha1.SessionStateCompleted
	s.Status.CompletionTime = &completed
	return s
}

func failingStagedReads() interceptor.Funcs {
	return interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok && key.Namespace == sessMoreSysNS {
				return errInternal()
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	}
}

func TestSessionReconcile_FailedPublishIsRetried(t *testing.T) {
	s := terminalSecretSession()
	r := interceptedSessionReconciler(t, failingStagedReads(), s, stagedReport(s, "n1", "one"))

	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter != 10*time.Second {
		t.Errorf("requeueAfter = %v, want a 10s publish retry", res.RequeueAfter)
	}
	got := (&fakeGetter{r: r}).session(t)
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionReportUploaded)
	if cond == nil || cond.Reason != "PublishFailed" {
		t.Errorf("ReportUploaded = %+v, want PublishFailed", cond)
	}
}

func TestSessionReconcile_PublishStatusWriteErrorSurfaces(t *testing.T) {
	s := terminalSecretSession()
	r := interceptedSessionReconciler(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			return errInternal()
		},
	}, s, stagedReport(s, "n1", "one"))

	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("a failed status write after publishing must be returned")
	}
}

func TestSessionReconcile_SettledSecretReportIsNotRepublished(t *testing.T) {
	s := terminalSecretSession()
	s.Status.Conditions = []metav1.Condition{{Type: ConditionReportUploaded, Status: metav1.ConditionTrue, Reason: "Published"}}
	r := interceptedSessionReconciler(t, failingStagedReads(), s, stagedReport(s, "n1", "one"))

	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter <= 10*time.Second {
		t.Errorf("requeueAfter = %v; a published report must only wait for its TTL", res.RequeueAfter)
	}
}

func TestSessionReconcile_ForeignSecretAppearingMidSessionIsNotOverwritten(t *testing.T) {
	s := terminalSecretSession()
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "report", Namespace: s.Namespace},
		Data:       map[string][]byte{"password": []byte("hunter2")},
	}
	r := frozenTargetsReconciler(t, s, foreign, stagedReport(s, "n1", "one"))

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionReportUploaded)
	if cond == nil || cond.Reason != reasonReportObjectConflict || !secretReportSettled(&got) {
		t.Fatalf("ReportUploaded = %+v, want a settled ReportObjectConflict", cond)
	}
	var kept corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "report", Namespace: s.Namespace}, &kept); err != nil {
		t.Fatal(err)
	}
	if string(kept.Data["password"]) != "hunter2" {
		t.Error("a Secret created by someone else mid-session must be left untouched")
	}
}
