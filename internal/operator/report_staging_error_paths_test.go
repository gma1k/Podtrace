package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func stagingClient(t *testing.T, funcs interceptor.Funcs, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(objects...).WithInterceptorFuncs(funcs).Build()
}

func failCreateOf[T client.Object]() interceptor.Funcs {
	return interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(T); ok {
				return errInternal()
			}
			return cl.Create(ctx, obj, opts...)
		},
	}
}

func failDeleteOf[T client.Object]() interceptor.Funcs {
	return interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(T); ok {
				return errInternal()
			}
			return cl.Delete(ctx, obj, opts...)
		},
	}
}

func failSecretList() interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.SecretList); ok {
				return errInternal()
			}
			return cl.List(ctx, list, opts...)
		},
	}
}

func TestEnsureSessionReportStaging_ErrorsSurface(t *testing.T) {
	nodes := map[string][]string{sessMoreSysNS: {"n1"}}
	for name, funcs := range map[string]interceptor.Funcs{
		"staging Secret": failCreateOf[*corev1.Secret](),
		"Role":           failCreateOf[*rbacv1.Role](),
		"RoleBinding":    failCreateOf[*rbacv1.RoleBinding](),
	} {
		t.Run(name, func(t *testing.T) {
			c := stagingClient(t, funcs)
			if err := ensureSessionReportStaging(context.Background(), c, secretReportSession(), nodes); err == nil {
				t.Errorf("a failed %s create must be surfaced", name)
			}
		})
	}
}

func TestEnsureSessionReportStaging_ExistingStagingSecretIsKept(t *testing.T) {
	s := secretReportSession()
	c := stagingClient(t, interceptor.Funcs{}, stagedReport(s, "n1", "already written"))
	if err := ensureSessionReportStaging(context.Background(), c, s, map[string][]string{sessMoreSysNS: {"n1"}}); err != nil {
		t.Fatal(err)
	}
	var got corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: sessMoreSysNS, Name: SessionReportStagingName(s.UID, "n1")}, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Data["report-n1.txt"]) != "already written" {
		t.Error("a re-reconcile must not wipe a report the Job already staged")
	}
}

func TestPublishSessionSecretReport_ErrorsSurface(t *testing.T) {
	s := secretReportSession()
	cases := map[string]interceptor.Funcs{
		"staging list":   failSecretList(),
		"report create":  failCreateOf[*corev1.Secret](),
		"staging delete": failDeleteOf[*corev1.Secret](),
		"report target lookup": {
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if key.Namespace == s.Namespace {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		},
		"staging read": {
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if key.Namespace == sessMoreSysNS {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		},
	}
	for name, funcs := range cases {
		t.Run(name, func(t *testing.T) {
			c := stagingClient(t, funcs, stagedReport(s, "n1", "one"))
			if err := publishSessionSecretReport(context.Background(), c, c, s); err == nil {
				t.Errorf("a failed %s must be surfaced", name)
			}
		})
	}
}

func TestPublishSessionSecretReport_SkipsStagingSecretDeletedMeanwhile(t *testing.T) {
	s := secretReportSession()
	c := stagingClient(t, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if key.Name == SessionReportStagingName(s.UID, "n2") {
				return apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, key.Name)
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	}, stagedReport(s, "n1", "one"), stagedReport(s, "n2", "two"))

	if err := publishSessionSecretReport(context.Background(), c, c, s); err != nil {
		t.Fatalf("a staging Secret gone between list and read must be skipped: %v", err)
	}
	var report corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: s.Namespace, Name: "report"}, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Data) != 1 || string(report.Data["report-n1.txt"]) != "one" {
		t.Errorf("report data = %v, want only the readable node", report.Data)
	}
}

func TestCleanupSessionReportStaging_ErrorsSurface(t *testing.T) {
	s := secretReportSession()
	for name, funcs := range map[string]interceptor.Funcs{
		"staging list":   failSecretList(),
		"staging delete": failDeleteOf[*corev1.Secret](),
		"Role delete":    failDeleteOf[*rbacv1.Role](),
	} {
		t.Run(name, func(t *testing.T) {
			stagingRole := &rbacv1.Role{}
			stagingRole.Name, stagingRole.Namespace = SessionReportStagingRoleName(s.UID), sessMoreSysNS
			c := stagingClient(t, funcs, stagedReport(s, "n1", "one"), stagingRole)
			if err := cleanupSessionReportStaging(context.Background(), c, s, sessMoreSysNS); err == nil {
				t.Errorf("a failed %s must be surfaced", name)
			}
		})
	}
}

func TestCleanupPodTraceSessionChildren_StagingErrorSurfaces(t *testing.T) {
	s := secretReportSession()
	c := stagingClient(t, interceptor.Funcs{
		Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if obj.GetLabels()[LabelComponent] == ComponentReportStaging {
				return errInternal()
			}
			return cl.Delete(ctx, obj, opts...)
		},
	}, stagedReport(s, "n1", "one"))
	if err := cleanupPodTraceSessionChildren(context.Background(), c, s, sessMoreSysNS); err == nil {
		t.Error("a staging Secret the finalizer could not delete must block finalizer removal")
	}
}

func TestPublishSecretReport_SkipsNonSecretAndSettledSessions(t *testing.T) {
	r := &PodTraceSessionReconciler{}
	cm := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.ReportRef = &podtracev1alpha1.ReportReference{ConfigMap: &corev1.LocalObjectReference{Name: "r"}}
	})
	r.publishSecretReport(context.Background(), cm)
	if len(cm.Status.Conditions) != 0 {
		t.Error("a ConfigMap sink has nothing to publish")
	}
	settled := secretReportSession()
	settled.Status.Conditions = []metav1.Condition{{Type: ConditionReportUploaded, Status: metav1.ConditionFalse, Reason: reasonNothingStaged}}
	r.publishSecretReport(context.Background(), settled)
	if settled.Status.Conditions[0].Reason != reasonNothingStaged {
		t.Error("a settled report must not be retried")
	}
}
