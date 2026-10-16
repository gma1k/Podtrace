package operator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestReportObjectConflictError_Error(t *testing.T) {
	e := &reportObjectConflictError{namespace: "team-a", name: "shared", resource: "configmaps"}
	msg := e.Error()
	for _, want := range []string{"team-a", "shared", "configmaps", "already exists"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q missing %q", msg, want)
		}
	}
}

func TestEnsureSessionReportObject_SecretVariantCreatesNothingInTenantNamespace(t *testing.T) {
	scheme := newRBACScheme(t)
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sec-uid"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ReportRef: &podtracev1alpha1.ReportReference{Secret: &corev1.LocalObjectReference{Name: "report-secret"}},
		},
	}
	if err := ensureSessionReportObject(ctx, c, s); err != nil {
		t.Fatalf("ensureSessionReportObject(secret): %v", err)
	}
	var sec corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: "report-secret", Namespace: "team-a"}, &sec); err == nil {
		t.Fatal("a Secret report is published at the end of the session, not pre-created")
	}
}

func TestEnsureSessionReportObject_NoRefIsNoop(t *testing.T) {
	scheme := newRBACScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "u"}}
	if err := ensureSessionReportObject(context.Background(), c, s); err != nil {
		t.Fatalf("no-ref session should be a no-op, got %v", err)
	}
}

func TestCleanupSessionPodReadRBAC_DeletesMatchingOnly(t *testing.T) {
	scheme := newRBACScheme(t)
	ctx := context.Background()
	s := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "clean-1"}}
	labels := sessionRBACLabels(s)

	matchRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: SessionPodReadRoleName(s.UID), Namespace: "team-b", Labels: labels}}
	otherRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "unrelated-role", Namespace: "team-b", Labels: labels}}
	matchRB := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: SessionPodReadRoleBindingName(s.UID), Namespace: "team-b", Labels: labels}}
	otherRB := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "unrelated-rb", Namespace: "team-b", Labels: labels}}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(matchRole, otherRole, matchRB, otherRB).Build()
	if err := cleanupSessionPodReadRBAC(ctx, c, s); err != nil {
		t.Fatalf("cleanupSessionPodReadRBAC: %v", err)
	}

	if err := c.Get(ctx, client.ObjectKeyFromObject(matchRole), &rbacv1.Role{}); !apierrors.IsNotFound(err) {
		t.Errorf("matching Role should be deleted, got %v", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(matchRB), &rbacv1.RoleBinding{}); !apierrors.IsNotFound(err) {
		t.Errorf("matching RoleBinding should be deleted, got %v", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(otherRole), &rbacv1.Role{}); err != nil {
		t.Errorf("non-matching Role must survive: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(otherRB), &rbacv1.RoleBinding{}); err != nil {
		t.Errorf("non-matching RoleBinding must survive: %v", err)
	}
}

func TestCleanupSessionPodReadRBAC_ListErrors(t *testing.T) {
	scheme := newRBACScheme(t)
	s := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "e"}}
	cases := []struct {
		name string
		fail func(client.ObjectList) bool
	}{
		{"rolebindings", func(l client.ObjectList) bool { _, ok := l.(*rbacv1.RoleBindingList); return ok }},
		{"roles", func(l client.ObjectList) bool { _, ok := l.(*rbacv1.RoleList); return ok }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(scheme).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if tc.fail(list) {
							return errInternal()
						}
						return cl.List(ctx, list, opts...)
					},
				}).Build()
			if err := cleanupSessionPodReadRBAC(context.Background(), c, s); err == nil {
				t.Fatalf("expected error when listing %s fails", tc.name)
			}
		})
	}
}

func TestEnsureSessionPodReadRBAC_CreateErrors(t *testing.T) {
	scheme := newRBACScheme(t)
	s := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "pe"}}

	t.Run("role", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).
			WithInterceptorFuncs(interceptor.Funcs{
				Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if _, ok := obj.(*rbacv1.Role); ok {
						return errInternal()
					}
					return cl.Create(ctx, obj, opts...)
				},
			}).Build()
		if err := ensureSessionPodReadRBAC(context.Background(), c, s, scheme, []string{"team-b"}, []string{"podtrace-system"}); err == nil {
			t.Fatal("expected Role create error")
		}
	})

	t.Run("rolebinding", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).
			WithInterceptorFuncs(interceptor.Funcs{
				Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if _, ok := obj.(*rbacv1.RoleBinding); ok {
						return errInternal()
					}
					return cl.Create(ctx, obj, opts...)
				},
			}).Build()
		if err := ensureSessionPodReadRBAC(context.Background(), c, s, scheme, []string{"team-b"}, []string{"podtrace-system"}); err == nil {
			t.Fatal("expected RoleBinding create error")
		}
	})
}

func TestEnsureSessionReportRBAC_BindingCreateError(t *testing.T) {
	scheme := newRBACScheme(t)
	s := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "rb-err"}}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*rbacv1.RoleBinding); ok {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).Build()
	if err := ensureSessionReportRBAC(context.Background(), c, s, scheme, []string{"podtrace-system"}); err == nil {
		t.Fatal("expected RoleBinding create error from ensureSessionReportRBAC")
	}
}

func TestCleanupSessionServiceAccount_DeleteError(t *testing.T) {
	scheme := newRBACScheme(t)
	s := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sa-err"}}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: SessionServiceAccountName(s.UID), Namespace: "podtrace-system"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sa).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	if err := cleanupSessionServiceAccount(context.Background(), c, s, "podtrace-system"); err == nil {
		t.Fatal("expected SA delete error to propagate")
	}
}
