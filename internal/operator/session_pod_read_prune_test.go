package operator

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEnsureSessionPodReadRBAC_RevokesNamespacesNoLongerTargeted(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := sessMoreSession(nil)
	stale := []client.Object{
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{
			Name: SessionPodReadRoleName(s.UID), Namespace: "withdrawn", Labels: sessionRBACLabels(s),
		}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
			Name: SessionPodReadRoleBindingName(s.UID), Namespace: "withdrawn", Labels: sessionRBACLabels(s),
		}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(stale...).Build()

	if err := ensureSessionPodReadRBAC(context.Background(), c, s, scheme, []string{"still-granted"}, []string{sessMoreSysNS}); err != nil {
		t.Fatalf("ensureSessionPodReadRBAC: %v", err)
	}

	var bindings rbacv1.RoleBindingList
	if err := c.List(context.Background(), &bindings); err != nil {
		t.Fatal(err)
	}
	if len(bindings.Items) != 1 || bindings.Items[0].Namespace != "still-granted" {
		t.Errorf("want only the still-granted RoleBinding, got %d binding(s)", len(bindings.Items))
	}
	var roles rbacv1.RoleList
	if err := c.List(context.Background(), &roles); err != nil {
		t.Fatal(err)
	}
	if len(roles.Items) != 1 || roles.Items[0].Namespace != "still-granted" {
		t.Errorf("want only the still-granted Role, got %d role(s)", len(roles.Items))
	}
}
