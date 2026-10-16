package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func findingsScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, rbacv1.AddToScheme, podtracev1alpha1.AddToScheme,
	} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func hasFlagValue(args []string, flag, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return true
		}
	}
	return false
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func TestBuildDiagnoseArgs_MultiNamespace(t *testing.T) {
	s := newSession(nil)

	multi := buildDiagnoseArgs(s, sessionTargets{Namespaces: []string{"team-a", "team-b"}, PodRefs: s.Spec.PodRefs}, s.Spec.Duration.Duration)
	if !hasFlagValue(multi, "--namespaces", "team-a,team-b") {
		t.Errorf("expected --namespaces team-a,team-b; got %v", multi)
	}
	if hasFlagValue(multi, "--namespace", "default") {
		t.Errorf("must not pin to the session namespace when an allowlist is resolved; got %v", multi)
	}

	own := buildDiagnoseArgs(s, sessionTargets{PodRefs: s.Spec.PodRefs}, s.Spec.Duration.Duration)
	if !hasFlagValue(own, "--namespace", "default") {
		t.Errorf("expected --namespace default for own-namespace scope; got %v", own)
	}
	if hasFlag(own, "--namespaces") {
		t.Errorf("must not emit --namespaces when no allowlist is resolved; got %v", own)
	}
}

func TestSessionPodNamespaces(t *testing.T) {
	s := newSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.PodRefs = []podtracev1alpha1.PodRef{
			{Namespace: "team-c", Name: "p1"},
			{Namespace: "default", Name: "p2"},
			{Name: "p3"},
		}
	})
	got := sessionPodNamespaces(s, sessionTargets{Namespaces: []string{"team-a", "team-b", "default"}, PodRefs: s.Spec.PodRefs})
	want := map[string]bool{"team-a": true, "team-b": true, "team-c": true}
	if len(got) != len(want) {
		t.Fatalf("got %v want keys %v", got, want)
	}
	for _, ns := range got {
		if !want[ns] {
			t.Errorf("unexpected namespace %q (own ns must be excluded): %v", ns, got)
		}
	}
}

func TestEnsureSessionPodReadRBAC(t *testing.T) {
	scheme := findingsScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newSession(nil)
	const systemNS = "podtrace-system"

	if err := ensureSessionPodReadRBAC(context.Background(), c, s, scheme, []string{"team-a", "team-b"}, []string{systemNS}); err != nil {
		t.Fatal(err)
	}

	for _, ns := range []string{"team-a", "team-b"} {
		var role rbacv1.Role
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: SessionPodReadRoleName(s.UID)}, &role); err != nil {
			t.Fatalf("pod-read Role missing in %s: %v", ns, err)
		}
		if !roleAllowsPods(role.Rules) {
			t.Errorf("pod-read Role in %s does not grant pods read: %+v", ns, role.Rules)
		}
		var rb rbacv1.RoleBinding
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: SessionPodReadRoleBindingName(s.UID)}, &rb); err != nil {
			t.Fatalf("pod-read RoleBinding missing in %s: %v", ns, err)
		}
		if len(rb.Subjects) != 1 || rb.Subjects[0].Namespace != systemNS || rb.Subjects[0].Name != SessionServiceAccountName(s.UID) {
			t.Errorf("RoleBinding in %s bound to wrong subject: %+v", ns, rb.Subjects)
		}
	}

	if err := cleanupSessionPodReadRBAC(context.Background(), c, s); err != nil {
		t.Fatal(err)
	}
	var leftover rbacv1.RoleList
	if err := c.List(context.Background(), &leftover); err != nil {
		t.Fatal(err)
	}
	for i := range leftover.Items {
		if leftover.Items[i].Name == SessionPodReadRoleName(s.UID) {
			t.Errorf("pod-read Role in %s survived cleanup", leftover.Items[i].Namespace)
		}
	}
}

func roleAllowsPods(rules []rbacv1.PolicyRule) bool {
	for _, r := range rules {
		for _, res := range r.Resources {
			if res == "pods" {
				return true
			}
		}
	}
	return false
}

func TestTracerConfigToPodTraces(t *testing.T) {
	pt1 := &podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns1"}}
	pt2 := &podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns2"}}
	c := fake.NewClientBuilder().WithScheme(findingsScheme(t)).WithObjects(pt1, pt2).Build()
	r := &PodTraceReconciler{Client: c}

	def := &podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	if got := r.tracerConfigToPodTraces(context.Background(), def); len(got) != 2 {
		t.Errorf("default TracerConfig should enqueue all PodTraces; got %d", len(got))
	}
	other := &podtracev1alpha1.TracerConfig{ObjectMeta: metav1.ObjectMeta{Name: "other"}}
	if got := r.tracerConfigToPodTraces(context.Background(), other); len(got) != 2 {
		t.Errorf("a non-default fleet should enqueue all PodTraces; got %d", len(got))
	}
}

func TestCleanupOrphanBundles(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "user", UID: "u1"}}
	name := ExporterBundleName(pt.UID)
	lbls := map[string]string{
		LabelManagedBy:    ManagedByValue,
		LabelComponent:    ComponentBundle,
		LabelPodTraceName: pt.Name,
		LabelPodTraceNS:   pt.Namespace,
	}
	var objs []client.Object
	for _, ns := range []string{"sys-a", "sys-b", "sys-c"} {
		objs = append(objs,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: lbls}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: lbls}},
		)
	}
	c := fake.NewClientBuilder().WithScheme(findingsScheme(t)).WithObjects(objs...).Build()

	if err := cleanupOrphanBundles(context.Background(), c, pt, "sys-c"); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"sys-a", "sys-b"} {
		var cm corev1.ConfigMap
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &cm); err == nil {
			t.Errorf("orphan bundle ConfigMap in %s survived", ns)
		}
		var sec corev1.Secret
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &sec); err == nil {
			t.Errorf("orphan bundle Secret in %s survived (credential leak)", ns)
		}
	}
	var keep corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "sys-c", Name: name}, &keep); err != nil {
		t.Errorf("current bundle Secret in sys-c was wrongly deleted: %v", err)
	}
}
