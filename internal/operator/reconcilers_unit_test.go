package operator

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func newOperatorScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("clientgoscheme: %v", err)
	}
	if err := podtracev1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("podtrace AddToScheme: %v", err)
	}
	return s
}

func TestNamingHelpers(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"AgentDaemonSetName", AgentDaemonSetName(DefaultTracerConfigName), "podtrace-agent"},
		{"AgentClusterRoleName", AgentClusterRoleName(DefaultTracerConfigName), "podtrace-agent"},
		{"AgentClusterRoleBindingName", AgentClusterRoleBindingName(DefaultTracerConfigName), "podtrace-agent"},
		{"AgentBundleRoleName", AgentBundleRoleName(DefaultTracerConfigName), "podtrace-agent-bundles"},
		{"AgentBundleRoleBindingName", AgentBundleRoleBindingName(DefaultTracerConfigName), "podtrace-agent-bundles"},
		{"AgentServiceAccountName", AgentServiceAccountName(DefaultTracerConfigName), "podtrace-agent"},
		{"OperatorWebhookServiceName", OperatorWebhookServiceName(), "podtrace-webhook"},
		{"SessionServiceAccountName", SessionServiceAccountName("abcdef012345xyz"), "podtrace-session-abcdef012345"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestDefaultControllerOptions(t *testing.T) {
	opts := defaultControllerOptions()
	if opts.MaxConcurrentReconciles != 1 {
		t.Errorf("MaxConcurrentReconciles = %d, want 1", opts.MaxConcurrentReconciles)
	}
}

func TestEnsureAndRemoveFinalizer(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{}
	if !ensureFinalizer(pt) {
		t.Fatal("ensureFinalizer should return true on first call")
	}
	if ensureFinalizer(pt) {
		t.Fatal("ensureFinalizer should return false on second call (already present)")
	}
	if !removeFinalizer(pt) {
		t.Fatal("removeFinalizer should return true when present")
	}
	if removeFinalizer(pt) {
		t.Fatal("removeFinalizer should return false when not present")
	}
}

func TestCleanupPodTraceChildren(t *testing.T) {
	const sysNS = "podtrace-system"
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default", UID: "uid-1"},
	}
	bundleName := ExporterBundleName(pt.UID)

	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: sysNS}}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: sysNS}}

	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(cm, sec).Build()

	if err := cleanupPodTraceChildren(context.Background(), c, pt, sysNS); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: bundleName, Namespace: sysNS}, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
		t.Errorf("ConfigMap not deleted: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: bundleName, Namespace: sysNS}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Errorf("Secret not deleted: %v", err)
	}

	if err := cleanupPodTraceChildren(context.Background(), c, pt, sysNS); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
}

func TestCleanupPodTraceSessionChildren(t *testing.T) {
	const sysNS = "podtrace-system"
	const userNS = "team-a"

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "sess", Namespace: userNS, UID: "uid-s"},
	}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SessionJobName(s.UID, "n1"),
			Namespace: sysNS,
			UID:       "uid-job",
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: s.Name,
				LabelSessionNS:   s.Namespace,
				LabelNodeName:    "n1",
			},
		},
	}
	bundleName := SessionBundleName(s.UID)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: sysNS}}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: sysNS}}

	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(job, cm, sec).Build()

	if err := cleanupPodTraceSessionChildren(context.Background(), c, s, sysNS); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	if err := c.Get(context.Background(), types.NamespacedName{Name: job.Name, Namespace: sysNS}, &batchv1.Job{}); !apierrors.IsNotFound(err) {
		t.Errorf("Job not deleted: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: bundleName, Namespace: sysNS}, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
		t.Errorf("Bundle ConfigMap not deleted: %v", err)
	}

	if err := cleanupPodTraceSessionChildren(context.Background(), c, s, sysNS); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
}

func TestPodTraceReconciler_NotFound(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build()
	r := &PodTraceReconciler{Client: c, Scheme: newOperatorScheme(t), SystemNamespace: "podtrace-system"}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing", Namespace: "ns"},
	})
	if err != nil {
		t.Fatalf("expected nil error for not-found, got %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("expected zero result, got %+v", res)
	}
}

func TestPodTraceReconciler_FinalizerAddedThenReconciled(t *testing.T) {
	const sysNS, ns = "podtrace-system", "default"
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: "uid-1"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			ExporterRef: corev1.LocalObjectReference{Name: "ec"},
		},
	}
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: ns},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP,
			},
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ec).Build()

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns}}

	res, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("1st reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("expected Requeue=true after finalizer add")
	}
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Fatal("finalizer should have been added")
	}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("2nd reconcile: %v", err)
	}

	var bundle corev1.ConfigMap
	bundleName := ExporterBundleName(pt.UID)
	if err := c.Get(context.Background(), types.NamespacedName{Name: bundleName, Namespace: sysNS}, &bundle); err != nil {
		t.Fatalf("bundle not created: %v", err)
	}
	if bundle.Data["type"] != "otlp" || bundle.Data["endpoint"] != "otel.default.svc:4318" {
		t.Errorf("bundle data wrong: %+v", bundle.Data)
	}
}

func TestPodTraceReconciler_ExporterNotFound(t *testing.T) {
	const sysNS, ns = "podtrace-system", "default"
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pt", Namespace: ns, UID: "uid-1",
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			ExporterRef: corev1.LocalObjectReference{Name: "missing-ec"},
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt).Build()

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got podtracev1alpha1.PodTrace
	_ = c.Get(context.Background(), client.ObjectKeyFromObject(pt), &got)
	if !hasCondition(got.Status.Conditions, ConditionDegraded, metav1.ConditionTrue) {
		t.Errorf("expected Degraded=True, got %+v", got.Status.Conditions)
	}
}

func TestPodTraceReconciler_PausedSetsCondition(t *testing.T) {
	const sysNS, ns = "podtrace-system", "default"
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pt", Namespace: ns, UID: "uid-1",
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			ExporterRef: corev1.LocalObjectReference{Name: "ec"},
			Paused:      true,
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt).Build()

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pt), &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, ConditionPaused, metav1.ConditionTrue) {
		t.Errorf("expected Paused=True, got %+v", got.Status.Conditions)
	}
	if !hasCondition(got.Status.Conditions, ConditionReady, metav1.ConditionFalse) {
		t.Errorf("expected Ready=False (paused), got %+v", got.Status.Conditions)
	}
}

func TestPodTraceReconciler_DeletionRunsCleanup(t *testing.T) {
	const sysNS, ns = "podtrace-system", "default"
	now := metav1.Now()
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pt", Namespace: ns, UID: "uid-1",
			Finalizers:        []string{FinalizerCleanup},
			DeletionTimestamp: &now,
		},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			ExporterRef: corev1.LocalObjectReference{Name: "ec"},
		},
	}
	bundleName := ExporterBundleName(pt.UID)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: sysNS}}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, cm).Build()

	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: bundleName, Namespace: sysNS}, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
		t.Errorf("bundle ConfigMap should be deleted: %v", err)
	}
	// PodTrace should be removed (finalizer cleared, fake client removes it).
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pt), &podtracev1alpha1.PodTrace{}); !apierrors.IsNotFound(err) {
		t.Errorf("PodTrace should be gone after finalizer removal: %v", err)
	}
}

func TestExporterConfigToPodTraces(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&podtracev1alpha1.PodTrace{
			ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns"},
			Spec:       podtracev1alpha1.PodTraceSpec{ExporterRef: corev1.LocalObjectReference{Name: "ec"}},
		},
		&podtracev1alpha1.PodTrace{
			ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns"},
			Spec:       podtracev1alpha1.PodTraceSpec{ExporterRef: corev1.LocalObjectReference{Name: "other"}},
		},
	).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme}
	got := r.exporterConfigToPodTraces(context.Background(), &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "ns"},
	})
	if len(got) != 1 {
		t.Errorf("got %d requests, want 1 (only matching ExporterRef)", len(got))
	}
	if got := r.exporterConfigToPodTraces(context.Background(), &corev1.Pod{}); got != nil {
		t.Errorf("non-EC input should return nil, got %v", got)
	}
}

func TestAllNodesReady(t *testing.T) {
	if !allNodesReady(nil) {
		t.Error("allNodesReady(nil) should be true (vacuous)")
	}
	if !allNodesReady([]podtracev1alpha1.PodTraceNodeStatus{{Ready: true}, {Ready: true}}) {
		t.Error("all-true should be true")
	}
	if allNodesReady([]podtracev1alpha1.PodTraceNodeStatus{{Ready: true}, {Ready: false}}) {
		t.Error("any-false should be false")
	}
}

func TestCountReadyPods(t *testing.T) {
	in := []podtracev1alpha1.PodTraceNodeStatus{
		{MatchedPods: 3, ActiveCgroups: 9},
		{MatchedPods: 2, ActiveCgroups: 6},
	}
	if got := countReadyPods(in); got != 5 {
		t.Errorf("countReadyPods = %d, want 5", got)
	}
}

func TestTracerConfigReconciler_NotFound(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing"},
	})
	if err != nil || res.RequeueAfter != 0 {
		t.Errorf("expected zero result + nil err, got %+v / %v", res, err)
	}
}

func TestTracerConfigReconciler_HappyPath(t *testing.T) {
	const sysNS = "podtrace-system"
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", UID: "tc-uid"},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: sysNS, Image: "ghcr.io/gma1k/podtrace:test"},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).Build()

	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: tc.Name},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	for _, gvk := range []struct {
		obj  client.Object
		name string
		ns   string
	}{
		{&appsv1.DaemonSet{}, AgentDaemonSetName(DefaultTracerConfigName), sysNS},
		{&corev1.ServiceAccount{}, AgentServiceAccountName(DefaultTracerConfigName), sysNS},
		{&rbacv1.ClusterRole{}, AgentClusterRoleName(DefaultTracerConfigName), ""},
		{&rbacv1.ClusterRoleBinding{}, AgentClusterRoleBindingName(DefaultTracerConfigName), ""},
		{&rbacv1.Role{}, AgentBundleRoleName(DefaultTracerConfigName), sysNS},
		{&rbacv1.RoleBinding{}, AgentBundleRoleBindingName(DefaultTracerConfigName), sysNS},
	} {
		if err := c.Get(context.Background(), types.NamespacedName{Name: gvk.name, Namespace: gvk.ns}, gvk.obj); err != nil {
			t.Errorf("%T %s/%s missing: %v", gvk.obj, gvk.ns, gvk.name, err)
		}
	}
}

func TestTracerConfigReconciler_SystemNamespaceFor(t *testing.T) {
	r := &TracerConfigReconciler{SystemNamespace: "fallback"}
	if got := r.systemNamespaceFor(&podtracev1alpha1.TracerConfig{}); got != "fallback" {
		t.Errorf("empty spec → fallback, got %q", got)
	}
	if got := r.systemNamespaceFor(&podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{SystemNamespace: "custom"},
	}); got != "custom" {
		t.Errorf("custom spec wins, got %q", got)
	}
}

func TestAgentClusterRoleRules(t *testing.T) {
	rules := agentClusterRoleRules("podtrace-system")
	if len(rules) < 4 {
		t.Fatalf("expected at least 4 rules, got %d", len(rules))
	}
	found := false
	for _, r := range rules {
		for _, res := range r.Resources {
			if res == "pods" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected pods rule in ClusterRole")
	}
}

func TestSessionReconciler_NotFound(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "ns-sys"}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "x", Namespace: "ns"},
	})
	if err != nil || res.RequeueAfter != 0 {
		t.Errorf("not-found should return zero result, got %+v / %v", res, err)
	}
}

func TestSessionReconciler_FinalizerAdded(t *testing.T) {
	const sysNS, ns = "ns-sys", "default"
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: ns, UID: "uid-s"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: corev1.LocalObjectReference{Name: "ec"},
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s).Build()

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: s.Name, Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("expected Requeue after finalizer add")
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(s), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) == 0 {
		t.Error("finalizer not added")
	}
}

func TestSessionReconciler_NoMatchedPodsStaysPending(t *testing.T) {
	const sysNS, ns = "ns-sys", "default"
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: ns, UID: "uid-s",
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: corev1.LocalObjectReference{Name: "ec"},
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s).Build()

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: s.Name, Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("expected non-zero RequeueAfter (pending sessions are re-queued)")
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(s), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != podtracev1alpha1.SessionStatePending {
		t.Errorf("state = %q, want Pending", got.Status.State)
	}
}

func TestSessionReconciler_TerminalSession_TTLNotExpiredKeepsAlive(t *testing.T) {
	const sysNS, ns = "ns-sys", "default"
	completion := metav1.Now()
	ttl := int32(3600)
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: ns, UID: "uid-s",
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:                &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:                metav1.Duration{Duration: time.Minute},
			ExporterRef:             corev1.LocalObjectReference{Name: "ec"},
			TTLSecondsAfterFinished: &ttl,
		},
		Status: podtracev1alpha1.PodTraceSessionStatus{
			State:          podtracev1alpha1.SessionStateCompleted,
			CompletionTime: &completion,
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s).Build()

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: s.Name, Namespace: ns},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Error("expected positive RequeueAfter for non-expired terminal session")
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(s), &podtracev1alpha1.PodTraceSession{}); err != nil {
		t.Errorf("session should not be deleted before TTL: %v", err)
	}
}

func TestSessionReconciler_TerminalSession_TTLExpiredDeletes(t *testing.T) {
	const sysNS, ns = "ns-sys", "default"
	completion := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	ttl := int32(60) // 1 minute, well past for a 2hr-old session.
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: ns, UID: "uid-s",
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:                &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:                metav1.Duration{Duration: time.Minute},
			ExporterRef:             corev1.LocalObjectReference{Name: "ec"},
			TTLSecondsAfterFinished: &ttl,
		},
		Status: podtracev1alpha1.PodTraceSessionStatus{
			State:          podtracev1alpha1.SessionStateFailed,
			CompletionTime: &completion,
		},
	}
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s).Build()

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sysNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: s.Name, Namespace: ns},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got podtracev1alpha1.PodTraceSession
	err := c.Get(context.Background(), client.ObjectKeyFromObject(s), &got)
	if apierrors.IsNotFound(err) {
		return
	}
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.DeletionTimestamp == nil {
		t.Error("expected DeletionTimestamp to be set or session to be NotFound")
	}
}

func TestSessionTTL_DefaultAndOverride(t *testing.T) {
	if got := sessionTTL(&podtracev1alpha1.PodTraceSession{}); got != 300 {
		t.Errorf("default = %d, want 300", got)
	}
	custom := int32(42)
	got := sessionTTL(&podtracev1alpha1.PodTraceSession{
		Spec: podtracev1alpha1.PodTraceSessionSpec{TTLSecondsAfterFinished: &custom},
	})
	if got != 42 {
		t.Errorf("custom = %d, want 42", got)
	}
}

func TestSystemNamespaceForSession(t *testing.T) {
	if got := systemNamespaceForSession(nil, "fallback"); got != "fallback" {
		t.Errorf("nil tc → fallback, got %q", got)
	}
	if got := systemNamespaceForSession(&podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{SystemNamespace: "custom"},
	}, "fallback"); got != "custom" {
		t.Errorf("custom wins, got %q", got)
	}
	if got := systemNamespaceForSession(&podtracev1alpha1.TracerConfig{}, "fallback"); got != "fallback" {
		t.Errorf("empty spec → fallback, got %q", got)
	}
}

func TestEffectiveMaxConcurrentSessionsPerNode(t *testing.T) {
	if got := effectiveMaxConcurrentSessionsPerNode(nil); got != 0 {
		t.Errorf("nil tc → 0, got %d", got)
	}
	got := effectiveMaxConcurrentSessionsPerNode(&podtracev1alpha1.TracerConfig{
		Spec: podtracev1alpha1.TracerConfigSpec{MaxConcurrentSessionsPerNode: 5},
	})
	if got != 5 {
		t.Errorf("got %d, want 5", got)
	}
}

func TestIsPodEligible(t *testing.T) {
	cases := []struct {
		phase corev1.PodPhase
		want  bool
	}{
		{corev1.PodRunning, true},
		{corev1.PodPending, false},
		{corev1.PodSucceeded, false},
		{corev1.PodFailed, false},
	}
	for _, c := range cases {
		if got := isPodEligible(&corev1.Pod{Status: corev1.PodStatus{Phase: c.phase}}); got != c.want {
			t.Errorf("phase=%v: got %v want %v", c.phase, got, c.want)
		}
	}
}

func TestResolveTargetNodes_BySelectorAndPodRefs(t *testing.T) {
	const ns = "team-a"
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, Labels: map[string]string{"app": "x"}},
			Spec:       corev1.PodSpec{NodeName: "n1"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: ns, Labels: map[string]string{"app": "x"}},
			Spec:       corev1.PodSpec{NodeName: "n2"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: ns, Labels: map[string]string{"app": "x"}},
			Spec:       corev1.PodSpec{NodeName: "n3"},
			Status:     corev1.PodStatus{Phase: corev1.PodPending},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p4", Namespace: ns},
			Spec:       corev1.PodSpec{NodeName: "n4"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	).Build()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: ns},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			PodRefs:  []podtracev1alpha1.PodRef{{Name: "p4"}},
		},
	}

	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	targets, err := r.resolveSessionTargets(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	got := targets.Nodes
	want := []string{"n1", "n2", "n4"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, n := range want {
		if got[i] != n {
			t.Errorf("got[%d]=%q want %q", i, got[i], n)
		}
	}
}

func TestResolveTracerConfig_NotFoundReturnsNil(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	got, err := r.resolveTracerConfig(context.Background())
	if err != nil {
		t.Fatalf("NotFound must not surface as an error, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil when default TracerConfig missing, got %+v", got)
	}
}

func TestResolveTracerConfig_FoundReturnsObject(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "x"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	got, err := r.resolveTracerConfig(context.Background())
	if err != nil {
		t.Fatalf("resolveTracerConfig: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil")
		return
	}
	if got.Spec.SystemNamespace != "x" {
		t.Errorf("got.SystemNamespace = %q", got.Spec.SystemNamespace)
	}
}

func hasCondition(conds []metav1.Condition, condType string, want metav1.ConditionStatus) bool {
	for _, c := range conds {
		if c.Type == condType {
			return c.Status == want
		}
	}
	return false
}

func TestReconcileTerminalSession_TTLSemantics(t *testing.T) {
	scheme := newOperatorScheme(t)
	past := metav1.NewTime(time.Now().Add(-time.Minute))

	zero := int32(0)
	sZero := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "z", Namespace: "default", UID: "uid-z"},
		Spec:       podtracev1alpha1.PodTraceSessionSpec{TTLSecondsAfterFinished: &zero},
		Status:     podtracev1alpha1.PodTraceSessionStatus{CompletionTime: &past},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sZero).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "ns-sys"}
	if _, err := r.reconcileTerminalSession(context.Background(), sZero); err != nil {
		t.Fatalf("reconcileTerminalSession(ttl=0): %v", err)
	}
	err := c.Get(context.Background(), types.NamespacedName{Name: "z", Namespace: "default"}, &podtracev1alpha1.PodTraceSession{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("ttl=0 finished session must be deleted immediately, got err=%v", err)
	}

	big := int32(3600)
	recent := metav1.NewTime(time.Now())
	sBig := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "default", UID: "uid-b"},
		Spec:       podtracev1alpha1.PodTraceSessionSpec{TTLSecondsAfterFinished: &big},
		Status:     podtracev1alpha1.PodTraceSessionStatus{CompletionTime: &recent},
	}
	c2 := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sBig).Build()
	r2 := &PodTraceSessionReconciler{Client: c2, Scheme: scheme, SystemNamespace: "ns-sys"}
	res, err := r2.reconcileTerminalSession(context.Background(), sBig)
	if err != nil {
		t.Fatalf("reconcileTerminalSession(ttl=3600): %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("not-yet-elapsed TTL must requeue, got %+v", res)
	}
	if err := c2.Get(context.Background(), types.NamespacedName{Name: "b", Namespace: "default"}, &podtracev1alpha1.PodTraceSession{}); err != nil {
		t.Errorf("session must NOT be deleted before TTL elapses: %v", err)
	}
}
