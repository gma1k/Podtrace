package operator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func secretReportSession() *podtracev1alpha1.PodTraceSession {
	return sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.ReportRef = &podtracev1alpha1.ReportReference{Secret: &corev1.LocalObjectReference{Name: "report"}}
	})
}

func stagedReport(s *podtracev1alpha1.PodTraceSession, node, body string) *corev1.Secret {
	labels := reportStagingLabels(s)
	labels[LabelNodeName] = node
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: SessionReportStagingName(s.UID, node), Namespace: sessMoreSysNS, Labels: labels},
		Data:       map[string][]byte{"report-" + node + ".txt": []byte(body)},
	}
}

func operatorSecretVerbs() map[string]bool {
	return map[string]bool{"get": true, "list": true, "watch": true, "create": true, "delete": true}
}

func TestSessionRoles_GrantNoSecretVerbTheOperatorLacks(t *testing.T) {
	s := secretReportSession()
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build()
	if err := ensureSessionReportStaging(context.Background(), c, s, map[string][]string{sessMoreSysNS: {"n1"}}); err != nil {
		t.Fatal(err)
	}
	var staging rbacv1.Role
	if err := c.Get(context.Background(), types.NamespacedName{Name: SessionReportStagingRoleName(s.UID), Namespace: sessMoreSysNS}, &staging); err != nil {
		t.Fatal(err)
	}
	rules := append(buildSessionReportRules(s.Spec.ReportRef), staging.Rules...)
	allowed := operatorSecretVerbs()
	for _, rule := range rules {
		for _, res := range rule.Resources {
			if res != "secrets" {
				continue
			}
			for _, verb := range rule.Verbs {
				if !allowed[verb] {
					t.Errorf("a session Role grants secrets %q, which the operator cannot delegate outside its own namespace", verb)
				}
			}
		}
	}
}

func TestEnsureSessionReportStaging_PreCreatesAndScopesByName(t *testing.T) {
	s := secretReportSession()
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build()
	if err := ensureSessionReportStaging(context.Background(), c, s, map[string][]string{sessMoreSysNS: {"n1", "n2"}}); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"n1", "n2"} {
		var staged corev1.Secret
		if err := c.Get(context.Background(), types.NamespacedName{Name: SessionReportStagingName(s.UID, node), Namespace: sessMoreSysNS}, &staged); err != nil {
			t.Fatalf("staging Secret for %s: %v", node, err)
		}
		if staged.Labels[LabelComponent] != ComponentReportStaging || staged.Labels[LabelSessionName] != s.Name {
			t.Errorf("staging Secret for %s carries labels %v", node, staged.Labels)
		}
	}
	var role rbacv1.Role
	if err := c.Get(context.Background(), types.NamespacedName{Name: SessionReportStagingRoleName(s.UID), Namespace: sessMoreSysNS}, &role); err != nil {
		t.Fatal(err)
	}
	if got := role.Rules[0].ResourceNames; len(got) != 2 {
		t.Errorf("get/delete must be scoped to the two staging names, got %v", got)
	}
	var binding rbacv1.RoleBinding
	if err := c.Get(context.Background(), types.NamespacedName{Name: SessionReportStagingRoleName(s.UID), Namespace: sessMoreSysNS}, &binding); err != nil {
		t.Fatal(err)
	}
	if len(binding.Subjects) != 1 || binding.Subjects[0].Name != SessionServiceAccountName(s.UID) {
		t.Errorf("binding subjects = %+v, want the session ServiceAccount", binding.Subjects)
	}
}

func TestPublishSessionSecretReport_MergesStagedReportsAndCleansUp(t *testing.T) {
	s := secretReportSession()
	stagingRole := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: SessionReportStagingRoleName(s.UID), Namespace: sessMoreSysNS}}
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithObjects(stagedReport(s, "n1", "one"), stagedReport(s, "n2", "two"), stagingRole).Build()

	if err := publishSessionSecretReport(context.Background(), c, c, s); err != nil {
		t.Fatalf("publish: %v", err)
	}
	var report corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "report", Namespace: s.Namespace}, &report); err != nil {
		t.Fatalf("tenant report Secret: %v", err)
	}
	if string(report.Data["report-n1.txt"]) != "one" || string(report.Data["report-n2.txt"]) != "two" {
		t.Errorf("report data = %v, want both nodes", report.Data)
	}
	if !reportObjectOwnedBySession(report.Labels, s) {
		t.Errorf("the published Secret must carry the session's ownership labels, got %v", report.Labels)
	}
	var left corev1.SecretList
	if err := c.List(context.Background(), &left, client.MatchingLabels(reportStagingLabels(s))); err != nil {
		t.Fatal(err)
	}
	if len(left.Items) != 0 {
		t.Errorf("%d staging Secret(s) left after publishing", len(left.Items))
	}
	var role rbacv1.Role
	if err := c.Get(context.Background(), types.NamespacedName{Name: SessionReportStagingRoleName(s.UID), Namespace: sessMoreSysNS}, &role); err == nil {
		t.Error("the staging Role, with its unscoped secrets create, must not outlive the published report")
	}
}

func TestPublishSessionSecretReport_RefusesSecretItDidNotCreate(t *testing.T) {
	s := secretReportSession()
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "report", Namespace: s.Namespace},
		Data:       map[string][]byte{"password": []byte("hunter2")},
	}
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithObjects(foreign, stagedReport(s, "n1", "one")).Build()

	err := publishSessionSecretReport(context.Background(), c, c, s)
	var conflict *reportObjectConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("want a reportObjectConflictError, got %v", err)
	}
	var got corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "report", Namespace: s.Namespace}, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Data["password"]) != "hunter2" {
		t.Error("a Secret the session did not create must be left untouched")
	}
}

func TestPublishSessionSecretReport_ReplacesEarlierRunOfSameSchedule(t *testing.T) {
	s := secretReportSession()
	s.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: podtracev1alpha1.GroupVersion.String(), Kind: "PodTraceSchedule", Name: "nightly", UID: "sch", Controller: boolPtr(true),
	}}
	earlier := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "report", Namespace: s.Namespace, Labels: map[string]string{
			labelReportKind: reportKindValue, reportManagedBy: reportManagedVal, LabelSchedule: "nightly",
			LabelSessionName: "nightly-1", LabelSessionNS: s.Namespace,
		}},
		Data: map[string][]byte{"report-n1.txt": []byte("old")},
	}
	c := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).
		WithObjects(earlier, stagedReport(s, "n1", "new")).Build()

	if err := publishSessionSecretReport(context.Background(), c, c, s); err != nil {
		t.Fatalf("publish: %v", err)
	}
	var got corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "report", Namespace: s.Namespace}, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Data["report-n1.txt"]) != "new" || got.Labels[LabelSessionName] != s.Name {
		t.Errorf("want the new run's report and ownership, got data %v labels %v", got.Data, got.Labels)
	}
}

func TestBuildSessionJobSpec_SecretReportGoesToStagingSecret(t *testing.T) {
	s := secretReportSession()
	tc := &podtracev1alpha1.TracerConfig{Spec: podtracev1alpha1.TracerConfigSpec{Image: "img"}}
	spec := buildSessionJobSpec(s, tc, "n1", sessionTargets{Nodes: []string{"n1"}})
	main := spec.Template.Spec.Containers[0]

	want := "secret/$(POD_NAMESPACE)/" + SessionReportStagingName(s.UID, "n1")
	if !strings.Contains(strings.Join(main.Args, " "), "--report-to "+want) {
		t.Errorf("args %v must report to %s", main.Args, want)
	}
	found := false
	for _, e := range main.Env {
		if e.Name == "POD_NAMESPACE" && e.ValueFrom != nil && e.ValueFrom.FieldRef.FieldPath == "metadata.namespace" {
			found = true
		}
	}
	if !found {
		t.Error("the main container needs POD_NAMESPACE for the kubelet to expand the report target")
	}
}

func TestSessionReconcile_TerminalSessionPublishesSecretReport(t *testing.T) {
	s := secretReportSession()
	completed := metav1.Now()
	s.Status.State = podtracev1alpha1.SessionStateCompleted
	s.Status.CompletionTime = &completed
	r := frozenTargetsReconciler(t, s, stagedReport(s, "n1", "one"))

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	if !secretReportSettled(&got) || meta.FindStatusCondition(got.Status.Conditions, ConditionReportUploaded).Status != metav1.ConditionTrue {
		t.Fatalf("conditions = %+v, want ReportUploaded=True", got.Status.Conditions)
	}
	var report corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "report", Namespace: s.Namespace}, &report); err != nil {
		t.Fatalf("tenant report Secret: %v", err)
	}
}

func TestSessionReconcile_TerminalSessionWithNothingStagedSettles(t *testing.T) {
	s := secretReportSession()
	completed := metav1.Now()
	s.Status.State = podtracev1alpha1.SessionStateFailed
	s.Status.CompletionTime = &completed
	r := frozenTargetsReconciler(t, s)

	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter < time.Minute {
		t.Errorf("requeueAfter = %v; a session with nothing to publish must wait for its TTL, not retry", res.RequeueAfter)
	}
	var report corev1.Secret
	if err := r.Get(context.Background(), types.NamespacedName{Name: "report", Namespace: s.Namespace}, &report); err == nil {
		t.Error("no report Secret may be published for a session that never staged one")
	}
	got := (&fakeGetter{r: r}).session(t)
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionReportUploaded)
	if cond == nil || cond.Reason != reasonNothingStaged {
		t.Errorf("ReportUploaded = %+v, want reason %s", cond, reasonNothingStaged)
	}
}
