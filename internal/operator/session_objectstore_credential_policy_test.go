package operator

import (
	"context"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/reportsink/objectstore"
)

func objectStoreSessionObjects(credsName string, secretData map[string][]byte) []client.Object {
	objects := sessMoreFanOutObjects()
	for _, o := range objects {
		if tc, ok := o.(*podtracev1alpha1.TracerConfig); ok {
			tc.Spec.Session.SidecarUploader = true
		}
	}
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.ReportRef = &podtracev1alpha1.ReportReference{ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "s3://other-tenant-bucket/reports/"}}
		if credsName != "" {
			s.Spec.ReportRef.ObjectStore.CredentialsSecretRef = &corev1.LocalObjectReference{Name: credsName}
		}
	})
	objects = append(objects, s)
	if credsName != "" {
		objects = append(objects, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: credsName, Namespace: s.Namespace}, Data: secretData})
	}
	return objects
}

func sessionJobs(t *testing.T, r *PodTraceSessionReconciler) []batchv1.Job {
	t.Helper()
	var jobs batchv1.JobList
	if err := r.List(context.Background(), &jobs, client.InNamespace(sessMoreSysNS)); err != nil {
		t.Fatal(err)
	}
	return jobs.Items
}

func uploaderEnv(t *testing.T, job batchv1.Job) map[string]string {
	t.Helper()
	for _, c := range job.Spec.Template.Spec.InitContainers {
		if c.Name != reportUploaderContainerName {
			continue
		}
		env := map[string]string{}
		for _, e := range c.Env {
			env[e.Name] = e.Value
		}
		return env
	}
	t.Fatal("report-uploader sidecar not found")
	return nil
}

func objectStoreReconciler(t *testing.T, objects []client.Object) *PodTraceSessionReconciler {
	t.Helper()
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objects...).Build()
	return &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
}

func TestSessionReconcile_TenantAmbientObjectStoreRefusedBeforeJobs(t *testing.T) {
	t.Setenv(ObjectStoreCrossNamespaceAmbientCredentialsEnv, "")
	r := objectStoreReconciler(t, objectStoreSessionObjects("", nil))

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "ObjectStoreCreds" || !strings.Contains(cond.Message, "ambient credentials are not allowed") {
		t.Fatalf("Degraded condition = %+v, want ObjectStoreCreds ambient refusal", cond)
	}
	if jobs := sessionJobs(t, r); len(jobs) != 0 {
		t.Fatalf("%d Jobs created for a refused destination", len(jobs))
	}
}

func TestSessionReconcile_TenantEndpointWithoutStaticKeysRefused(t *testing.T) {
	t.Setenv(ObjectStoreCrossNamespaceAmbientCredentialsEnv, "true")
	r := objectStoreReconciler(t, objectStoreSessionObjects("creds", map[string][]byte{"endpoint": []byte("https://attacker.example")}))

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "ObjectStoreCreds" || !strings.Contains(cond.Message, "attacker.example") {
		t.Fatalf("Degraded condition = %+v, want the tenant endpoint refused", cond)
	}
	if jobs := sessionJobs(t, r); len(jobs) != 0 {
		t.Fatalf("%d Jobs created for a refused destination", len(jobs))
	}
}

func TestSessionReconcile_TenantStaticKeysUploaderDeniedAmbient(t *testing.T) {
	t.Setenv(ObjectStoreCrossNamespaceAmbientCredentialsEnv, "")
	t.Setenv(objectstore.EnvEndpointAllowlist, "minio.storage.svc, *.r2.example")
	r := objectStoreReconciler(t, objectStoreSessionObjects("creds", map[string][]byte{
		"access_key_id":     []byte("AKIA"),
		"secret_access_key": []byte("secret"),
		"endpoint":          []byte("http://minio.tenant.svc:9000"),
	}))

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	jobs := sessionJobs(t, r)
	if len(jobs) == 0 {
		t.Fatal("no Job created for a destination with static credentials")
	}
	env := uploaderEnv(t, jobs[0])
	if env[objectstore.EnvAllowAmbientCredentials] != "false" {
		t.Errorf("%s = %q, want false for a tenant session", objectstore.EnvAllowAmbientCredentials, env[objectstore.EnvAllowAmbientCredentials])
	}
	if env[objectstore.EnvEndpointAllowlist] != "minio.storage.svc,*.r2.example" {
		t.Errorf("%s = %q, want the operator allowlist", objectstore.EnvEndpointAllowlist, env[objectstore.EnvEndpointAllowlist])
	}
}

func TestSessionReconcile_CrossNamespaceAmbientOptIn(t *testing.T) {
	t.Setenv(ObjectStoreCrossNamespaceAmbientCredentialsEnv, "true")
	r := objectStoreReconciler(t, objectStoreSessionObjects("", nil))

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	jobs := sessionJobs(t, r)
	if len(jobs) == 0 {
		t.Fatal("no Job created with the cross-namespace ambient opt-in")
	}
	if env := uploaderEnv(t, jobs[0]); env[objectstore.EnvAllowAmbientCredentials] != "true" {
		t.Errorf("%s = %q, want true with the admin opt-in", objectstore.EnvAllowAmbientCredentials, env[objectstore.EnvAllowAmbientCredentials])
	}
}

func TestObjectStoreCredentialPolicy_OperatorNamespaceIsAdminOwned(t *testing.T) {
	t.Setenv(ObjectStoreCrossNamespaceAmbientCredentialsEnv, "")
	admin := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Namespace: "podtrace-system"}}
	tenant := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a"}}

	if !objectStoreCredentialPolicy(admin, "podtrace-system").AllowAmbientCredentials {
		t.Error("a session in the operator's namespace must keep ambient credentials")
	}
	if objectStoreCredentialPolicy(tenant, "podtrace-system").AllowAmbientCredentials {
		t.Error("a tenant session must not get ambient credentials without the opt-in")
	}
	if objectStoreCredentialPolicy(tenant, "").AllowAmbientCredentials {
		t.Error("an unknown operator namespace must not make every session admin-owned")
	}
	t.Setenv(ObjectStoreCrossNamespaceAmbientCredentialsEnv, "true")
	if !objectStoreCredentialPolicy(tenant, "podtrace-system").AllowAmbientCredentials {
		t.Error("the admin opt-in must grant tenant sessions ambient credentials")
	}
}

func TestApplyObjectStoreCredentialPolicyEnv_OnlyTouchesUploader(t *testing.T) {
	spec := corev1.PodSpec{InitContainers: []corev1.Container{{Name: "other"}, {Name: reportUploaderContainerName}}}
	applyObjectStoreCredentialPolicyEnv(&spec, objectstore.CredentialPolicy{AllowAmbientCredentials: true})
	if len(spec.InitContainers[0].Env) != 0 {
		t.Errorf("unrelated init container got env %v", spec.InitContainers[0].Env)
	}
	if len(spec.InitContainers[1].Env) != 2 {
		t.Errorf("uploader env = %v, want the two policy variables", spec.InitContainers[1].Env)
	}
}
