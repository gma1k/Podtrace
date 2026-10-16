package operator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func secretWebhookFleet() *podtracev1alpha1.TracerConfig {
	return tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.Alerting = &podtracev1alpha1.AgentAlertingSpec{
			Enabled:             true,
			WebhookURLSecretRef: &podtracev1alpha1.SecretKeySelector{Name: "alert-hook", Key: "url"},
		}
	})
}

func TestBuildAgentDaemonSetSpec_AlertWebhookFromSecret(t *testing.T) {
	spec := buildAgentDaemonSetSpec(secretWebhookFleet(), "podtrace-system")

	for _, e := range spec.Template.Spec.Containers[0].Env {
		if e.Name != "PODTRACE_ALERT_WEBHOOK_URL" {
			continue
		}
		if e.Value != "" {
			t.Fatal("a Secret-backed webhook URL must not be written into the DaemonSet")
		}
		ref := e.ValueFrom.SecretKeyRef
		if ref == nil || ref.Name != "alert-hook" || ref.Key != "url" {
			t.Fatalf("env source = %+v, want secretKeyRef alert-hook/url", e.ValueFrom)
		}
		if ref.Optional == nil || !*ref.Optional {
			t.Error("a missing webhook Secret must not stop the agents from starting")
		}
		return
	}
	t.Fatal("PODTRACE_ALERT_WEBHOOK_URL missing from the agent env")
}

func TestAlertWebhookSecret_Problems(t *testing.T) {
	withURL := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "alert-hook", Namespace: "podtrace-system"},
		Data:       map[string][]byte{"url": []byte("https://hooks.example/x")},
	}
	withoutKey := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "alert-hook", Namespace: "podtrace-system"},
		Data:       map[string][]byte{"other": []byte("x")},
	}
	cases := map[string]struct {
		objects []client.Object
		want    string
	}{
		"present":     {objects: []client.Object{withURL}, want: ""},
		"no secret":   {want: "does not exist"},
		"missing key": {objects: []client.Object{withoutKey}, want: `has no key "url"`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(c.objects...).Build()
			r := &TracerConfigReconciler{Client: cl, APIReader: cl}
			_, got := r.alertWebhookSecret(context.Background(), secretWebhookFleet(), "podtrace-system")
			if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
				t.Errorf("problem = %q, want %q", got, c.want)
			}
		})
	}
}

func TestAlertWebhookSecret_IgnoredWithoutSecretRef(t *testing.T) {
	r := &TracerConfigReconciler{Client: fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).Build()}
	if hash, got := r.alertWebhookSecret(context.Background(), tc(nil), "podtrace-system"); got != "" || hash != "" {
		t.Errorf("a fleet without a webhook Secret has no problem to report, got %q", got)
	}
}

func webhookSecret(url string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "alert-hook", Namespace: "podtrace-system"},
		Data:       map[string][]byte{"url": []byte(url)},
	}
}

func TestAlertWebhookSecret_HashFollowsTheURL(t *testing.T) {
	hashOf := func(url string) string {
		cl := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(webhookSecret(url)).Build()
		hash, problem := (&TracerConfigReconciler{Client: cl}).alertWebhookSecret(context.Background(), secretWebhookFleet(), "podtrace-system")
		if problem != "" {
			t.Fatalf("problem = %q", problem)
		}
		return hash
	}
	a, b := hashOf("https://hooks.example/a"), hashOf("https://hooks.example/b")
	if a == "" || a == b {
		t.Errorf("hashes %q and %q; a rotated URL must change the pod template so agents pick it up", a, b)
	}
	if strings.Contains(a, "hooks.example") {
		t.Error("the pod template must carry a hash, never the URL")
	}
}

func TestEnsureAgentDaemonSet_StampsWebhookHash(t *testing.T) {
	scheme := newOperatorScheme(t)
	fleet := secretWebhookFleet()
	fleet.Name = DefaultTracerConfigName
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(fleet).Build()
	r := &TracerConfigReconciler{Client: cl, Scheme: scheme}

	ds, err := r.ensureAgentDaemonSet(context.Background(), fleet, "podtrace-system", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if got := ds.Spec.Template.Annotations[AnnotationAlertWebhookHash]; got != "abc123" {
		t.Errorf("pod template annotation = %q, want the webhook hash", got)
	}
}

func TestSecretToTracerConfigs(t *testing.T) {
	other := tc(func(x *podtracev1alpha1.TracerConfig) { x.Name = "other" })
	fleet := secretWebhookFleet()
	fleet.Name = "with-hook"
	cl := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithObjects(fleet, other).Build()
	r := &TracerConfigReconciler{Client: cl, SystemNamespace: "podtrace-system"}

	got := r.secretToTracerConfigs(context.Background(), webhookSecret("x"))
	if len(got) != 1 || got[0].Name != "with-hook" {
		t.Errorf("requests = %v, want only the fleet that reads this Secret", got)
	}
	elsewhere := webhookSecret("x")
	elsewhere.Namespace = "team-a"
	if got := r.secretToTracerConfigs(context.Background(), elsewhere); len(got) != 0 {
		t.Errorf("a same-named Secret in another namespace must not enqueue the fleet, got %v", got)
	}
}

func TestTracerConfigReconcile_MissingWebhookSecretIsReported(t *testing.T) {
	scheme := newOperatorScheme(t)
	fleet := secretWebhookFleet()
	fleet.Name = DefaultTracerConfigName
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).WithObjects(fleet).Build()
	r := &TracerConfigReconciler{Client: cl, APIReader: cl, Scheme: scheme, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("a missing webhook Secret must be re-checked until it appears")
	}
	var got podtracev1alpha1.TracerConfig
	if err := cl.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionReconciled)
	if cond == nil || !strings.Contains(cond.Message, "alert webhook Secret podtrace-system/alert-hook does not exist") {
		t.Errorf("Reconciled condition = %+v, want it to name the missing Secret", cond)
	}
}

func TestAlertWebhookSecret_ReadErrorReportsNothing(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errInternal()
		},
	}).Build()
	hash, problem := (&TracerConfigReconciler{Client: cl}).alertWebhookSecret(context.Background(), secretWebhookFleet(), "podtrace-system")
	if hash != "" || problem != "" {
		t.Errorf("a transient read error must neither roll the agents nor claim the Secret is missing, got %q %q", hash, problem)
	}
}

func TestSecretToTracerConfigs_ListErrorEnqueuesNothing(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(newOperatorScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errInternal()
		},
	}).Build()
	if got := (&TracerConfigReconciler{Client: cl}).secretToTracerConfigs(context.Background(), webhookSecret("x")); got != nil {
		t.Errorf("requests = %v, want none", got)
	}
}
