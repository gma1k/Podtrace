package operator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func newSessionBundleScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := podtracev1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func newOTLPExporter(name, ns string) *podtracev1alpha1.ExporterConfig {
	return &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID("ec-uid-" + name)},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint: "otel:4318",
				Protocol: podtracev1alpha1.OTLPProtocolHTTP,
			},
		},
	}
}

func TestEnsureSessionExporterBundle_CreatesConfigMap(t *testing.T) {
	scheme := newSessionBundleScheme(t)
	ec := newOTLPExporter("prod-otlp", "team-a")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec).Build()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sess-abc123"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ExporterRef: corev1.LocalObjectReference{Name: "prod-otlp"},
		},
	}

	if err := ensureSessionExporterBundle(context.Background(), c, c, s, ec, "podtrace-system"); err != nil {
		t.Fatalf("ensureSessionExporterBundle: %v", err)
	}

	var cm corev1.ConfigMap
	if err := c.Get(context.Background(), types.NamespacedName{Name: SessionBundleName(s.UID), Namespace: "podtrace-system"}, &cm); err != nil {
		t.Fatalf("get bundle CM: %v", err)
	}
	if cm.Data["type"] != "otlp" || cm.Data["endpoint"] != "otel.team-a.svc:4318" {
		t.Errorf("CM data wrong: %+v", cm.Data)
	}
	if cm.Data["bundle.yaml"] == "" {
		t.Error("bundle.yaml key missing")
	}
	if cm.Labels[LabelSessionName] != "diag" || cm.Labels[LabelSessionNS] != "team-a" {
		t.Errorf("labels missing session owner: %+v", cm.Labels)
	}
}

func TestEnsureSessionExporterBundle_UpdatesExisting(t *testing.T) {
	scheme := newSessionBundleScheme(t)
	ec := newOTLPExporter("prod-otlp", "team-a")
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sess-abc"},
	}
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SessionBundleName(s.UID),
			Namespace: "podtrace-system",
			Labels:    map[string]string{"existing": "true"},
		},
		Data: map[string]string{"other": "preserved"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, existing).Build()

	if err := ensureSessionExporterBundle(context.Background(), c, c, s, ec, "podtrace-system"); err != nil {
		t.Fatalf("ensureSessionExporterBundle: %v", err)
	}

	var cm corev1.ConfigMap
	_ = c.Get(context.Background(), types.NamespacedName{Name: SessionBundleName(s.UID), Namespace: "podtrace-system"}, &cm)
	if cm.Labels["existing"] != "true" {
		t.Errorf("lost existing label: %+v", cm.Labels)
	}
	if _, ok := cm.Data["other"]; ok {
		t.Errorf("stale data key not pruned on update: %+v", cm.Data)
	}
	if cm.Data["type"] != "otlp" {
		t.Errorf("bundle keys not applied: %+v", cm.Data)
	}
}

func TestEnsureSessionExporterBundle_WithCredentialCreatesSecret(t *testing.T) {
	scheme := newSessionBundleScheme(t)
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "dd", Namespace: "team-a", UID: "ec-dd"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeDataDog,
			DataDog: &podtracev1alpha1.DataDogExporter{
				Site:            "datadoghq.eu",
				APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd-creds", Key: "api_key"},
			},
		},
	}
	userSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "dd-creds", Namespace: "team-a"},
		Data:       map[string][]byte{"api_key": []byte("supersecret")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, userSecret).Build()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sess-xyz"},
	}
	if err := ensureSessionExporterBundle(context.Background(), c, c, s, ec, "podtrace-system"); err != nil {
		t.Fatalf("ensureSessionExporterBundle: %v", err)
	}

	var secret corev1.Secret
	key := client.ObjectKey{Name: SessionBundleName(s.UID), Namespace: "podtrace-system"}
	if err := c.Get(context.Background(), key, &secret); err != nil {
		t.Fatalf("expected companion Secret: %v", err)
	}
	if string(secret.Data["credential"]) != "supersecret" {
		t.Errorf("credential key wrong: %s", secret.Data["credential"])
	}
}

func TestMarshalBundleToYAML_DecodeError(t *testing.T) {
	if _, err := marshalBundleToYAML(nil); err == nil {
		t.Fatal("expected error when ConfigMap data is nil")
	}
}

func TestMarshalBundleToYAML_RoundTrip(t *testing.T) {
	cmData := map[string]string{
		"type":          "otlp",
		"endpoint":      "otel:4318",
		"protocol":      "http",
		"insecure":      "true",
		"headers.X-Env": "prod",
	}
	yaml, err := marshalBundleToYAML(cmData)
	if err != nil {
		t.Fatal(err)
	}
	if yaml == "" {
		t.Fatal("empty YAML")
	}
	// A quick substring check is enough: the bundle package's own
	// tests cover YAML round-trip correctness.
	if !strings.Contains(yaml, "endpoint: otel:4318") {
		t.Errorf("endpoint missing from YAML: %q", yaml)
	}
}
