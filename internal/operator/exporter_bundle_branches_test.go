package operator

import (
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestRenderBundlePayload_MissingVariantErrors(t *testing.T) {
	cases := []struct {
		name string
		typ  podtracev1alpha1.ExporterType
	}{
		{"jaeger", podtracev1alpha1.ExporterTypeJaeger},
		{"zipkin", podtracev1alpha1.ExporterTypeZipkin},
		{"splunk", podtracev1alpha1.ExporterTypeSplunk},
		{"datadog", podtracev1alpha1.ExporterTypeDataDog},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := renderBundlePayload(nil, ec("missing-"+tc.name, podtracev1alpha1.ExporterConfigSpec{
				Type: tc.typ,
			}), nil)
			if err == nil {
				t.Fatalf("expected error when spec.%s is nil for type=%s", tc.name, tc.typ)
			}
		})
	}
}

func TestRenderBundlePayload_DataDogExplicitEndpoint(t *testing.T) {
	data, secret, _, err := renderBundlePayload(nil, ec("dd-ep", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeDataDog,
		DataDog: &podtracev1alpha1.DataDogExporter{
			Site:            "datadoghq.eu",
			Endpoint:        "dd-custom:4318",
			APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd", Key: "api"},
		},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Name != "dd" {
		t.Fatalf("expected DataDog credential ref, got %+v", secret)
	}
	if data["site"] != "datadoghq.eu" {
		t.Errorf("site=%q want datadoghq.eu", data["site"])
	}
	if data["endpoint"] != "dd-custom.default.svc:4318" {
		t.Errorf("explicit endpoint not honored: %q", data["endpoint"])
	}
}

func TestRenderBundlePayload_TargetNamespacesSorted(t *testing.T) {
	data, _, _, err := renderBundlePayload(nil, ec("ns", podtracev1alpha1.ExporterConfigSpec{
		Type:   podtracev1alpha1.ExporterTypeJaeger,
		Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "j:14268"},
	}), []string{"team-c", "team-a", "team-b"})
	if err != nil {
		t.Fatal(err)
	}
	if data["target_namespaces"] != "team-a,team-b,team-c" {
		t.Errorf("target_namespaces=%q want sorted CSV", data["target_namespaces"])
	}
}

func TestResolvePolicyStatus_NilInputs(t *testing.T) {
	if got := resolvePolicyStatus(nil, nil); got != nil {
		t.Errorf("resolvePolicyStatus(nil, nil)=%+v want nil", got)
	}
}

func TestSynthBundleForHash_Nil(t *testing.T) {
	if got := synthBundleForHash(nil); got != nil {
		t.Errorf("synthBundleForHash(nil)=%+v want nil", got)
	}
}
