package agent

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gma1k/podtrace/internal/operator"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func TestLoadBundle_OTLPLiteral(t *testing.T) {
	const systemNS = "podtrace-system"
	uid := types.UID("e8c32c91-0000-0000-0000-000000000001")
	name := operator.ExporterBundleName(uid)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       systemNS,
			ResourceVersion: "42",
		},
		Data: map[string]string{
			"type":             "otlp",
			"endpoint":         "otel:4318",
			"protocol":         "http",
			"insecure":         "false",
			"headers.X-Env":    "prod",
			"headers.X-Tenant": "team-a",
			"sample_percent":   "50",
		},
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()

	payload, err := LoadBundle(context.Background(), c, systemNS, uid)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if payload.Type != bundle.TypeOTLP || payload.Endpoint != "otel:4318" {
		t.Errorf("payload wrong: %+v", payload)
	}
	if payload.Sample == nil || *payload.Sample != 0.5 {
		t.Errorf("sample=%v want 0.5", payload.Sample)
	}
	if payload.Headers["X-Env"] != "prod" || payload.Headers["X-Tenant"] != "team-a" {
		t.Errorf("headers lost: %+v", payload.Headers)
	}
	if payload.Insecure {
		t.Error("insecure parsed wrong for 'false'")
	}
	if payload.ResourceVer != "42" {
		t.Errorf("ResourceVer=%q want 42", payload.ResourceVer)
	}
	if payload.SamplingKey != string(uid) {
		t.Errorf("SamplingKey=%q want the PodTrace UID", payload.SamplingKey)
	}
}

func TestLoadBundle_WithCredential(t *testing.T) {
	const systemNS = "podtrace-system"
	uid := types.UID("e8c32c91-0000-0000-0000-000000000002")
	name := operator.ExporterBundleName(uid)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS},
		Data:       map[string]string{"type": "datadog", "site": "datadoghq.com"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS},
		Data:       map[string][]byte{"credential": []byte("super-secret")},
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm, secret).Build()

	payload, err := LoadBundle(context.Background(), c, systemNS, uid)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload.Credential) != "super-secret" {
		t.Errorf("credential=%q want super-secret", payload.Credential)
	}
}

// TestLoadBundle_CredentialRotationChangesRevision is the regression guard:
// a credential-only rotation leaves the bundle ConfigMap untouched,
// so the ConfigMap ResourceVersion alone cannot detect it.
func TestLoadBundle_CredentialRotationChangesRevision(t *testing.T) {
	const systemNS = "podtrace-system"
	uid := types.UID("e8c32c91-0000-0000-0000-000000000003")
	name := operator.ExporterBundleName(uid)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	load := func(cmRV, secRV, token string) *BundlePayload {
		t.Helper()
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS, ResourceVersion: cmRV},
			Data:       map[string]string{"type": "datadog", "site": "datadoghq.com"},
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS, ResourceVersion: secRV},
			Data:       map[string][]byte{"credential": []byte(token)},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm, secret).Build()
		p, err := LoadBundle(context.Background(), c, systemNS, uid)
		if err != nil {
			t.Fatalf("LoadBundle: %v", err)
		}
		return p
	}

	base := load("100", "7", "token-old")
	if base.ResourceVer != "100/7" {
		t.Fatalf("ResourceVer=%q want 100/7", base.ResourceVer)
	}

	rotated := load("100", "8", "token-new")
	if rotated.ResourceVer == base.ResourceVer {
		t.Fatalf("ResourceVer unchanged after credential rotation (%q): the cached exporter would keep exporting with the dead token", rotated.ResourceVer)
	}
	if rotated.ResourceVer != "100/8" {
		t.Errorf("ResourceVer=%q want 100/8", rotated.ResourceVer)
	}
	if string(rotated.Credential) != "token-new" {
		t.Errorf("credential=%q want token-new", rotated.Credential)
	}
}

func TestLoadBundle_MissingConfigMap(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	_, err := LoadBundle(context.Background(), c, "podtrace-system", types.UID("missing"))
	if err == nil {
		t.Fatal("expected NotFound error for missing ConfigMap")
		return
	}
	if !strings.Contains(err.Error(), "ConfigMap") {
		t.Errorf("error does not mention ConfigMap: %v", err)
	}
}

func TestBuildExporter_OTLP(t *testing.T) {
	p := &BundlePayload{
		Type:     "otlp",
		Endpoint: "otel-collector:4318",
		Protocol: "http",
		Insecure: true,
	}
	exp, err := BuildExporter(p, CRKey{"ns", "cr"})
	if err != nil {
		t.Fatal(err)
	}
	if exp == nil {
		t.Fatal("nil exporter")
		return
	}
	ctx, cancel := contextWithTimeout(1)
	defer cancel()
	_ = exp.Close(ctx)
}

func TestBuildExporter_Jaeger(t *testing.T) {
	p := &BundlePayload{
		Type:     bundle.TypeJaeger,
		Endpoint: "jaeger-collector.observability:4318",
		Insecure: true,
	}
	exp, err := BuildExporter(p, CRKey{"ns", "cr"})
	if err != nil {
		t.Fatalf("BuildExporter: %v", err)
	}
	if exp == nil {
		t.Fatal("nil exporter")
		return
	}
	if !strings.Contains(exp.Name(), "jaeger") {
		t.Errorf("Name() = %q; expected to contain %q", exp.Name(), "jaeger")
	}
	ctx, cancel := contextWithTimeout(1)
	defer cancel()
	_ = exp.Close(ctx)
}

func TestBuildExporter_DataDog(t *testing.T) {
	p := &BundlePayload{
		Type:       bundle.TypeDataDog,
		Endpoint:   "datadog-agent.datadog:4318",
		Site:       "datadoghq.com",
		Insecure:   true,
		HeaderName: "DD-API-KEY",
		Credential: []byte("dd-api-key-redacted"),
	}
	exp, err := BuildExporter(p, CRKey{"ns", "cr"})
	if err != nil {
		t.Fatalf("BuildExporter: %v", err)
	}
	if exp == nil {
		t.Fatal("nil exporter")
		return
	}
	if !strings.Contains(exp.Name(), "datadog") {
		t.Errorf("Name() = %q; expected to contain %q", exp.Name(), "datadog")
	}
	ctx, cancel := contextWithTimeout(1)
	defer cancel()
	_ = exp.Close(ctx)
}

func TestBuildExporter_Splunk(t *testing.T) {
	p := &BundlePayload{
		Type:       bundle.TypeSplunk,
		Endpoint:   "splunk-otel-collector.splunk:4318",
		Insecure:   true,
		HeaderName: "X-SF-TOKEN",
		Credential: []byte("splunk-token-redacted"),
	}
	exp, err := BuildExporter(p, CRKey{"ns", "cr"})
	if err != nil {
		t.Fatalf("BuildExporter: %v", err)
	}
	if exp == nil {
		t.Fatal("nil exporter")
		return
	}
	if !strings.Contains(exp.Name(), "splunk") {
		t.Errorf("Name() = %q; expected to contain %q", exp.Name(), "splunk")
	}
	ctx, cancel := contextWithTimeout(1)
	defer cancel()
	_ = exp.Close(ctx)
}

func TestBuildExporter_ZipkinReturnsHelpfulError(t *testing.T) {
	_, err := BuildExporter(&BundlePayload{Type: bundle.TypeZipkin, Endpoint: "zipkin:9411"}, CRKey{"ns", "n"})
	if err == nil {
		t.Fatal("expected error from zipkin exporter")
		return
	}
	if !strings.Contains(err.Error(), "OpenTelemetry Collector") {
		t.Errorf("error should point at OTel Collector; got: %v", err)
	}
	if !strings.Contains(err.Error(), "type: otlp") {
		t.Errorf("error should suggest type: otlp; got: %v", err)
	}
}

func TestBuildExporter_EmptyEndpointRejected(t *testing.T) {
	for _, ty := range []bundle.Type{bundle.TypeOTLP, bundle.TypeJaeger, bundle.TypeDataDog, bundle.TypeSplunk} {
		t.Run(string(ty), func(t *testing.T) {
			_, err := BuildExporter(&BundlePayload{Type: ty, Credential: []byte("secret")}, CRKey{"ns", "n"})
			if err == nil {
				t.Fatalf("expected error for empty endpoint on %q", ty)
				return
			}
			if !strings.Contains(err.Error(), "endpoint") {
				t.Errorf("error should mention endpoint; got: %v", err)
			}
		})
	}
}

func TestBuildExporter_UnknownType(t *testing.T) {
	_, err := BuildExporter(&BundlePayload{Type: "nothing"}, CRKey{"ns", "n"})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestBuildExporter_NilPayload(t *testing.T) {
	_, err := BuildExporter(nil, CRKey{"ns", "n"})
	if err == nil {
		t.Fatal("expected error for nil payload")
	}
}

func TestClassifyExporterError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errSentinel("nil bundle payload"), ExporterErrNilPayload},
		{errSentinel("unknown exporter type \"zipkin-direct\""), ExporterErrUnsupportedType},
		{errSentinel("missing endpoint for OTLP exporter"), ExporterErrEndpointMissing},
		{errSentinel("TLS handshake failed: bad certificate"), ExporterErrTLSInvalid},
		{errSentinel("missing api key for DataDog exporter"), ExporterErrAuthMissing},
		{errSentinel("something exotic happened"), ExporterErrUnknown},
	}
	for _, c := range cases {
		if got := ClassifyExporterError(c.err); got != c.want {
			t.Errorf("ClassifyExporterError(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func errSentinel(s string) error { return errString(s) }

func contextWithTimeout(_ int) (context.Context, func()) {
	return context.WithCancel(context.Background()) //nolint:contextcheck // tests tolerate indefinite ctx
}
