package operator

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func ec(name string, spec podtracev1alpha1.ExporterConfigSpec) *podtracev1alpha1.ExporterConfig {
	return &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: types.UID("u-" + name)},
		Spec:       spec,
	}
}

func TestRenderBundlePayload_OTLP_LiteralHeaders(t *testing.T) {
	data, secret, _, err := renderBundlePayload(nil, ec("otlp-lit", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		OTLP: &podtracev1alpha1.OTLPExporter{
			Endpoint: "otel:4318",
			Protocol: podtracev1alpha1.OTLPProtocolGRPC,
			Insecure: true,
			Headers: []podtracev1alpha1.OTLPHeader{
				{Name: "X-Tenant", Value: "team-a"},
				{Name: "X-Env", Value: "prod"},
			},
		},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if secret != nil {
		t.Errorf("OTLP without ValueFrom must not produce a credential Secret ref")
	}
	for k, v := range map[string]string{
		"type":             "otlp",
		"endpoint":         "otel.default.svc:4318",
		"protocol":         "grpc",
		"insecure":         "true",
		"headers.X-Tenant": "team-a",
		"headers.X-Env":    "prod",
	} {
		if data[k] != v {
			t.Errorf("data[%q]=%q want %q", k, data[k], v)
		}
	}
}

func TestRenderBundlePayload_OTLP_SecretBackedHeader(t *testing.T) {
	data, secret, _, err := renderBundlePayload(nil, ec("otlp-sec", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		OTLP: &podtracev1alpha1.OTLPExporter{
			Endpoint: "otel:4318",
			Headers: []podtracev1alpha1.OTLPHeader{
				{Name: "Authorization", ValueFrom: &podtracev1alpha1.SecretKeySelector{
					Name: "auth", Key: "token",
				}},
			},
		},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Name != "auth" || secret.Key != "token" {
		t.Fatalf("expected credential ref auth/token, got %+v", secret)
	}
	if data["header_secret_name"] != "Authorization" {
		t.Errorf("header_secret_name=%q want Authorization", data["header_secret_name"])
	}
	if data["protocol"] != "http" {
		t.Errorf("protocol defaulted wrong: %q", data["protocol"])
	}
}

func TestRenderBundlePayload_Jaeger_NoCredentials(t *testing.T) {
	data, secret, _, err := renderBundlePayload(nil, ec("j", podtracev1alpha1.ExporterConfigSpec{
		Type:   podtracev1alpha1.ExporterTypeJaeger,
		Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "http://jaeger:14268"},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if secret != nil {
		t.Error("Jaeger has no credentials; Secret ref must be nil")
	}
	if data["endpoint"] != "http://jaeger.default.svc:14268" || data["type"] != "jaeger" {
		t.Errorf("payload wrong: %v", data)
	}
}

func TestRenderBundlePayload_Zipkin(t *testing.T) {
	data, secret, _, err := renderBundlePayload(nil, ec("z", podtracev1alpha1.ExporterConfigSpec{
		Type:   podtracev1alpha1.ExporterTypeZipkin,
		Zipkin: &podtracev1alpha1.ZipkinExporter{Endpoint: "http://zipkin:9411/api/v2/spans"},
	}), nil)
	if err != nil || secret != nil || data["type"] != "zipkin" {
		t.Fatalf("zipkin payload: err=%v secret=%v data=%v", err, secret, data)
	}
}

func TestRenderBundlePayload_Splunk_RequiresTokenSecret(t *testing.T) {
	data, secret, _, err := renderBundlePayload(nil, ec("s", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeSplunk,
		Splunk: &podtracev1alpha1.SplunkExporter{
			Endpoint:       "https://splunk:8088",
			TokenSecretRef: podtracev1alpha1.SecretKeySelector{Name: "hec", Key: "token"},
		},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Name != "hec" {
		t.Fatalf("expected HEC credential ref, got %+v", secret)
	}
	if data["endpoint"] != "https://splunk.default.svc:8088" {
		t.Errorf("splunk endpoint lost: %v", data)
	}
}

func TestRenderBundlePayload_DataDog_DefaultSite(t *testing.T) {
	data, secret, _, err := renderBundlePayload(nil, ec("d", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeDataDog,
		DataDog: &podtracev1alpha1.DataDogExporter{
			APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd", Key: "api"},
		},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Name != "dd" {
		t.Fatalf("expected DataDog credential ref, got %+v", secret)
	}
	if data["site"] != "datadoghq.com" {
		t.Errorf("default site should be datadoghq.com, got %q", data["site"])
	}
}

func TestRenderBundlePayload_ErrorOnMissingVariant(t *testing.T) {
	_, _, _, err := renderBundlePayload(nil, ec("broken", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		// no OTLP block populated
	}), nil)
	if err == nil {
		t.Fatal("expected error when spec.otlp is nil for type=otlp")
	}
}

func TestRenderBundlePayload_UnknownType(t *testing.T) {
	_, _, _, err := renderBundlePayload(nil, ec("xxx", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterType("made-up"),
	}), nil)
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestRenderBundlePayload_SamplePercent(t *testing.T) {
	pct := int32(25)
	data, _, _, err := renderBundlePayload(nil, ec("s", podtracev1alpha1.ExporterConfigSpec{
		Type:          podtracev1alpha1.ExporterTypeJaeger,
		Jaeger:        &podtracev1alpha1.JaegerExporter{Endpoint: "j:14268"},
		SamplePercent: &pct,
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if data["sample_percent"] != "25" {
		t.Errorf("sample_percent=%q want 25", data["sample_percent"])
	}
}

// TestRenderBundlePayload_FullPolicyPropagation pins the
// spec→bundle wiring for every policy field at once: filters,
// thresholds, sample (min applied), generation, and the resulting
// policy_hash.
func TestRenderBundlePayload_FullPolicyPropagation(t *testing.T) {
	crPct := int32(50)
	ecPct := int32(80)
	rttMs := int32(100)
	fsMs := int32(25)
	errPct := int32(5)

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "p",
			Namespace:  "default",
			UID:        types.UID("u-p"),
			Generation: 7,
		},
		Spec: podtracev1alpha1.PodTraceSpec{
			Filters:       []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterFS, podtracev1alpha1.FilterDNS},
			SamplePercent: &crPct,
			Thresholds: &podtracev1alpha1.Thresholds{
				ErrorRatePercent:    &errPct,
				RTTSpikeMs:          &rttMs,
				FilesystemLatencyMs: &fsMs,
			},
		},
	}
	ecObj := ec("ec", podtracev1alpha1.ExporterConfigSpec{
		Type:          podtracev1alpha1.ExporterTypeJaeger,
		Jaeger:        &podtracev1alpha1.JaegerExporter{Endpoint: "j:14268"},
		SamplePercent: &ecPct,
	})

	data, _, _, err := renderBundlePayload(policyFromPodTrace(pt), ecObj, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	if data["filters"] != "dns,fs" {
		t.Errorf("filters=%q want %q", data["filters"], "dns,fs")
	}
	if data["sample_percent"] != "50" {
		t.Errorf("sample_percent=%q want 50 (min applied)", data["sample_percent"])
	}
	if data["threshold_error_rate_percent"] != "5" {
		t.Errorf("threshold_error_rate_percent=%q", data["threshold_error_rate_percent"])
	}
	if data["threshold_rtt_spike_ms"] != "100" {
		t.Errorf("threshold_rtt_spike_ms=%q", data["threshold_rtt_spike_ms"])
	}
	if data["threshold_fs_slow_ms"] != "25" {
		t.Errorf("threshold_fs_slow_ms=%q", data["threshold_fs_slow_ms"])
	}
	if data["policy_generation"] != "7" {
		t.Errorf("policy_generation=%q want 7", data["policy_generation"])
	}
	if data["policy_hash"] == "" {
		t.Error("policy_hash must be stamped")
	}

	status := resolvePolicyStatus(policyFromPodTrace(pt), ecObj)
	if status == nil {
		t.Fatal("resolvePolicyStatus returned nil")
		return
	}
	if status.EffectiveSampleRate == nil || *status.EffectiveSampleRate != 50 {
		t.Errorf("status.EffectiveSampleRate=%v want 50", status.EffectiveSampleRate)
	}
	if status.Hash != data["policy_hash"] {
		t.Errorf("status hash %q != bundle hash %q (must match for propagation diff)", status.Hash, data["policy_hash"])
	}
	if status.Generation != 7 {
		t.Errorf("status.Generation=%d want 7", status.Generation)
	}
}

// TestRenderBundlePayload_NoPolicyOmitsKeys guards the absent-key
// contract: when spec carries no policy, the bundle ConfigMap contains
// none of the new keys (except policy_hash, which is always stamped so
// agents see a uniform schema).
func TestRenderBundlePayload_NoPolicyOmitsKeys(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default", UID: types.UID("u")},
	}
	ecObj := ec("ec", podtracev1alpha1.ExporterConfigSpec{
		Type:   podtracev1alpha1.ExporterTypeJaeger,
		Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "j:14268"},
	})
	data, _, _, err := renderBundlePayload(policyFromPodTrace(pt), ecObj, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, k := range []string{
		"filters", "threshold_error_rate_percent", "threshold_rtt_spike_ms",
		"threshold_fs_slow_ms", "sample_percent", "policy_generation",
	} {
		if _, ok := data[k]; ok {
			t.Errorf("expected key %q absent for empty-policy CR, got %q", k, data[k])
		}
	}
	if data["policy_hash"] == "" {
		t.Error("policy_hash is always stamped, even for empty policy")
	}
}

// TestEffectiveSamplePercent_MinimumApplies covers the "minimum
// applies" contract enumeratively so a future regression cannot
// reintroduce the dead-CR-samplePercent bug.
func TestEffectiveSamplePercent_MinimumApplies(t *testing.T) {
	cases := []struct {
		name      string
		cr        *int32
		ec        *int32
		wantValue int32
		wantNil   bool
	}{
		{name: "both_unset_returns_nil", cr: nil, ec: nil, wantNil: true},
		{name: "only_cr_set", cr: ptr32(25), ec: nil, wantValue: 25},
		{name: "only_ec_set", cr: nil, ec: ptr32(40), wantValue: 40},
		{name: "cr_lower_wins", cr: ptr32(20), ec: ptr32(80), wantValue: 20},
		{name: "ec_lower_wins", cr: ptr32(80), ec: ptr32(20), wantValue: 20},
		{name: "equal", cr: ptr32(50), ec: ptr32(50), wantValue: 50},
		{name: "zero_treated_as_zero_not_unset", cr: ptr32(0), ec: ptr32(50), wantValue: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &bundlePolicyInputs{SamplePercent: tc.cr}
			ecObj := ec("e", podtracev1alpha1.ExporterConfigSpec{SamplePercent: tc.ec})
			got := effectiveSamplePercentFromPolicy(policy, ecObj)
			if tc.wantNil {
				if got != nil {
					t.Errorf("got %v, want nil", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("got nil, want value")
				return
			}
			if *got != tc.wantValue {
				t.Errorf("got %d, want %d", *got, tc.wantValue)
			}
		})
	}
}

func ptr32(v int32) *int32 { return &v }

func TestRenderBundlePayload_AlwaysStampsVersion(t *testing.T) {
	cases := []struct {
		name string
		spec podtracev1alpha1.ExporterConfigSpec
	}{
		{
			name: "otlp",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "x:4318"},
			},
		},
		{
			name: "jaeger",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type:   podtracev1alpha1.ExporterTypeJaeger,
				Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "j:4318"},
			},
		},
		{
			name: "zipkin",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type:   podtracev1alpha1.ExporterTypeZipkin,
				Zipkin: &podtracev1alpha1.ZipkinExporter{Endpoint: "z:9411"},
			},
		},
		{
			name: "splunk",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeSplunk,
				Splunk: &podtracev1alpha1.SplunkExporter{
					Endpoint:       "s:4318",
					TokenSecretRef: podtracev1alpha1.SecretKeySelector{Name: "x", Key: "k"},
				},
			},
		},
		{
			name: "datadog",
			spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeDataDog,
				DataDog: &podtracev1alpha1.DataDogExporter{
					APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "x", Key: "k"},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, _, _, err := renderBundlePayload(nil, ec("v-"+tc.name, tc.spec), nil)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if data["version"] != bundle.CurrentVersion {
				t.Errorf("version stamp = %q, want %q", data["version"], bundle.CurrentVersion)
			}
		})
	}
}
