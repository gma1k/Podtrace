package operator

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestQualifyServiceHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"otel-collector:4318", "otel-collector.team-a.svc:4318"},
		{"otel-collector", "otel-collector.team-a.svc"},
		{"http://recv:4318", "http://recv.team-a.svc:4318"},
		{"https://splunk:8088/services/collector", "https://splunk.team-a.svc:8088/services/collector"},
		{"http://zipkin:9411/api/v2/spans", "http://zipkin.team-a.svc:9411/api/v2/spans"},
		{"zipkin:9411/api/v2/spans", "zipkin.team-a.svc:9411/api/v2/spans"},
		{"http://recv", "http://recv.team-a.svc"},
		{"otel-collector.observability:4318", "otel-collector.observability:4318"},
		{"http://otel.observability.svc.cluster.local:4318", "http://otel.observability.svc.cluster.local:4318"},
		{"collector.example.com:443", "collector.example.com:443"},
		{"localhost:4318", "localhost:4318"},
		{"http://LOCALHOST:4318", "http://LOCALHOST:4318"},
		{"10.0.0.5:4318", "10.0.0.5:4318"},
		{"http://[fd00::1]:4318", "http://[fd00::1]:4318"},
		{"[fd00::1]:4318", "[fd00::1]:4318"},
		{"", ""},
		{"http://%zz", "http://%zz"},
	}
	for _, tc := range cases {
		if got := qualifyServiceHost(tc.in, "team-a"); got != tc.want {
			t.Errorf("qualifyServiceHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestQualifyServiceHostWithoutNamespaceIsUnchanged(t *testing.T) {
	if got := qualifyServiceHost("otel:4318", ""); got != "otel:4318" {
		t.Fatalf("got %q, want the endpoint unchanged", got)
	}
}

func TestRenderBundlePayloadQualifiesShortNamesForEveryExporterType(t *testing.T) {
	meta := metav1.ObjectMeta{Name: "ec", Namespace: "team-a"}
	secretRef := podtracev1alpha1.SecretKeySelector{Name: "creds", Key: "token"}
	cases := map[string]podtracev1alpha1.ExporterConfigSpec{
		"otlp":    {Type: podtracev1alpha1.ExporterTypeOTLP, OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318"}},
		"jaeger":  {Type: podtracev1alpha1.ExporterTypeJaeger, Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "otel:4318"}},
		"zipkin":  {Type: podtracev1alpha1.ExporterTypeZipkin, Zipkin: &podtracev1alpha1.ZipkinExporter{Endpoint: "otel:4318"}},
		"splunk":  {Type: podtracev1alpha1.ExporterTypeSplunk, Splunk: &podtracev1alpha1.SplunkExporter{Endpoint: "otel:4318", TokenSecretRef: secretRef}},
		"datadog": {Type: podtracev1alpha1.ExporterTypeDataDog, DataDog: &podtracev1alpha1.DataDogExporter{Endpoint: "otel:4318", APIKeySecretRef: secretRef}},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			ec := &podtracev1alpha1.ExporterConfig{ObjectMeta: meta, Spec: spec}
			data, _, _, err := renderBundlePayload(nil, ec, nil)
			if err != nil {
				t.Fatalf("renderBundlePayload: %v", err)
			}
			if data["endpoint"] != "otel.team-a.svc:4318" {
				t.Fatalf("endpoint = %q, want otel.team-a.svc:4318", data["endpoint"])
			}
		})
	}
}

func TestRenderBundlePayloadKeepsTheDataDogDefaultEndpoint(t *testing.T) {
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "team-a"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type:    podtracev1alpha1.ExporterTypeDataDog,
			DataDog: &podtracev1alpha1.DataDogExporter{APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd", Key: "k"}},
		},
	}
	data, _, _, err := renderBundlePayload(nil, ec, nil)
	if err != nil {
		t.Fatalf("renderBundlePayload: %v", err)
	}
	if data["endpoint"] != "datadog-agent.datadog:4318" {
		t.Fatalf("endpoint = %q, want the unchanged default", data["endpoint"])
	}
}
