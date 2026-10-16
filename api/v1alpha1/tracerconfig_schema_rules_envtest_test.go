//go:build envtest
// +build envtest

package v1alpha1_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func createTracerConfig(ctx context.Context, h *envtestHarness, name string, spec map[string]any) error {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("podtrace.io/v1alpha1")
	u.SetKind("TracerConfig")
	u.SetName(name)
	u.Object["spec"] = spec
	return h.client.Create(ctx, u)
}

func TestEnvtest_TracerConfigSchemaRules(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alerting := func(a map[string]any) map[string]any {
		return map[string]any{"image": "ghcr.io/gma1k/podtrace:test", "agent": map[string]any{"alerting": a}}
	}
	cases := map[string]struct {
		spec      map[string]any
		wantError string
	}{
		"webhook secret ref": {
			spec: alerting(map[string]any{"enabled": true, "webhookURLSecretRef": map[string]any{"name": "hook", "key": "url"}}),
		},
		"plain webhook url": {
			spec: alerting(map[string]any{"enabled": true, "webhookURL": "https://hooks.example/x"}),
		},
		"both webhook sources": {
			spec: alerting(map[string]any{"enabled": true, "webhookURL": "https://hooks.example/x",
				"webhookURLSecretRef": map[string]any{"name": "hook", "key": "url"}}),
			wantError: "set at most one of webhookURL or webhookURLSecretRef",
		},
		"empty url beside secret ref": {
			spec: alerting(map[string]any{"enabled": true, "webhookURL": "",
				"webhookURLSecretRef": map[string]any{"name": "hook", "key": "url"}}),
		},
		"fleet namespace": {
			spec: map[string]any{"image": "ghcr.io/gma1k/podtrace:test", "systemNamespace": "fleet-b"},
		},
		"namespace that is not a name": {
			spec:      map[string]any{"image": "ghcr.io/gma1k/podtrace:test", "systemNamespace": "Fleet_B"},
			wantError: "spec.systemNamespace",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := createTracerConfig(ctx, h, "rules-"+strings.ReplaceAll(name, " ", "-"), c.spec)
			if c.wantError == "" {
				if err != nil {
					t.Fatalf("the API server rejected a valid TracerConfig: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantError) {
				t.Fatalf("error = %v, want one containing %q", err, c.wantError)
			}
		})
	}
}
