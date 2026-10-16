package v1alpha1_test

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	webhookv1alpha1 "github.com/gma1k/podtrace/internal/webhook/v1alpha1"
)

func applicationTrace(mutate func(*podtracev1alpha1.ApplicationTrace)) *podtracev1alpha1.ApplicationTrace {
	app := &podtracev1alpha1.ApplicationTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "default"},
		Spec: podtracev1alpha1.ApplicationTraceSpec{
			AppSelector: podtracev1alpha1.AppSelector{MatchSelectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"app": "frontend"}},
				{MatchLabels: map[string]string{"app": "checkout"}},
			}},
			ExporterRef: corev1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if mutate != nil {
		mutate(app)
	}
	return app
}

func TestApplicationTraceWebhook(t *testing.T) {
	cases := map[string]struct {
		mutate    func(*podtracev1alpha1.ApplicationTrace)
		wantError string
	}{
		"valid": {},
		"name too long": {
			mutate:    func(a *podtracev1alpha1.ApplicationTrace) { a.Name = strings.Repeat("a", 64) },
			wantError: "metadata.name",
		},
		"no selectors": {
			mutate:    func(a *podtracev1alpha1.ApplicationTrace) { a.Spec.AppSelector.MatchSelectors = nil },
			wantError: "spec.appSelector.matchSelectors",
		},
		"malformed selector": {
			mutate: func(a *podtracev1alpha1.ApplicationTrace) {
				a.Spec.AppSelector.MatchSelectors[1] = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "app", Operator: "Bogus", Values: []string{"x"}},
				}}
			},
			wantError: "matchSelectors[1]",
		},
		"malformed namespace selector": {
			mutate:    func(a *podtracev1alpha1.ApplicationTrace) { a.Spec.NamespaceSelector = malformedSelector() },
			wantError: "namespaceSelector",
		},
		"missing exporter": {
			mutate:    func(a *podtracev1alpha1.ApplicationTrace) { a.Spec.ExporterRef.Name = "nope" },
			wantError: "ExporterConfig not found",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			v := &webhookv1alpha1.ApplicationTraceCustomValidator{Client: newClientWithExporter(t, "default", "prod-otlp")}
			_, err := v.ValidateCreate(context.Background(), applicationTrace(c.mutate))
			if c.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantError) {
				t.Fatalf("error = %v, want one containing %q", err, c.wantError)
			}
		})
	}
}

func TestApplicationTraceWebhook_CrossNamespaceWithoutConsentWarns(t *testing.T) {
	v := &webhookv1alpha1.ApplicationTraceCustomValidator{Client: newClientWithExporter(t, "default", "prod-otlp",
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other", Labels: map[string]string{"tier": "web"}}})}
	app := applicationTrace(func(a *podtracev1alpha1.ApplicationTrace) {
		a.Spec.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}}
	})
	warnings, err := v.ValidateCreate(context.Background(), app)
	if err != nil {
		t.Fatalf("a missing consent is surfaced as a warning, not a rejection: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("a namespace that does not consent must be named in a warning")
	}
}

func TestApplicationTraceWebhook_UnchangedSpecSkipsValidation(t *testing.T) {
	v := &webhookv1alpha1.ApplicationTraceCustomValidator{Client: newClientWithExporter(t, "default", "")}
	app := applicationTrace(nil)
	if _, err := v.ValidateUpdate(context.Background(), app, app.DeepCopy()); err != nil {
		t.Errorf("a metadata-only update must not be re-validated: %v", err)
	}
	if _, err := v.ValidateDelete(context.Background(), app); err != nil {
		t.Errorf("delete must always be allowed: %v", err)
	}
}

func TestApplicationTraceWebhook_ChangedSpecIsValidated(t *testing.T) {
	v := &webhookv1alpha1.ApplicationTraceCustomValidator{Client: newClientWithExporter(t, "default", "prod-otlp")}
	oldApp := applicationTrace(nil)
	newApp := applicationTrace(func(a *podtracev1alpha1.ApplicationTrace) { a.Spec.ExporterRef.Name = "nope" })
	if _, err := v.ValidateUpdate(context.Background(), oldApp, newApp); err == nil {
		t.Error("an update that points at a missing ExporterConfig must be rejected")
	}
}
