package v1alpha1_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	webhookv1alpha1 "github.com/gma1k/podtrace/internal/webhook/v1alpha1"
)

func newNonConnectingManager(t *testing.T) ctrl.Manager {
	t.Helper()
	s := newSetupScheme(t)
	cfg := &rest.Config{Host: "http://127.0.0.1:1"}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 s,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Skipf("could not build non-connecting manager: %v", err)
	}
	return mgr
}

func newSetupScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("clientgoscheme.AddToScheme: %v", err)
	}
	if err := podtracev1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

func TestSetupExporterConfigWebhookWithManager(t *testing.T) {
	mgr := newNonConnectingManager(t)
	if err := webhookv1alpha1.SetupExporterConfigWebhookWithManager(mgr); err != nil {
		t.Fatalf("SetupExporterConfigWebhookWithManager: %v", err)
	}
}

func TestSetupPodTraceWebhookWithManager(t *testing.T) {
	mgr := newNonConnectingManager(t)
	if err := webhookv1alpha1.SetupPodTraceWebhookWithManager(mgr); err != nil {
		t.Fatalf("SetupPodTraceWebhookWithManager: %v", err)
	}
}

func TestSetupPodTraceScheduleWebhookWithManager(t *testing.T) {
	mgr := newNonConnectingManager(t)
	if err := webhookv1alpha1.SetupPodTraceScheduleWebhookWithManager(mgr, "podtrace-system"); err != nil {
		t.Fatalf("SetupPodTraceScheduleWebhookWithManager: %v", err)
	}
}

func TestSetupPodTraceSessionWebhookWithManager(t *testing.T) {
	mgr := newNonConnectingManager(t)
	if err := webhookv1alpha1.SetupPodTraceSessionWebhookWithManager(mgr, "podtrace-system"); err != nil {
		t.Fatalf("SetupPodTraceSessionWebhookWithManager: %v", err)
	}
}

func TestSetupTracerConfigWebhookWithManager(t *testing.T) {
	mgr := newNonConnectingManager(t)
	if err := webhookv1alpha1.SetupTracerConfigWebhookWithManager(mgr); err != nil {
		t.Fatalf("SetupTracerConfigWebhookWithManager: %v", err)
	}
}

func TestSetupApplicationTraceWebhookWithManager(t *testing.T) {
	mgr := newNonConnectingManager(t)
	if err := webhookv1alpha1.SetupApplicationTraceWebhookWithManager(mgr); err != nil {
		t.Fatalf("SetupApplicationTraceWebhookWithManager: %v", err)
	}
}
