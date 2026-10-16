package v1alpha1

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func reportOnlySchedule(name string) *podtracev1alpha1.PodTraceSchedule {
	return &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *",
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Spec: podtracev1alpha1.PodTraceSessionSpec{
					Selector:  &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
					Duration:  metav1.Duration{Duration: 30 * time.Second},
					ReportRef: &podtracev1alpha1.ReportReference{ConfigMap: &corev1.LocalObjectReference{Name: "report"}},
				},
			},
		},
	}
}

func fleetBTracerConfig() *podtracev1alpha1.TracerConfig {
	return &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "regulated"},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "img", SystemNamespace: "fleet-b"},
	}
}

func TestScheduleWebhook_ReportOnlyTemplateAdmitted(t *testing.T) {
	v := &PodTraceScheduleCustomValidator{Client: entitlementClient(t, fleetBTracerConfig()), SystemNamespace: "podtrace-system"}
	if _, err := v.validate(context.Background(), reportOnlySchedule("nightly")); err != nil {
		t.Fatalf("a template with only a reportRef is a valid session spec: %v", err)
	}
}

func TestScheduleWebhook_UnentitledTracerConfigRefRejected(t *testing.T) {
	v := &PodTraceScheduleCustomValidator{Client: entitlementClient(t, fleetBTracerConfig()), SystemNamespace: "podtrace-system"}
	sch := reportOnlySchedule("nightly")
	sch.Spec.SessionTemplate.Spec.TracerConfigRef = &corev1.LocalObjectReference{Name: "regulated"}
	_, err := v.validate(context.Background(), sch)
	if err == nil || !strings.Contains(err.Error(), "spec.sessionTemplate.spec.tracerConfigRef") {
		t.Fatalf("a schedule whose every child would be refused must be rejected, got %v", err)
	}
}

func TestScheduleWebhook_NameLongerThanLabelValueRejected(t *testing.T) {
	v := &PodTraceScheduleCustomValidator{Client: entitlementClient(t, fleetBTracerConfig()), SystemNamespace: "podtrace-system"}
	_, err := v.validate(context.Background(), reportOnlySchedule(strings.Repeat("a", 64)))
	if err == nil || !strings.Contains(err.Error(), "metadata.name") {
		t.Fatalf("a 64-character schedule name must be rejected, got %v", err)
	}
}
