package operator

import (
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestSessionReconcile_NonPositiveDurationFailsTerminally(t *testing.T) {
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.Duration = metav1.Duration{Duration: -5 * time.Minute}
	})
	objects := append(sessMoreFanOutObjects(), s)
	r := frozenTargetsReconciler(t, objects...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Fatalf("state = %q, want Failed", got.Status.State)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "InvalidDuration" {
		t.Fatalf("degraded condition = %+v, want InvalidDuration", cond)
	}
}

func TestBuildSessionJobSpec_LargeDeadlineOffsetDoesNotOverflow(t *testing.T) {
	s := sessMoreSession(nil)
	tc := &podtracev1alpha1.TracerConfig{Spec: podtracev1alpha1.TracerConfigSpec{Image: "img"}}
	tc.Spec.Session.ActiveDeadlineOffset = &metav1.Duration{Duration: 700_000 * time.Hour}

	spec := buildSessionJobSpec(s, tc, "n1", sessionTargets{Nodes: []string{"n1"}})
	if spec.ActiveDeadlineSeconds == nil || *spec.ActiveDeadlineSeconds <= int64(700_000*time.Hour/time.Second) {
		t.Fatalf("activeDeadlineSeconds = %v, want duration plus the full offset", spec.ActiveDeadlineSeconds)
	}
}

func TestRenderBundlePayload_RejectsInvalidHeaderName(t *testing.T) {
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "team-a"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint: "otel:4318",
				Protocol: podtracev1alpha1.OTLPProtocolHTTP,
				Headers:  []podtracev1alpha1.OTLPHeader{{Name: "X Tenant", Value: "a"}},
			},
		},
	}
	_, _, _, err := renderBundlePayload(nil, ec, nil)
	if err == nil || !strings.Contains(err.Error(), "X Tenant") {
		t.Fatalf("a header name that cannot be a ConfigMap key must be rejected, got %v", err)
	}
}

func TestSessionReconcile_DurationBeyondJobLimitFailsTerminally(t *testing.T) {
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.Duration = metav1.Duration{Duration: 8760 * time.Hour}
	})
	objects := append(sessMoreFanOutObjects(), s)
	r := frozenTargetsReconciler(t, objects...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if got.Status.State != podtracev1alpha1.SessionStateFailed || cond == nil || cond.Reason != "DurationTooLong" {
		t.Fatalf("state %q condition %+v, want Failed/DurationTooLong", got.Status.State, cond)
	}
}

func TestSessionReconcile_LongDurationCappedByFleetRuns(t *testing.T) {
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.Duration = metav1.Duration{Duration: 8760 * time.Hour}
	})
	objects := sessMoreFanOutObjects()
	objects[2].(*podtracev1alpha1.TracerConfig).Spec.Session.MaxDuration = &metav1.Duration{Duration: time.Hour}
	r := frozenTargetsReconciler(t, append(objects, s)...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	if got.Status.State == podtracev1alpha1.SessionStateFailed {
		t.Fatalf("a fleet maxDuration under the Job limit must let the session run, got %+v", got.Status.Conditions)
	}
}
