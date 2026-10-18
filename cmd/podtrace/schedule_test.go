package main

import (
	corev1 "k8s.io/api/core/v1"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func mkSchedule() *podtracev1alpha1.PodTraceSchedule {
	return &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nightly",
			Namespace: "obs",
			UID:       types.UID("sched-uid"),
		},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Metadata: podtracev1alpha1.PodTraceSessionTemplateMetadata{
					Labels:      map[string]string{"env": "prod"},
					Annotations: map[string]string{"team": "obs"},
				},
				Spec: podtracev1alpha1.PodTraceSessionSpec{
					Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
					Duration:    metav1.Duration{Duration: 30 * time.Second},
					ExporterRef: corev1.LocalObjectReference{Name: "prod-otlp"},
				},
			},
		},
	}
}

func TestBuildManualSession_HonorsOwnership(t *testing.T) {
	s := buildManualSession(mkSchedule(), time.Unix(1700000000, 0), false)
	if got, want := s.Namespace, "obs"; got != want {
		t.Fatalf("namespace: %q want %q", got, want)
	}
	if len(s.OwnerReferences) != 1 {
		t.Fatalf("expected owner ref, got %v", s.OwnerReferences)
	}
	if s.OwnerReferences[0].Name != "nightly" {
		t.Fatalf("owner name = %q", s.OwnerReferences[0].Name)
	}
	if s.Labels["podtrace.io/schedule"] != "nightly" || s.Labels["podtrace.io/trigger"] != "manual" {
		t.Fatalf("labels: %v", s.Labels)
	}
	if s.Labels["env"] != "prod" {
		t.Fatalf("template labels not propagated: %v", s.Labels)
	}
	if s.Annotations["team"] != "obs" {
		t.Fatalf("template annotations not propagated: %v", s.Annotations)
	}
	if !strings.Contains(s.Name, "nightly") {
		t.Fatalf("name doesn't contain schedule prefix: %q", s.Name)
	}
}

func TestBuildManualSession_ForceSkipsOwnership(t *testing.T) {
	s := buildManualSession(mkSchedule(), time.Now(), true)
	if len(s.OwnerReferences) != 0 {
		t.Fatalf("force should skip ownership, got %v", s.OwnerReferences)
	}
}

func TestManualSessionName_LengthBounded(t *testing.T) {
	long := strings.Repeat("x", 70)
	got := manualSessionName(long, time.Now())
	if len(got) > 63 {
		t.Fatalf("name overflowed: %d > 63 (%q)", len(got), got)
	}
}

func TestBuildManualSession_DoesNotShareSpec(t *testing.T) {
	sch := mkSchedule()
	s := buildManualSession(sch, time.Now(), false)
	s.Spec.Duration = metav1.Duration{Duration: time.Hour}
	if sch.Spec.SessionTemplate.Spec.Duration.Duration == time.Hour {
		t.Fatal("session spec aliased the schedule template (mutation leaked back)")
	}
}

func TestTwoManualTriggersInTheSameSecondGetDistinctNames(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if a, b := manualSessionName("nightly", now), manualSessionName("nightly", now); a == b {
		t.Fatalf("both triggers were named %q", a)
	}
}

func TestManualSessionNamesAreValidResourceNames(t *testing.T) {
	for _, schedule := range []string{"nightly", strings.Repeat("x", 70)} {
		name := manualSessionName(schedule, time.Now())
		if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 || len(name) > 63 {
			t.Errorf("%q is not a valid session name: %v", name, errs)
		}
	}
}
