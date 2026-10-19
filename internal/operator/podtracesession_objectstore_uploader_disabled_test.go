package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func sessionPod(name string, initContainers ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "podtrace-system",
			Labels: map[string]string{
				LabelSessionName: "diag",
				LabelSessionNS:   "default",
			},
		},
	}
	for _, n := range initContainers {
		pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{Name: n})
	}
	return pod
}

func TestHarvestReportLocation_PodsWithoutUploaderMeanUploaderDisabled(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(harvestScheme(t)).WithObjects(sessionPod("diag-pod")).Build()

	obs, err := harvestReportLocation(context.Background(), c, sessionWithObjectStore(""), "podtrace-system")
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	if !obs.UploaderDisabled {
		t.Fatal("UploaderDisabled = false, want true when no session pod carries the uploader sidecar")
	}
}

func TestHarvestReportLocation_UploaderInSpecIsNotDisabled(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(harvestScheme(t)).WithObjects(sessionPod("diag-pod", reportUploaderContainerName)).Build()

	obs, err := harvestReportLocation(context.Background(), c, sessionWithObjectStore(""), "podtrace-system")
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	if obs.UploaderDisabled {
		t.Fatal("UploaderDisabled = true, want false when the uploader sidecar is in the pod spec")
	}
}

func TestHarvestReportLocation_NoPodsYetIsNotDisabled(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(harvestScheme(t)).Build()

	obs, err := harvestReportLocation(context.Background(), c, sessionWithObjectStore(""), "podtrace-system")
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	if obs.UploaderDisabled {
		t.Fatal("UploaderDisabled = true before any session pod exists, want false")
	}
}

func TestApplyReportUploadStatus_UploaderDisabledIsFalseWithReason(t *testing.T) {
	s := sessionWithObjectStore("")

	applyReportUploadStatus(s, reportUploadObservation{UploaderDisabled: true})

	var found *metav1.Condition
	for i := range s.Status.Conditions {
		if s.Status.Conditions[i].Type == ConditionReportUploaded {
			found = &s.Status.Conditions[i]
		}
	}
	if found == nil {
		t.Fatal("ReportUploaded condition missing")
		return
	}
	if found.Status != metav1.ConditionFalse || found.Reason != "UploaderDisabled" {
		t.Fatalf("ReportUploaded = %s/%s, want False/UploaderDisabled", found.Status, found.Reason)
	}
	if s.Status.ReportFailureReason != "" {
		t.Fatalf("ReportFailureReason = %q, want empty", s.Status.ReportFailureReason)
	}
}
