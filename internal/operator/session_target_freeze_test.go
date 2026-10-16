package operator

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func fannedOutSession() *podtracev1alpha1.PodTraceSession {
	return sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.CreationTimestamp = pendingDeadlineCreated
		s.Status.State = podtracev1alpha1.SessionStateRunning
		s.Status.Jobs = []podtracev1alpha1.SessionJobRef{{Node: "n1", Name: SessionJobName(s.UID, "n1")}}
	})
}

func runningSessionJob(s *podtracev1alpha1.PodTraceSession, node string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SessionJobName(s.UID, node),
			Namespace: sessMoreSysNS,
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: s.Name,
				LabelSessionNS:   s.Namespace,
				LabelNodeName:    node,
			},
		},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "podtrace", Image: "ghcr.io/gma1k/podtrace:test"}},
		}}},
		Status: batchv1.JobStatus{Active: 1},
	}
}

func frozenTargetsReconciler(t *testing.T, objects ...client.Object) *PodTraceSessionReconciler {
	t.Helper()
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objects...).Build()
	return &PodTraceSessionReconciler{
		Client:          c,
		Scheme:          scheme,
		SystemNamespace: sessMoreSysNS,
		nowFn:           func() time.Time { return pendingDeadlineCreated.Add(pendingMatchDeadline + time.Hour) },
	}
}

func TestSessionReconcile_TargetPodGoneKeepsRunningJobs(t *testing.T) {
	s := fannedOutSession()
	objects := sessMoreFanOutObjects()[1:]
	objects = append(objects, s, runningSessionJob(s, "n1"))
	r := frozenTargetsReconciler(t, objects...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	if got.Status.State != podtracev1alpha1.SessionStateRunning {
		t.Fatalf("state = %q, want Running while the Job still captures", got.Status.State)
	}
}

func TestSessionReconcile_TargetPodMovedDoesNotFanOutAgain(t *testing.T) {
	s := fannedOutSession()
	moved := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1-new", Namespace: "default", Labels: map[string]string{"a": "b"}},
		Spec:       corev1.PodSpec{NodeName: "n2"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	objects := sessMoreFanOutObjects()[1:]
	objects = append(objects, s, moved, runningSessionJob(s, "n1"))
	r := frozenTargetsReconciler(t, objects...)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var jobs batchv1.JobList
	if err := r.List(context.Background(), &jobs, client.InNamespace(sessMoreSysNS)); err != nil {
		t.Fatal(err)
	}
	for i := range jobs.Items {
		if jobs.Items[i].Labels[LabelNodeName] == "n2" {
			t.Fatal("a pod that moved after fan-out must not get a fresh full-duration Job on its new node")
		}
	}
}

func TestFannedOutNodes(t *testing.T) {
	got := fannedOutNodes([]podtracev1alpha1.SessionJobRef{{Node: "b"}, {Node: "a"}, {Node: "b"}, {Node: ""}})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("fannedOutNodes = %v, want [a b]", got)
	}
}
