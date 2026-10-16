package operator

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestNodesAtCapacity_JobWithoutNodeLabelIgnored(t *testing.T) {
	const ns = "team-a"
	scheme := newOperatorScheme(t)

	labelled := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "labelled",
			Namespace: "podtrace-system",
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: "other",
				LabelSessionNS:   ns,
				LabelNodeName:    "n1",
			},
		},
	}
	unlabelled := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-node-label",
			Namespace: "podtrace-system",
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: "other",
				LabelSessionNS:   ns,
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(labelled, unlabelled).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	over, err := r.nodesAtCapacity(context.Background(), []string{"n1"}, 1, ns, "self")
	if err != nil {
		t.Fatalf("nodesAtCapacity: %v", err)
	}
	if len(over) != 1 || over[0] != "n1" {
		t.Errorf("expected n1 over capacity from the labelled Job only, got %v", over)
	}
}

func capacityBlockedReconciler(t *testing.T, at time.Time, s *podtracev1alpha1.PodTraceSession) *PodTraceSessionReconciler {
	t.Helper()
	objects := sessMoreFanOutObjects()
	tc := objects[2].(*podtracev1alpha1.TracerConfig)
	tc.Spec.MaxConcurrentSessionsPerNode = 1
	other := runningSessionJob(sessMoreSession(func(o *podtracev1alpha1.PodTraceSession) {
		o.Name, o.UID = "other", "uid-other"
	}), "n1")
	objects = append(objects, s, other)
	r := frozenTargetsReconciler(t, objects...)
	r.nowFn = func() time.Time { return at }
	return r
}

func TestSessionReconcile_CapacityWaitPastDeadlineFailsTerminally(t *testing.T) {
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.CreationTimestamp = pendingDeadlineCreated })
	r := capacityBlockedReconciler(t, pendingDeadlineCreated.Add(pendingMatchDeadline+time.Minute), s)

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := (&fakeGetter{r: r}).session(t)
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Fatalf("state = %q, want Failed", got.Status.State)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "NodeCapacityDeadlineExceeded" {
		t.Fatalf("degraded condition = %+v, want NodeCapacityDeadlineExceeded", cond)
	}
}

func TestSessionReconcile_CapacityWaitBeforeDeadlineRequeues(t *testing.T) {
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.CreationTimestamp = pendingDeadlineCreated })
	r := capacityBlockedReconciler(t, pendingDeadlineCreated.Add(time.Minute), s)

	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("a session waiting on capacity must requeue")
	}
	got := (&fakeGetter{r: r}).session(t)
	if got.Status.State == podtracev1alpha1.SessionStateFailed {
		t.Fatal("a session inside the deadline must keep waiting")
	}
}
