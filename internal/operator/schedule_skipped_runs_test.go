package operator

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func scheduleBehindByFourRuns(name string, mutate func(*podtracev1alpha1.PodTraceSchedule)) *podtracev1alpha1.PodTraceSchedule {
	return schBranchAt(name, fixedScheduleNow.Add(-time.Hour), func(s *podtracev1alpha1.PodTraceSchedule) {
		last := metav1.NewTime(fixedScheduleNow.Add(-20 * time.Minute))
		s.Status.LastScheduleTime = &last
		mutate(s)
	})
}

func assertSkippedToLatestRun(t *testing.T, r *PodTraceScheduleReconciler, sch *podtracev1alpha1.PodTraceSchedule) {
	t.Helper()
	if _, err := reconcileSchBranch(r, sch); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(context.Background(), types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.LastScheduleTime == nil || !got.Status.LastScheduleTime.Time.Equal(fixedScheduleNow) {
		t.Errorf("lastScheduleTime = %v, want the most recent due run %v", got.Status.LastScheduleTime, fixedScheduleNow)
	}
}

func TestScheduleReconcile_ForbidSkipAdvancesLastScheduleTime(t *testing.T) {
	sch := scheduleBehindByFourRuns("forbid-skip", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.ConcurrencyPolicy = podtracev1alpha1.ForbidConcurrent
	})
	r := newSchBranchReconciler(t, interceptor.Funcs{}, sch, schBranchActive(sch, "running"))
	assertSkippedToLatestRun(t, r, sch)
}

func TestScheduleReconcile_ActiveLimitSkipAdvancesLastScheduleTime(t *testing.T) {
	limit := int32(1)
	sch := scheduleBehindByFourRuns("cap-skip", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.MaxActiveSessions = &limit
	})
	r := newSchBranchReconciler(t, interceptor.Funcs{}, sch, schBranchActive(sch, "running"))
	assertSkippedToLatestRun(t, r, sch)
}
