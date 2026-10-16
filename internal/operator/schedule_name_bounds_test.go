package operator

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestScheduledSessionName_TruncationStaysValid(t *testing.T) {
	name := strings.Repeat("a", 51) + ".-" + strings.Repeat("b", 20)
	got := scheduledSessionName(name, time.Unix(1_700_000_000, 0))
	if len(got) > 63 {
		t.Fatalf("name %q is %d characters", got, len(got))
	}
	if errs := validation.IsDNS1123Subdomain(got); len(errs) > 0 {
		t.Errorf("scheduledSessionName = %q is not a valid object name: %v", got, errs)
	}
}

func TestTriggeredSessionName_TruncationStaysValid(t *testing.T) {
	name := strings.Repeat("a", 42) + ".-" + strings.Repeat("b", 20)
	got := triggeredSessionName(name, "obs", "hog", time.Unix(1_700_000_000, 0))
	if len(got) > 63 {
		t.Fatalf("name %q is %d characters", got, len(got))
	}
	if errs := validation.IsDNS1123Subdomain(got); len(errs) > 0 {
		t.Errorf("triggeredSessionName = %q is not a valid object name: %v", got, errs)
	}
}

func TestScheduleReconcile_NameTooLongDegrades(t *testing.T) {
	name := strings.Repeat("s", 64)
	sch := cronSchedule(name, "default")
	sch.CreationTimestamp = metav1.NewTime(fixedScheduleNow.Add(-time.Hour))
	r, _ := newScheduleReconciler(t, sch)

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: "default"},
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(context.Background(), &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Items) != 0 {
		t.Errorf("a schedule whose name cannot be a label value must create no sessions, got %d", len(sessions.Items))
	}
	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "NameTooLong" {
		t.Errorf("degraded condition = %+v, want NameTooLong", cond)
	}
}
