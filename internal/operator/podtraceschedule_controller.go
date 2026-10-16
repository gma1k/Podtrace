package operator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// Tunable knobs. Defined as vars (not consts) so envtests can shorten
// them without changing controller code.
var (
	scheduleResyncFloor = 5 * time.Second

	scheduleResyncCeiling = 60 * time.Second

	scheduleSessionNameFmt = "%s-%d"
)

// PodTraceScheduleReconciler turns a PodTraceSchedule CR into a stream
// of owned PodTraceSession resources.
type PodTraceScheduleReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	nowFn func() time.Time
}

// +kubebuilder:rbac:groups=podtrace.io,resources=podtraceschedules,verbs=get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=podtrace.io,resources=podtraceschedules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=podtrace.io,resources=podtraceschedules/finalizers,verbs=update
// +kubebuilder:rbac:groups=podtrace.io,resources=podtracesessions,verbs=get;list;watch;create;update;patch;delete

func (r *PodTraceScheduleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("podtraceschedule", req.String())

	var sch podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, req.NamespacedName, &sch); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get PodTraceSchedule: %w", err)
	}

	now := r.now()

	children, err := r.listOwnedSessions(ctx, &sch)
	if err != nil {
		return ctrl.Result{}, err
	}
	active, succeeded, failed := classifySessions(children)

	if sch.Spec.Suspend != nil && *sch.Spec.Suspend {
		if err := r.applyHistoryLimits(ctx, &sch, succeeded, failed); err != nil {
			return ctrl.Result{}, err
		}
		r.refreshStatus(&sch, active, mostRecentSuccess(succeeded))
		r.setCondition(&sch, ConditionPaused, metav1.ConditionTrue, "Suspended", "schedule suspended by spec.suspend")
		r.setCondition(&sch, ConditionReconciled, metav1.ConditionTrue, "Suspended", "schedule suspended; no sessions run")
		if err := r.patchStatus(ctx, &sch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: scheduleResyncCeiling}, nil
	}
	r.setCondition(&sch, ConditionPaused, metav1.ConditionFalse, "NotSuspended", "")

	if err := validateManagedCRName("PodTraceSchedule", sch.Name); err != nil {
		r.setCondition(&sch, ConditionDegraded, metav1.ConditionTrue, "NameTooLong", err.Error())
		r.refreshStatus(&sch, active, nil)
		if perr := r.patchStatus(ctx, &sch); perr != nil {
			return ctrl.Result{}, perr
		}
		return ctrl.Result{}, nil
	}

	if err := podtracev1alpha1.ValidateSessionTemplateMetadata(sch.Spec.SessionTemplate.Metadata); err != nil {
		r.setCondition(&sch, ConditionDegraded, metav1.ConditionTrue, "SessionTemplateInvalid", err.Error())
		r.refreshStatus(&sch, active, nil)
		if perr := r.patchStatus(ctx, &sch); perr != nil {
			return ctrl.Result{}, perr
		}
		return ctrl.Result{}, nil
	}

	if sch.Spec.Trigger != nil {
		return r.reconcileTrigger(ctx, &sch, active, succeeded, failed, now)
	}

	cronSched, loc, err := r.parseSchedule(&sch)
	if err != nil {
		r.setCondition(&sch, ConditionDegraded, metav1.ConditionTrue, "ScheduleInvalid", err.Error())
		r.refreshStatus(&sch, active, nil)
		if perr := r.patchStatus(ctx, &sch); perr != nil {
			return ctrl.Result{}, perr
		}
		return ctrl.Result{}, nil
	}

	base := sch.CreationTimestamp.Time
	if sch.Status.LastScheduleTime != nil {
		base = sch.Status.LastScheduleTime.Time
	}
	nextRun := cronSched.Next(base.In(loc))

	requeue := requeueAfter(nextRun, now)
	if now.Before(nextRun) {
		if err := r.applyHistoryLimits(ctx, &sch, succeeded, failed); err != nil {
			return ctrl.Result{}, err
		}
		r.refreshStatus(&sch, active, mostRecentSuccess(succeeded))
		r.setCondition(&sch, ConditionDegraded, metav1.ConditionFalse, "Scheduled", "")
		r.setCondition(&sch, ConditionReconciled, metav1.ConditionTrue, "Scheduled",
			fmt.Sprintf("next run at %s", nextRun.Format(time.RFC3339)))
		if err := r.patchStatus(ctx, &sch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeue}, nil
	}

	if sch.Spec.StartingDeadlineSeconds != nil {
		deadline := nextRun.Add(time.Duration(*sch.Spec.StartingDeadlineSeconds) * time.Second)
		if now.After(deadline) {
			logger.Info("missed run past startingDeadlineSeconds; skipping",
				"scheduledTime", nextRun, "now", now)
			t := metav1.NewTime(nextRun)
			sch.Status.LastScheduleTime = &t
			if err := r.applyHistoryLimits(ctx, &sch, succeeded, failed); err != nil {
				return ctrl.Result{}, err
			}
			r.refreshStatus(&sch, active, mostRecentSuccess(succeeded))
			r.setCondition(&sch, ConditionReconciled, metav1.ConditionTrue, "MissedDeadline",
				fmt.Sprintf("run at %s skipped: past startingDeadlineSeconds", nextRun.Format(time.RFC3339)))
			if err := r.patchStatus(ctx, &sch); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
	}

	// Bounded catch-up, mirroring CronJob's >100-missed-runs guard: without
	// startingDeadlineSeconds, every missed tick used to replay serially —
	// a schedule suspended for a month at "* * * * *" would fire tens of
	// thousands of stale sessions. Past the bound, the backlog is skipped
	// and the schedule resumes from now.
	missed := 0
	for t := nextRun; !t.After(now); t = cronSched.Next(t) {
		missed++
		if missed > maxMissedRuns {
			break
		}
	}
	if missed > maxMissedRuns {
		t := metav1.NewTime(now)
		sch.Status.LastScheduleTime = &t
		if err := r.applyHistoryLimits(ctx, &sch, succeeded, failed); err != nil {
			return ctrl.Result{}, err
		}
		r.refreshStatus(&sch, active, mostRecentSuccess(succeeded))
		r.setCondition(&sch, ConditionReconciled, metav1.ConditionTrue, "TooManyMissedRuns",
			fmt.Sprintf("more than %d missed runs since %s; backlog skipped, resuming from now", maxMissedRuns, base.Format(time.RFC3339)))
		if err := r.patchStatus(ctx, &sch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueAfter(cronSched.Next(now), now)}, nil
	}

	// MaxActiveSessions safety valve: independent of ConcurrencyPolicy.
	// When the cap is hit we behave like Forbid for this tick — run is
	// skipped, condition records the reason. Run history GC even on the
	// skip, otherwise stale completed children would accumulate.
	if cap := sch.Spec.MaxActiveSessions; cap != nil && *cap > 0 && len(active) >= int(*cap) {
		logger.Info("MaxActiveSessions reached; skipping run",
			"active", len(active), "cap", *cap)
		if err := r.applyHistoryLimits(ctx, &sch, succeeded, failed); err != nil {
			return ctrl.Result{}, err
		}
		skipped := skipDueRuns(&sch, cronSched, nextRun, now)
		r.refreshStatus(&sch, active, mostRecentSuccess(succeeded))
		r.setCondition(&sch, ConditionReconciled, metav1.ConditionTrue, "ActiveLimitReached",
			fmt.Sprintf("run at %s skipped: %d active session(s) >= maxActiveSessions=%d",
				skipped.Format(time.RFC3339), len(active), *cap))
		if err := r.patchStatus(ctx, &sch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: requeueAfter(cronSched.Next(skipped), now)}, nil
	}

	switch sch.Spec.ConcurrencyPolicy {
	case podtracev1alpha1.ForbidConcurrent:
		if len(active) > 0 {
			logger.Info("Forbid: skipping run while sessions active", "active", len(active))
			if err := r.applyHistoryLimits(ctx, &sch, succeeded, failed); err != nil {
				return ctrl.Result{}, err
			}
			skipped := skipDueRuns(&sch, cronSched, nextRun, now)
			r.refreshStatus(&sch, active, mostRecentSuccess(succeeded))
			r.setCondition(&sch, ConditionReconciled, metav1.ConditionTrue, "Forbidden",
				fmt.Sprintf("run at %s skipped: %d active session(s)", skipped.Format(time.RFC3339), len(active)))
			if err := r.patchStatus(ctx, &sch); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: requeueAfter(cronSched.Next(skipped), now)}, nil
		}
	case podtracev1alpha1.ReplaceConcurrent:
		for i := range active {
			if err := r.Delete(ctx, &active[i]); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("delete active session %s: %w", active[i].Name, err)
			}
		}
	}

	session, created, err := r.ensureSessionForRun(ctx, &sch, nextRun)
	if err != nil {
		if apierrors.IsForbidden(err) && strings.Contains(err.Error(), "being terminated") {
			logger.Info("namespace terminating; stopping schedule reconcile", "err", err)
			return ctrl.Result{}, nil
		}
		r.setCondition(&sch, ConditionDegraded, metav1.ConditionTrue, "CreateSession", err.Error())
		if perr := r.patchStatus(ctx, &sch); perr != nil {
			return ctrl.Result{}, perr
		}
		return ctrl.Result{}, err
	}
	r.setCondition(&sch, ConditionDegraded, metav1.ConditionFalse, "Reconciled", "")

	t := metav1.NewTime(nextRun)
	sch.Status.LastScheduleTime = &t
	if created {
		logger.Info("created PodTraceSession", "session", session.Name, "scheduledTime", nextRun)
	}

	children, err = r.listOwnedSessions(ctx, &sch)
	if err != nil {
		return ctrl.Result{}, err
	}
	active, succeeded, failed = classifySessions(children)
	if err := r.applyHistoryLimits(ctx, &sch, succeeded, failed); err != nil {
		return ctrl.Result{}, err
	}

	r.refreshStatus(&sch, active, mostRecentSuccess(succeeded))
	r.setCondition(&sch, ConditionReconciled, metav1.ConditionTrue, "Triggered",
		fmt.Sprintf("session %s created for scheduled run at %s", session.Name, nextRun.Format(time.RFC3339)))

	if err := r.patchStatus(ctx, &sch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeueAfter(cronSched.Next(nextRun), now)}, nil
}

func (r *PodTraceScheduleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.nowFn == nil {
		r.nowFn = time.Now
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("podtraceschedule").
		For(&podtracev1alpha1.PodTraceSchedule{}).
		Owns(&podtracev1alpha1.PodTraceSession{}).
		Watches(&corev1.Event{},
			handler.EnqueueRequestsFromMapFunc(r.mapEventToTriggerSchedules),
			builder.WithPredicates(alertEventPredicate())).
		WithOptions(defaultControllerOptions()).
		Complete(r)
}

func (r *PodTraceScheduleReconciler) now() time.Time {
	if r.nowFn != nil {
		return r.nowFn()
	}
	return time.Now()
}

// parseSchedule returns the parsed cron schedule and its location.
func (r *PodTraceScheduleReconciler) parseSchedule(sch *podtracev1alpha1.PodTraceSchedule) (interface {
	Next(time.Time) time.Time
}, *time.Location, error) {
	loc := time.Local
	if sch.Spec.TimeZone != nil && *sch.Spec.TimeZone != "" {
		l, err := time.LoadLocation(*sch.Spec.TimeZone)
		if err != nil {
			return nil, nil, fmt.Errorf("timezone %q: %w", *sch.Spec.TimeZone, err)
		}
		loc = l
	}
	parsed, err := podtracev1alpha1.ParseSchedule(sch.Spec.Schedule)
	if err != nil {
		return nil, nil, err
	}
	return parsed, loc, nil
}

// listOwnedSessions returns every PodTraceSession owned by the schedule.
func (r *PodTraceScheduleReconciler) listOwnedSessions(ctx context.Context, sch *podtracev1alpha1.PodTraceSchedule) ([]podtracev1alpha1.PodTraceSession, error) {
	var all podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &all, client.InNamespace(sch.Namespace)); err != nil {
		return nil, fmt.Errorf("list child sessions: %w", err)
	}
	out := make([]podtracev1alpha1.PodTraceSession, 0, len(all.Items))
	for i := range all.Items {
		if isOwnedBy(&all.Items[i], sch) {
			out = append(out, all.Items[i])
		}
	}
	return out, nil
}

func isOwnedBy(obj metav1.Object, owner *podtracev1alpha1.PodTraceSchedule) bool {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.UID == owner.UID && ref.Kind == "PodTraceSchedule" {
			return true
		}
	}
	return false
}

// classifySessions splits children into active / succeeded / failed by
// session state.
func classifySessions(sessions []podtracev1alpha1.PodTraceSession) (active, succeeded, failed []podtracev1alpha1.PodTraceSession) {
	for i := range sessions {
		s := sessions[i]
		switch s.Status.State {
		case podtracev1alpha1.SessionStateCompleted:
			succeeded = append(succeeded, s)
		case podtracev1alpha1.SessionStateFailed:
			failed = append(failed, s)
		default:
			active = append(active, s)
		}
	}
	return
}

func mostRecentSuccess(succeeded []podtracev1alpha1.PodTraceSession) *metav1.Time {
	var latest *metav1.Time
	for i := range succeeded {
		ct := succeeded[i].Status.CompletionTime
		if ct == nil {
			continue
		}
		if latest == nil || ct.After(latest.Time) {
			latest = ct
		}
	}
	return latest
}

func (r *PodTraceScheduleReconciler) ensureSessionForRun(ctx context.Context, sch *podtracev1alpha1.PodTraceSchedule, runTime time.Time) (*podtracev1alpha1.PodTraceSession, bool, error) {
	name := scheduledSessionName(sch.Name, runTime)
	session := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: sch.Namespace,
		},
	}
	created := false
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, session, func() error {
		if session.CreationTimestamp.IsZero() {
			session.Spec = *sch.Spec.SessionTemplate.Spec.DeepCopy()
		}
		labels := map[string]string{}
		for k, v := range sch.Spec.SessionTemplate.Metadata.Labels {
			labels[k] = v
		}
		labels[LabelManagedBy] = ManagedByValue
		labels[LabelComponent] = ComponentSession
		labels[LabelSchedule] = sch.Name
		session.Labels = mergeLabels(session.Labels, labels)

		anns := map[string]string{}
		for k, v := range sch.Spec.SessionTemplate.Metadata.Annotations {
			anns[k] = v
		}
		anns["podtrace.io/scheduled-at"] = runTime.UTC().Format(time.RFC3339)
		session.Annotations = mergeLabels(session.Annotations, anns)

		return controllerutil.SetControllerReference(sch, session, r.Scheme)
	})
	if err != nil {
		return nil, false, fmt.Errorf("ensure session for scheduled run %s: %w", runTime.Format(time.RFC3339), err)
	}
	if op == controllerutil.OperationResultCreated {
		created = true
	}
	return session, created, nil
}

// scheduledSessionName is deterministic and idempotent. Length-bounded
// to fit Kubernetes' 63-char label limit.
func scheduledSessionName(scheduleName string, runTime time.Time) string {
	raw := fmt.Sprintf(scheduleSessionNameFmt, scheduleName, runTime.Unix())
	if len(raw) > 63 {
		trail := fmt.Sprintf("-%d", runTime.Unix())
		raw = truncateNamePrefix(scheduleName, 63-len(trail)) + trail
	}
	return raw
}

// skipDueRuns records every run due by now as skipped, the way a CronJob
// skips a run that Forbid or a cap holds back: lastScheduleTime moves to
// the most recent due run, so the skipped ticks do not replay one by one
// once the active sessions finish. It returns that run.
func skipDueRuns(sch *podtracev1alpha1.PodTraceSchedule, cronSched interface{ Next(time.Time) time.Time }, nextRun, now time.Time) time.Time {
	latest := nextRun
	for i := 0; i < maxMissedRuns; i++ {
		next := cronSched.Next(latest)
		if next.After(now) {
			break
		}
		latest = next
	}
	t := metav1.NewTime(latest)
	sch.Status.LastScheduleTime = &t
	return latest
}

// truncateNamePrefix cuts name to at most n bytes for use as the head of a
// generated object name, dropping trailing '-' and '.' so the cut never
// leaves an empty or non-alphanumeric DNS label such as "x.-1700000000".
func truncateNamePrefix(name string, n int) string {
	if len(name) > n {
		name = name[:n]
	}
	return strings.TrimRight(name, "-.")
}

func (r *PodTraceScheduleReconciler) applyHistoryLimits(ctx context.Context, sch *podtracev1alpha1.PodTraceSchedule, succeeded, failed []podtracev1alpha1.PodTraceSession) error {
	if lim := sch.Spec.SuccessfulSessionsHistoryLimit; lim != nil {
		if err := r.gcOldest(ctx, succeeded, int(*lim)); err != nil {
			return fmt.Errorf("gc successful: %w", err)
		}
	}
	if lim := sch.Spec.FailedSessionsHistoryLimit; lim != nil {
		if err := r.gcOldest(ctx, failed, int(*lim)); err != nil {
			return fmt.Errorf("gc failed: %w", err)
		}
	}
	return nil
}

func (r *PodTraceScheduleReconciler) gcOldest(ctx context.Context, sessions []podtracev1alpha1.PodTraceSession, keep int) error {
	if len(sessions) <= keep {
		return nil
	}
	sortByCompletion(sessions) // ascending: oldest first
	toDelete := sessions[:len(sessions)-keep]
	for i := range toDelete {
		if err := r.Delete(ctx, &toDelete[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete %s: %w", toDelete[i].Name, err)
		}
	}
	return nil
}

func sortByCompletion(sessions []podtracev1alpha1.PodTraceSession) {
	sort.SliceStable(sessions, func(i, j int) bool {
		a := keyFor(sessions[i])
		b := keyFor(sessions[j])
		return a.Before(b)
	})
}

func keyFor(s podtracev1alpha1.PodTraceSession) time.Time {
	if s.Status.CompletionTime != nil {
		return s.Status.CompletionTime.Time
	}
	return s.CreationTimestamp.Time
}

func (r *PodTraceScheduleReconciler) refreshStatus(sch *podtracev1alpha1.PodTraceSchedule, active []podtracev1alpha1.PodTraceSession, lastSuccess *metav1.Time) {
	refs := make([]corev1.ObjectReference, 0, len(active))
	for i := range active {
		s := active[i]
		refs = append(refs, corev1.ObjectReference{
			APIVersion:      podtracev1alpha1.GroupVersion.String(),
			Kind:            "PodTraceSession",
			Namespace:       s.Namespace,
			Name:            s.Name,
			UID:             s.UID,
			ResourceVersion: s.ResourceVersion,
		})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	sch.Status.Active = refs
	if lastSuccess != nil {
		sch.Status.LastSuccessfulTime = lastSuccess
	}
	sch.Status.ObservedGeneration = sch.Generation
}

func (r *PodTraceScheduleReconciler) setCondition(sch *podtracev1alpha1.PodTraceSchedule, condType string, status metav1.ConditionStatus, reason, message string) {
	sch.Status.Conditions = upsertCondition(sch.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: sch.Generation,
	})
}

// patchStatus writes the computed status, retrying on optimistic-concurrency
// conflicts by re-reading the latest object and re-applying the computed
// status. Conflicts used to be swallowed with no requeue — for a schedule
// that silently dropped status.lastScheduleTime, and under ReplaceConcurrent
// the re-derived tick first deleted the session it had just created.
func (r *PodTraceScheduleReconciler) patchStatus(ctx context.Context, sch *podtracev1alpha1.PodTraceSchedule) error {
	desired := sch.Status.DeepCopy()
	key := types.NamespacedName{Namespace: sch.Namespace, Name: sch.Name}
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest podtracev1alpha1.PodTraceSchedule
		if err := r.Get(ctx, key, &latest); err != nil {
			return err
		}
		latest.Status = *desired.DeepCopy()
		return r.Status().Update(ctx, &latest)
	})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("update status: %w", err)
	}
	return nil
}

// maxMissedRuns bounds catch-up replay after a long suspension or operator
// outage, mirroring CronJob's "too many missed start times" guard.
const maxMissedRuns = 100

// requeueAfter clamps the gap between now and nextRun into the
// [floor, ceiling] window.
func requeueAfter(nextRun, now time.Time) time.Duration {
	d := nextRun.Sub(now)
	if d < scheduleResyncFloor {
		d = scheduleResyncFloor
	}
	if d > scheduleResyncCeiling {
		d = scheduleResyncCeiling
	}
	return d
}
