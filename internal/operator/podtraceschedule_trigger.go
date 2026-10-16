package operator

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// alertEventPredicate limits the Event watch to podtrace alert Events so the
// controller is not woken by every Event in the cluster.
func alertEventPredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		ev, ok := obj.(*corev1.Event)
		return ok && ev.Reason == alerting.EventReasonAlert
	})
}

// mapEventToTriggerSchedules enqueues every trigger-mode schedule when a
// podtrace alert Event fires.
func (r *PodTraceScheduleReconciler) mapEventToTriggerSchedules(ctx context.Context, obj client.Object) []reconcile.Request {
	ev, ok := obj.(*corev1.Event)
	if !ok || ev.Reason != alerting.EventReasonAlert {
		return nil
	}
	var schedules podtracev1alpha1.PodTraceScheduleList
	if err := r.List(ctx, &schedules); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range schedules.Items {
		if schedules.Items[i].Spec.Trigger == nil {
			continue
		}
		reqs = append(reqs, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&schedules.Items[i]),
		})
	}
	return reqs
}

// Trigger-mode defaults. Vars (not consts) so envtests can shorten them.
var (
	defaultTriggerCooldown = 10 * time.Minute

	defaultTriggerMaxSessionsPerHour int32 = 6

	triggerRateWindow = time.Hour

	triggerResyncInterval = 60 * time.Second
)

// triggerSourceKindForAlertSource maps an agent alert Source token to the
// TriggerSourceKind a schedule selects on.
func triggerSourceKindForAlertSource(source string) (podtracev1alpha1.TriggerSourceKind, bool) {
	switch source {
	case alerting.AlertSourceResourceMonitor, alerting.AlertSourceResourceMonitorBPF:
		return podtracev1alpha1.TriggerSourceResourceAlert, true
	case alerting.AlertSourceOOM:
		return podtracev1alpha1.TriggerSourceOOMKill, true
	case alerting.AlertSourceErrorRate:
		return podtracev1alpha1.TriggerSourceErrorRate, true
	case alerting.AlertSourceIssue:
		return podtracev1alpha1.TriggerSourceIssue, true
	default:
		return "", false
	}
}

// severityRank orders alert severities. Higher fires when a source's
// MinSeverity is lower-or-equal. "error" sits below "warning" so it never
// satisfies a warning-or-higher gate.
func severityRank(sev string) int {
	switch sev {
	case string(alerting.SeverityFatal):
		return 3
	case string(alerting.SeverityCritical):
		return 2
	case string(alerting.SeverityWarning):
		return 1
	default:
		return 0
	}
}

// effectiveMinSeverity resolves an empty MinSeverity to the safe default
// (critical), so a warning does not spawn a privileged Job unless opted in.
func effectiveMinSeverity(s string) string {
	if s == "" {
		return string(alerting.SeverityCritical)
	}
	return s
}

// alertEvent is the parsed, trigger-relevant view of a Kubernetes Event.
type alertEvent struct {
	Namespace string
	PodName   string
	Kind      podtracev1alpha1.TriggerSourceKind
	Severity  string
	At        time.Time

	IssueID string
	Reason  string
}

// parseAlertEvent extracts the trigger view from a raw Event, or false when
// the Event is not a podtrace alert or lacks the fields a trigger needs.
func parseAlertEvent(ev *corev1.Event) (alertEvent, bool) {
	if ev == nil || ev.Reason != alerting.EventReasonAlert {
		return alertEvent{}, false
	}
	if ev.InvolvedObject.Kind != "Pod" || ev.InvolvedObject.Name == "" {
		return alertEvent{}, false
	}
	if ev.Source.Component != alerting.EventComponent && ev.ReportingController != alerting.EventComponent {
		return alertEvent{}, false
	}
	if ev.InvolvedObject.Namespace != "" && ev.InvolvedObject.Namespace != ev.Namespace {
		return alertEvent{}, false
	}
	kind, ok := triggerSourceKindForAlertSource(ev.Annotations[alerting.AnnotationAlertSource])
	if !ok {
		return alertEvent{}, false
	}
	out := alertEvent{
		Namespace: ev.Namespace,
		PodName:   ev.InvolvedObject.Name,
		Kind:      kind,
		Severity:  ev.Annotations[alerting.AnnotationAlertSeverity],
		At:        eventTime(ev),
	}
	if kind == podtracev1alpha1.TriggerSourceIssue {
		out.IssueID = knownIssueID(ev.Annotations[alerting.AnnotationIssueID])
		out.Reason = truncateReason(ev.Message)
	}
	return out, true
}

// knownIssueID returns id when it is in the issue registry, and "" otherwise,
// so an Event cannot put an arbitrary string on a session.
func knownIssueID(id string) string {
	for _, known := range detector.Registry {
		if string(known) == id {
			return id
		}
	}
	return ""
}

// maxTriggerReasonBytes bounds the reason copied onto a session's annotations.
const maxTriggerReasonBytes = 512

func truncateReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) <= maxTriggerReasonBytes {
		return reason
	}
	cut := maxTriggerReasonBytes
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut]
}

// eventTime returns the most recent observation time recorded on the Event.
func eventTime(ev *corev1.Event) time.Time {
	if !ev.LastTimestamp.IsZero() {
		return ev.LastTimestamp.Time
	}
	if !ev.EventTime.IsZero() {
		return ev.EventTime.Time
	}
	return ev.CreationTimestamp.Time
}

// matchesTriggerSources reports whether the event's kind+severity satisfies
// any of the trigger's configured sources.
func matchesTriggerSources(ev alertEvent, sources []podtracev1alpha1.TriggerSource) bool {
	got := severityRank(ev.Severity)
	for _, src := range sources {
		if src.Kind != ev.Kind {
			continue
		}
		if src.IssueID != "" && src.IssueID != ev.IssueID {
			continue
		}
		if got >= severityRank(effectiveMinSeverity(src.MinSeverity)) {
			return true
		}
	}
	return false
}

// lastFiringForPod returns the most recent firing recorded for a pod, or nil.
func lastFiringForPod(firings []podtracev1alpha1.TriggerFiring, namespace, pod string) *podtracev1alpha1.TriggerFiring {
	var latest *podtracev1alpha1.TriggerFiring
	for i := range firings {
		f := &firings[i]
		if f.Namespace != namespace || f.PodName != pod {
			continue
		}
		if latest == nil || f.Time.After(latest.Time.Time) {
			latest = f
		}
	}
	return latest
}

// eligibleToFire reports whether a session may fire for an alert event given
// the pod's last firing and the cooldown.
func eligibleToFire(last *podtracev1alpha1.TriggerFiring, eventAt, now time.Time, cooldown time.Duration) bool {
	if last == nil {
		return true
	}
	if !eventAt.After(last.Time.Time) {
		return false
	}
	return now.Sub(last.Time.Time) >= cooldown
}

// countFiringsInWindow counts firings whose time falls within [now-window, now].
func countFiringsInWindow(firings []podtracev1alpha1.TriggerFiring, now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	n := 0
	for i := range firings {
		if firings[i].Time.After(cutoff) {
			n++
		}
	}
	return n
}

// firingRetention is how long a firing stays in the status log: long enough
// to enforce both the hourly rate cap and the per-pod cooldown.
func firingRetention(cooldown time.Duration) time.Duration {
	if cooldown > triggerRateWindow {
		return cooldown
	}
	return triggerRateWindow
}

// pruneFirings drops firings older than the retention horizon so the status
// log stays bounded.
func pruneFirings(firings []podtracev1alpha1.TriggerFiring, now time.Time, cooldown time.Duration) []podtracev1alpha1.TriggerFiring {
	cutoff := now.Add(-firingRetention(cooldown))
	out := make([]podtracev1alpha1.TriggerFiring, 0, len(firings))
	for i := range firings {
		if firings[i].Time.After(cutoff) {
			out = append(out, firings[i])
		}
	}
	return out
}

func triggerCooldown(t *podtracev1alpha1.TriggerSpec) time.Duration {
	if t.Cooldown != nil && t.Cooldown.Duration > 0 {
		return t.Cooldown.Duration
	}
	return defaultTriggerCooldown
}

func triggerMaxPerHour(t *podtracev1alpha1.TriggerSpec) int32 {
	if t.MaxSessionsPerHour != nil && *t.MaxSessionsPerHour > 0 {
		return *t.MaxSessionsPerHour
	}
	return defaultTriggerMaxSessionsPerHour
}

func triggerConcurrency(t *podtracev1alpha1.TriggerSpec) podtracev1alpha1.ConcurrencyPolicy {
	if t.ConcurrencyPolicy == "" {
		return podtracev1alpha1.ForbidConcurrent
	}
	return t.ConcurrencyPolicy
}

// reconcileTrigger drives event-driven ("flight recorder") session creation.
func (r *PodTraceScheduleReconciler) reconcileTrigger(ctx context.Context, sch *podtracev1alpha1.PodTraceSchedule, active, succeeded, failed []podtracev1alpha1.PodTraceSession, now time.Time) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	tr := sch.Spec.Trigger
	cooldown := triggerCooldown(tr)

	if err := r.applyHistoryLimits(ctx, sch, succeeded, failed); err != nil {
		return ctrl.Result{}, err
	}

	namespaces, deniedNamespaces, err := r.triggerNamespaces(ctx, sch)
	if err != nil {
		r.setCondition(sch, ConditionDegraded, metav1.ConditionTrue, "NamespaceSelectorInvalid", err.Error())
		return ctrl.Result{RequeueAfter: triggerResyncInterval}, r.finishTriggerStatus(ctx, sch, active, now, cooldown)
	}
	if len(deniedNamespaces) > 0 {
		r.setCondition(sch, ConditionDegraded, metav1.ConditionFalse, "SomeNamespacesDenied",
			crossNamespaceDeniedMessage(sch.Namespace, deniedNamespaces))
	} else {
		r.setCondition(sch, ConditionDegraded, metav1.ConditionFalse, "Reconciled", "")
	}

	events, err := r.listAlertEvents(ctx, namespaces)
	if err != nil {
		return ctrl.Result{}, err
	}

	eligible, err := r.filterEligibleEvents(ctx, sch, events)
	if err != nil {
		return ctrl.Result{}, err
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].At.Before(eligible[j].At) })

	firings := triggerFirings(sch)
	maxPerHour := triggerMaxPerHour(tr)
	remaining := int(maxPerHour) - countFiringsInWindow(firings, now, triggerRateWindow)
	toFire, rateLimited := selectEventsToFire(eligible, firings, now, cooldown, remaining)

	switch triggerConcurrency(tr) {
	case podtracev1alpha1.ForbidConcurrent:
		if len(active) > 0 {
			r.setCondition(sch, ConditionReconciled, metav1.ConditionTrue, "Forbidden",
				fmt.Sprintf("%d active triggered session(s); not firing", len(active)))
			return ctrl.Result{RequeueAfter: triggerResyncInterval}, r.finishTriggerStatus(ctx, sch, active, now, cooldown)
		}
	case podtracev1alpha1.ReplaceConcurrent:
		if err := r.replaceActiveSessions(ctx, sch, active, toFire); err != nil {
			return ctrl.Result{}, err
		}
	}

	firedThisPass := 0
	for _, ev := range toFire {
		session, err := r.ensureTriggeredSession(ctx, sch, ev)
		if err != nil {
			if apierrors.IsForbidden(err) && strings.Contains(err.Error(), "being terminated") {
				logger.Info("namespace terminating; stopping trigger reconcile", "err", err)
				return ctrl.Result{}, nil
			}
			logger.Error(err, "triggered session not created; skipping event",
				"pod", ev.Namespace+"/"+ev.PodName, "kind", ev.Kind)
			r.setCondition(sch, ConditionDegraded, metav1.ConditionTrue, "CreateSession", err.Error())
			continue
		}
		firings = append(firings, podtracev1alpha1.TriggerFiring{
			PodName:     ev.PodName,
			Namespace:   ev.Namespace,
			Time:        metav1.NewTime(now),
			SessionName: session,
		})
		firedThisPass++
		logger.Info("fired triggered session", "session", session, "pod", ev.Namespace+"/"+ev.PodName,
			"kind", ev.Kind, "severity", ev.Severity)
	}

	sch.Status.Trigger = &podtracev1alpha1.TriggerStatus{RecentFirings: pruneFirings(firings, now, cooldown)}

	switch {
	case rateLimited:
		r.setCondition(sch, ConditionReconciled, metav1.ConditionTrue, "RateLimited",
			fmt.Sprintf("maxSessionsPerHour=%d reached; %d fired this pass", maxPerHour, firedThisPass))
	case firedThisPass > 0:
		r.setCondition(sch, ConditionReconciled, metav1.ConditionTrue, "Triggered",
			fmt.Sprintf("fired %d session(s) from matching alerts", firedThisPass))
	default:
		r.setCondition(sch, ConditionReconciled, metav1.ConditionTrue, "Watching",
			"no matching alert eligible to fire")
	}

	return ctrl.Result{RequeueAfter: triggerResyncInterval}, r.finishTriggerStatus(ctx, sch, active, now, cooldown)
}

// replaceActiveSessions deletes the active sessions a Replace trigger
// supersedes, and only once a session that does not exist yet is about to
// start.
func (r *PodTraceScheduleReconciler) replaceActiveSessions(ctx context.Context, sch *podtracev1alpha1.PodTraceSchedule, active []podtracev1alpha1.PodTraceSession, toFire []alertEvent) error {
	wanted := make(map[string]struct{}, len(toFire))
	for _, ev := range toFire {
		wanted[triggeredSessionName(sch.Name, ev.Namespace, ev.PodName, ev.At)] = struct{}{}
	}
	activeNames := make(map[string]struct{}, len(active))
	for i := range active {
		activeNames[active[i].Name] = struct{}{}
	}
	starting := false
	for name := range wanted {
		if _, running := activeNames[name]; !running {
			starting = true
		}
	}
	if !starting {
		return nil
	}
	for i := range active {
		if _, keep := wanted[active[i].Name]; keep {
			continue
		}
		if err := r.Delete(ctx, &active[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("replace: delete active session %s: %w", active[i].Name, err)
		}
	}
	return nil
}

// selectEventsToFire picks, oldest first, the events that may fire this pass:
// each pod at most once, past its cooldown, and no more than remaining in
// total.
func selectEventsToFire(eligible []alertEvent, firings []podtracev1alpha1.TriggerFiring, now time.Time, cooldown time.Duration, remaining int) (toFire []alertEvent, rateLimited bool) {
	oldest := now.Add(-firingRetention(cooldown))
	picked := map[string]struct{}{}
	for _, ev := range eligible {
		if ev.At.Before(oldest) {
			continue
		}
		key := ev.Namespace + "/" + ev.PodName
		if _, dup := picked[key]; dup {
			continue
		}
		if !eligibleToFire(lastFiringForPod(firings, ev.Namespace, ev.PodName), ev.At, now, cooldown) {
			continue
		}
		if remaining <= 0 {
			return toFire, true
		}
		picked[key] = struct{}{}
		toFire = append(toFire, ev)
		remaining--
	}
	return toFire, false
}

// finishTriggerStatus refreshes active-session status and persists.
func (r *PodTraceScheduleReconciler) finishTriggerStatus(ctx context.Context, sch *podtracev1alpha1.PodTraceSchedule, active []podtracev1alpha1.PodTraceSession, now time.Time, cooldown time.Duration) error {
	r.refreshStatus(sch, active, nil)
	if sch.Status.Trigger == nil {
		sch.Status.Trigger = &podtracev1alpha1.TriggerStatus{RecentFirings: pruneFirings(triggerFirings(sch), now, cooldown)}
	}
	return r.patchStatus(ctx, sch)
}

func triggerFirings(sch *podtracev1alpha1.PodTraceSchedule) []podtracev1alpha1.TriggerFiring {
	if sch.Status.Trigger == nil {
		return nil
	}
	return sch.Status.Trigger.RecentFirings
}

// triggerNamespaces resolves the namespaces whose alert Events this trigger
// may consume: the schedule's own namespace, plus any namespace its
// NamespaceSelector matches that consents via the tenancy annotation.
func (r *PodTraceScheduleReconciler) triggerNamespaces(ctx context.Context, sch *podtracev1alpha1.PodTraceSchedule) (allowed, denied []string, err error) {
	if sch.Spec.Trigger.NamespaceSelector == nil {
		return []string{sch.Namespace}, nil, nil
	}
	allowed, denied, err = ResolveNamespaceSelector(ctx, r.Client, sch.Spec.Trigger.NamespaceSelector, sch.Namespace)
	if err != nil {
		return nil, nil, err
	}
	if !containsString(allowed, sch.Namespace) {
		allowed = append(allowed, sch.Namespace)
	}
	return allowed, denied, nil
}

// listAlertEvents returns podtrace alert Events across the given namespaces.
// This list is the durable backstop: even if a watch delivery is dropped, a
// missed alert is caught here on the next resync while the Event lives in
// etcd.
func (r *PodTraceScheduleReconciler) listAlertEvents(ctx context.Context, namespaces []string) ([]alertEvent, error) {
	seen := map[string]struct{}{}
	var out []alertEvent
	for _, ns := range namespaces {
		var list corev1.EventList
		if err := r.List(ctx, &list, client.InNamespace(ns)); err != nil {
			return nil, fmt.Errorf("list events in %s: %w", ns, err)
		}
		for i := range list.Items {
			parsed, ok := parseAlertEvent(&list.Items[i])
			if !ok {
				continue
			}
			key := string(list.Items[i].UID)
			if key == "" {
				key = parsed.Namespace + "/" + parsed.PodName + "/" + string(parsed.Kind) + "/" + parsed.At.String()
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, parsed)
		}
	}
	return out, nil
}

// filterEligibleEvents keeps only events matching the trigger's sources and
// (when set) its pod Selector.
func (r *PodTraceScheduleReconciler) filterEligibleEvents(ctx context.Context, sch *podtracev1alpha1.PodTraceSchedule, events []alertEvent) ([]alertEvent, error) {
	tr := sch.Spec.Trigger
	var sel labels.Selector
	if tr.Selector != nil {
		s, err := metav1.LabelSelectorAsSelector(tr.Selector)
		if err != nil {
			return nil, fmt.Errorf("spec.trigger.selector: %w", err)
		}
		sel = s
	}
	out := make([]alertEvent, 0, len(events))
	for _, ev := range events {
		if !matchesTriggerSources(ev, tr.Sources) {
			continue
		}
		if sel != nil {
			var pod corev1.Pod
			if err := r.Get(ctx, client.ObjectKey{Namespace: ev.Namespace, Name: ev.PodName}, &pod); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, fmt.Errorf("get pod %s/%s for selector match: %w", ev.Namespace, ev.PodName, err)
			}
			if !sel.Matches(labels.Set(pod.Labels)) {
				continue
			}
		}
		out = append(out, ev)
	}
	return out, nil
}

// ensureTriggeredSession creates (idempotently) a PodTraceSession that traces
// the alerting pod, stamped with the triggering-alert context.
func (r *PodTraceScheduleReconciler) ensureTriggeredSession(ctx context.Context, sch *podtracev1alpha1.PodTraceSchedule, ev alertEvent) (string, error) {
	name := triggeredSessionName(sch.Name, ev.Namespace, ev.PodName, ev.At)
	session := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: sch.Namespace},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, session, func() error {
		if session.CreationTimestamp.IsZero() {
			session.Spec = *sch.Spec.SessionTemplate.Spec.DeepCopy()
			session.Spec.Selector = nil
			session.Spec.NamespaceSelector = nil
			session.Spec.PodRefs = []podtracev1alpha1.PodRef{{Namespace: ev.Namespace, Name: ev.PodName}}
		}
		labelsMap := map[string]string{}
		for k, v := range sch.Spec.SessionTemplate.Metadata.Labels {
			labelsMap[k] = v
		}
		labelsMap[LabelManagedBy] = ManagedByValue
		labelsMap[LabelComponent] = ComponentSession
		labelsMap[LabelSchedule] = sch.Name
		session.Labels = mergeLabels(session.Labels, labelsMap)

		anns := map[string]string{}
		for k, v := range sch.Spec.SessionTemplate.Metadata.Annotations {
			anns[k] = v
		}
		anns[AnnotationTriggeredBy] = string(ev.Kind)
		anns[AnnotationTriggerSeverity] = ev.Severity
		anns[AnnotationTriggerPod] = ev.Namespace + "/" + ev.PodName
		anns[AnnotationTriggeredAt] = ev.At.UTC().Format(time.RFC3339)
		if ev.IssueID != "" {
			anns[alerting.AnnotationIssueID] = ev.IssueID
		}
		if ev.Reason != "" {
			anns[AnnotationTriggerReason] = ev.Reason
		}
		session.Annotations = mergeLabels(session.Annotations, anns)

		return controllerutil.SetControllerReference(sch, session, r.Scheme)
	})
	if err != nil {
		return "", fmt.Errorf("ensure triggered session for %s/%s: %w", ev.Namespace, ev.PodName, err)
	}
	return name, nil
}

// triggeredSessionName is deterministic per (schedule, pod, alert time) so a
// re-reconcile of the same alert is idempotent, and bounded to 63 chars.
func triggeredSessionName(scheduleName, namespace, pod string, at time.Time) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(namespace + "/" + pod))
	suffix := fmt.Sprintf("-%08x-%d", h.Sum32(), at.Unix())
	return truncateNamePrefix(scheduleName, 63-len(suffix)) + suffix
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
