package operator

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
)

func TestTriggerSourceKindForAlertSource(t *testing.T) {
	cases := []struct {
		source string
		want   podtracev1alpha1.TriggerSourceKind
		ok     bool
	}{
		{alerting.AlertSourceResourceMonitor, podtracev1alpha1.TriggerSourceResourceAlert, true},
		{alerting.AlertSourceResourceMonitorBPF, podtracev1alpha1.TriggerSourceResourceAlert, true},
		{alerting.AlertSourceOOM, podtracev1alpha1.TriggerSourceOOMKill, true},
		{alerting.AlertSourceErrorRate, podtracev1alpha1.TriggerSourceErrorRate, true},
		{"crypto-detector", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := triggerSourceKindForAlertSource(c.source)
		if got != c.want || ok != c.ok {
			t.Errorf("triggerSourceKindForAlertSource(%q) = (%q,%v), want (%q,%v)", c.source, got, ok, c.want, c.ok)
		}
	}
}

func TestMatchesTriggerSources(t *testing.T) {
	sources := []podtracev1alpha1.TriggerSource{
		{Kind: podtracev1alpha1.TriggerSourceResourceAlert, MinSeverity: "critical"},
		{Kind: podtracev1alpha1.TriggerSourceOOMKill},
	}
	cases := []struct {
		name string
		ev   alertEvent
		want bool
	}{
		{"resource critical matches", alertEvent{Kind: podtracev1alpha1.TriggerSourceResourceAlert, Severity: "critical"}, true},
		{"resource fatal exceeds min", alertEvent{Kind: podtracev1alpha1.TriggerSourceResourceAlert, Severity: "fatal"}, true},
		{"resource warning below min", alertEvent{Kind: podtracev1alpha1.TriggerSourceResourceAlert, Severity: "warning"}, false},
		{"oom defaults to critical min, warning drops", alertEvent{Kind: podtracev1alpha1.TriggerSourceOOMKill, Severity: "warning"}, false},
		{"oom critical matches default", alertEvent{Kind: podtracev1alpha1.TriggerSourceOOMKill, Severity: "critical"}, true},
		{"unconfigured kind never matches", alertEvent{Kind: podtracev1alpha1.TriggerSourceErrorRate, Severity: "fatal"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchesTriggerSources(c.ev, sources); got != c.want {
				t.Errorf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestParseAlertEvent(t *testing.T) {
	at := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	srcAnn := func(source, severity string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Annotations: map[string]string{
			alerting.AnnotationAlertSource:   source,
			alerting.AnnotationAlertSeverity: severity,
		}}
	}
	validMeta := srcAnn(alerting.AlertSourceOOM, "fatal")
	validMeta.Namespace = "prod"
	valid := &corev1.Event{
		ObjectMeta:     validMeta,
		Reason:         alerting.EventReasonAlert,
		Source:         corev1.EventSource{Component: alerting.EventComponent},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "prod", Name: "checkout-7f"},
		LastTimestamp:  metav1.NewTime(at),
	}
	got, ok := parseAlertEvent(valid)
	if !ok {
		t.Fatal("valid alert event should parse")
	}
	if got.PodName != "checkout-7f" || got.Namespace != "prod" || got.Kind != podtracev1alpha1.TriggerSourceOOMKill || got.Severity != "fatal" || !got.At.Equal(at) {
		t.Errorf("unexpected parse: %+v", got)
	}

	rejects := map[string]*corev1.Event{
		"wrong reason": {ObjectMeta: srcAnn(alerting.AlertSourceOOM, "fatal"), Reason: "Scheduled", InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "p"}},
		"not a pod":    {ObjectMeta: srcAnn(alerting.AlertSourceOOM, "fatal"), Reason: alerting.EventReasonAlert, InvolvedObject: corev1.ObjectReference{Kind: "Node", Name: "n"}},
		"no pod name":  {ObjectMeta: srcAnn(alerting.AlertSourceOOM, "fatal"), Reason: alerting.EventReasonAlert, InvolvedObject: corev1.ObjectReference{Kind: "Pod"}},
		"unknown src":  {ObjectMeta: srcAnn("crypto-detector", "fatal"), Reason: alerting.EventReasonAlert, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "p"}},
	}
	for name, ev := range rejects {
		if _, ok := parseAlertEvent(ev); ok {
			t.Errorf("%s: expected reject", name)
		}
	}
}

func TestEligibleToFire(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	cooldown := 10 * time.Minute
	firing := func(min int) *podtracev1alpha1.TriggerFiring {
		return &podtracev1alpha1.TriggerFiring{Time: metav1.NewTime(now.Add(time.Duration(min) * time.Minute))}
	}
	cases := []struct {
		name    string
		last    *podtracev1alpha1.TriggerFiring
		eventAt time.Time
		want    bool
	}{
		{"no prior firing fires", nil, now, true},
		{"event not newer than last firing", firing(-5), now.Add(-6 * time.Minute), false},
		{"cooldown still active", firing(-3), now.Add(-2 * time.Minute), false},
		{"newer event and cooldown elapsed", firing(-11), now.Add(-1 * time.Minute), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := eligibleToFire(c.last, c.eventAt, now, cooldown); got != c.want {
				t.Errorf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestCountFiringsInWindowAndPrune(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	firings := []podtracev1alpha1.TriggerFiring{
		{PodName: "a", Time: metav1.NewTime(now.Add(-10 * time.Minute))},
		{PodName: "b", Time: metav1.NewTime(now.Add(-40 * time.Minute))},
		{PodName: "c", Time: metav1.NewTime(now.Add(-90 * time.Minute))},
	}
	if n := countFiringsInWindow(firings, now, time.Hour); n != 2 {
		t.Errorf("countFiringsInWindow = %d, want 2", n)
	}
	pruned := pruneFirings(firings, now, 10*time.Minute)
	if len(pruned) != 2 {
		t.Errorf("pruneFirings kept %d, want 2 (>1h dropped)", len(pruned))
	}
}

func TestPruneFirings_CooldownLongerThanRateWindowExtendsRetention(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	firings := []podtracev1alpha1.TriggerFiring{
		{PodName: "a", Time: metav1.NewTime(now.Add(-90 * time.Minute))},
		{PodName: "b", Time: metav1.NewTime(now.Add(-5 * time.Hour))},
	}
	if kept := pruneFirings(firings, now, 10*time.Minute); len(kept) != 0 {
		t.Errorf("with a short cooldown the 1h window governs, kept %d, want 0", len(kept))
	}
	kept := pruneFirings(firings, now, 4*time.Hour)
	if len(kept) != 1 || kept[0].PodName != "a" {
		t.Errorf("a cooldown longer than the rate window must retain within it, kept %+v", kept)
	}
}

func TestSeverityRank(t *testing.T) {
	cases := map[string]int{
		string(alerting.SeverityFatal):    3,
		string(alerting.SeverityCritical): 2,
		string(alerting.SeverityWarning):  1,
		string(alerting.SeverityError):    0,
		"":                                0,
		"nonsense":                        0,
	}
	for severity, want := range cases {
		if got := severityRank(severity); got != want {
			t.Errorf("severityRank(%q) = %d, want %d", severity, got, want)
		}
	}
	if severityRank(string(alerting.SeverityError)) >= severityRank(string(alerting.SeverityWarning)) {
		t.Error("error must rank below warning so it never satisfies a warning-or-higher gate")
	}
}

func TestEventTime_PrefersMostRecentObservation(t *testing.T) {
	last := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	event := time.Date(2026, 7, 27, 11, 0, 0, 0, time.UTC)
	created := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)

	all := &corev1.Event{
		ObjectMeta:    metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(created)},
		LastTimestamp: metav1.NewTime(last),
		EventTime:     metav1.NewMicroTime(event),
	}
	if got := eventTime(all); !got.Equal(last) {
		t.Errorf("eventTime = %v, want lastTimestamp %v", got, last)
	}

	noLast := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(created)},
		EventTime:  metav1.NewMicroTime(event),
	}
	if got := eventTime(noLast); !got.Equal(event) {
		t.Errorf("eventTime = %v, want eventTime %v", got, event)
	}

	onlyCreated := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(created)},
	}
	if got := eventTime(onlyCreated); !got.Equal(created) {
		t.Errorf("eventTime = %v, want creationTimestamp %v", got, created)
	}
}

func TestParseAlertEvent_FallsBackToEventNamespace(t *testing.T) {
	at := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod",
			Annotations: map[string]string{
				alerting.AnnotationAlertSource:   alerting.AlertSourceOOM,
				alerting.AnnotationAlertSeverity: "fatal",
			},
		},
		Reason:         alerting.EventReasonAlert,
		Source:         corev1.EventSource{Component: alerting.EventComponent},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "checkout-7f"},
		LastTimestamp:  metav1.NewTime(at),
	}
	got, ok := parseAlertEvent(ev)
	if !ok {
		t.Fatal("an Event without involvedObject.namespace should still parse")
		return
	}
	if got.Namespace != "prod" {
		t.Errorf("namespace = %q, want the Event's own namespace %q", got.Namespace, "prod")
	}
}

func TestLastFiringForPod(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	firings := []podtracev1alpha1.TriggerFiring{
		{PodName: "p", Namespace: "ns", Time: metav1.NewTime(now.Add(-20 * time.Minute))},
		{PodName: "p", Namespace: "ns", Time: metav1.NewTime(now.Add(-5 * time.Minute))},
		{PodName: "other", Namespace: "ns", Time: metav1.NewTime(now)},
	}
	got := lastFiringForPod(firings, "ns", "p")
	if got == nil || !got.Time.Time.Equal(now.Add(-5*time.Minute)) {
		t.Errorf("lastFiringForPod = %+v, want the -5m entry", got)
	}
	if lastFiringForPod(firings, "ns", "missing") != nil {
		t.Error("missing pod should return nil")
	}
}

func TestTriggerDefaults(t *testing.T) {
	empty := &podtracev1alpha1.TriggerSpec{}
	if triggerCooldown(empty) != defaultTriggerCooldown {
		t.Errorf("cooldown default = %v", triggerCooldown(empty))
	}
	if triggerMaxPerHour(empty) != defaultTriggerMaxSessionsPerHour {
		t.Errorf("maxPerHour default = %d", triggerMaxPerHour(empty))
	}
	if triggerConcurrency(empty) != podtracev1alpha1.ForbidConcurrent {
		t.Errorf("concurrency default = %q, want Forbid", triggerConcurrency(empty))
	}
	cd := metav1.Duration{Duration: 3 * time.Minute}
	max := int32(2)
	set := &podtracev1alpha1.TriggerSpec{Cooldown: &cd, MaxSessionsPerHour: &max, ConcurrencyPolicy: podtracev1alpha1.ReplaceConcurrent}
	if triggerCooldown(set) != 3*time.Minute || triggerMaxPerHour(set) != 2 || triggerConcurrency(set) != podtracev1alpha1.ReplaceConcurrent {
		t.Error("explicit trigger values not honored")
	}
}

func TestTriggeredSessionName(t *testing.T) {
	at := time.Unix(1753617600, 0)
	a := triggeredSessionName("nightly", "prod", "checkout-7f", at)
	b := triggeredSessionName("nightly", "prod", "checkout-7f", at)
	if a != b {
		t.Errorf("not deterministic: %q vs %q", a, b)
	}
	if len(a) > 63 {
		t.Errorf("name %q exceeds 63 chars", a)
	}
	if c := triggeredSessionName("nightly", "prod", "other-pod", at); c == a {
		t.Error("different pods must yield different names")
	}
	long := triggeredSessionName("this-is-a-very-long-schedule-name-that-exceeds-the-k8s-limit-easily", "prod", "p", at)
	if len(long) > 63 {
		t.Errorf("long schedule name not bounded: %d chars", len(long))
	}
}

func TestEveryTriggerSourceKindIsAcceptedByTheCRD(t *testing.T) {
	crd := repoFile(t, "deploy", "charts", "podtrace", "templates", "crds",
		"podtrace.io_podtraceschedules.yaml")

	for _, kind := range []podtracev1alpha1.TriggerSourceKind{
		podtracev1alpha1.TriggerSourceResourceAlert,
		podtracev1alpha1.TriggerSourceOOMKill,
		podtracev1alpha1.TriggerSourceErrorRate,
		podtracev1alpha1.TriggerSourceIssue,
	} {
		if !strings.Contains(crd, "- "+string(kind)) {
			t.Errorf("kind %q exists in Go but is not in the CRD enum; the API server would "+
				"reject a schedule using it even though the operator handles it", kind)
		}
	}
}

func TestAnIssueAlertMapsToTheIssueTriggerKind(t *testing.T) {
	got, ok := triggerSourceKindForAlertSource(alerting.AlertSourceIssue)
	if !ok || got != podtracev1alpha1.TriggerSourceIssue {
		t.Errorf("issue alerts map to %q,%v; want Issue,true. Without this a firing issue "+
			"cannot trigger the deep-dive session that explains it", got, ok)
	}
	if _, ok := triggerSourceKindForAlertSource("not_a_source"); ok {
		t.Error("an unknown alert source was mapped to a trigger kind")
	}
}

func TestParseAlertEvent_RejectsInvolvedObjectInAnotherNamespace(t *testing.T) {
	ev := podtraceAlertEvent("tenant-a", "hog")
	ev.InvolvedObject.Namespace = "tenant-b"
	if _, ok := parseAlertEvent(ev); ok {
		t.Error("an Event in tenant-a naming a pod in tenant-b must not parse")
	}
}

func TestParseAlertEvent_RequiresAgentComponent(t *testing.T) {
	ev := podtraceAlertEvent("obs", "hog")
	ev.Source = corev1.EventSource{Component: "kubectl"}
	if _, ok := parseAlertEvent(ev); ok {
		t.Error("an Event not reported by the podtrace agent must not parse")
	}
	ev.ReportingController = alerting.EventComponent
	if _, ok := parseAlertEvent(ev); !ok {
		t.Error("an events.k8s.io Event whose reportingController is the agent must parse")
	}
}

func TestSelectEventsToFire_IgnoresEventsOlderThanRetention(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	stale := resourceAlertFor("obs", "hog-old")
	stale.At = now.Add(-2 * triggerRateWindow)
	fresh := resourceAlertFor("obs", "hog-new")
	fresh.At = now.Add(-time.Minute)

	got, rateLimited := selectEventsToFire([]alertEvent{stale, fresh}, nil, now, defaultTriggerCooldown, 10)
	if rateLimited {
		t.Error("nothing was held back by the hourly cap")
	}
	if len(got) != 1 || got[0].PodName != "hog-new" {
		t.Errorf("only the event inside the retention window may fire, got %+v", got)
	}
}

func TestSelectEventsToFire_OnePerPodAndCapped(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	a1 := resourceAlertFor("obs", "a")
	a1.At = now.Add(-3 * time.Minute)
	a2 := resourceAlertFor("obs", "a")
	a2.At = now.Add(-2 * time.Minute)
	b := resourceAlertFor("obs", "b")
	b.At = now.Add(-time.Minute)

	got, rateLimited := selectEventsToFire([]alertEvent{a1, a2, b}, nil, now, defaultTriggerCooldown, 1)
	if len(got) != 1 || got[0].PodName != "a" {
		t.Errorf("want only the oldest pod-a alert, got %+v", got)
	}
	if !rateLimited {
		t.Error("pod b was held back by the cap and must report rate limiting")
	}
}
