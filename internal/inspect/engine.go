package inspect

import (
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

const DefaultBudget = 512

// The engine turns "true right now" into "worth telling someone".
type Observer interface {
	IssueActivated(issue detector.Issue)
	IssueCleared(issue detector.Issue)
}

// Options configures an Engine.
type Options struct {
	Source FamilySource

	Gatherer prometheus.Gatherer

	Registerer prometheus.Registerer

	Rules      []Rule
	Thresholds Thresholds
	Observer   Observer

	Budget int

	Now func() time.Time
}

// Engine evaluates rules on a schedule and reports the issues that stick.
type Engine struct {
	source   FamilySource
	gatherer prometheus.Gatherer
	rules    []Rule
	limits   Thresholds
	observer Observer
	budget   int
	now      func() time.Time

	previous Snapshot

	mu      sync.Mutex
	pending map[string]time.Time
	active  map[string]detector.Issue
	since   map[string]time.Time
	causes  map[detector.IssueRef][]detector.Cause
	edges   []Edge

	issueActive   *prometheus.GaugeVec
	evaluations   prometheus.Counter
	evalFailures  prometheus.Counter
	transitions   *prometheus.CounterVec
	trackedActive prometheus.Gauge
	budgetDropped prometheus.Counter
	untriggerable prometheus.Counter
}

// New builds an Engine and registers its metrics.
func New(opts Options) (*Engine, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Budget <= 0 {
		opts.Budget = DefaultBudget
	}
	if opts.Rules == nil {
		opts.Rules = Rules()
	}
	if opts.Thresholds.unset() {
		opts.Thresholds = DefaultThresholds()
	}

	e := &Engine{
		source:   opts.Source,
		gatherer: opts.Gatherer,
		rules:    opts.Rules,
		limits:   opts.Thresholds,
		observer: opts.Observer,
		budget:   opts.Budget,
		now:      opts.Now,
		pending:  map[string]time.Time{},
		active:   map[string]detector.Issue{},
		since:    map[string]time.Time{},

		issueActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "podtrace_issue_active",
			Help: "1 while a continuous inspection is firing for a subject, by issue id and severity. Deliberately a metric rather than a status condition: every agent would contend on the same object.",
		}, []string{"id", "namespace", "workload", "pod", "resource", "severity"}),

		evaluations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "podtrace_inspections_evaluations_total",
			Help: "Rule evaluations completed. A flat counter means the inspection loop is not running.",
		}),

		evalFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "podtrace_inspections_failures_total",
			Help: "Evaluations that could not gather metrics. Inspections are blind while this rises.",
		}),

		transitions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "podtrace_inspections_transitions_total",
			Help: "Issue state changes, by id and transition. activated and escalated are what trigger a session; cleared is the recovery.",
		}, []string{"id", "transition"}),

		trackedActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "podtrace_inspections_tracked_issues",
			Help: "Issue instances currently tracked, counted against the inspection budget.",
		}),

		budgetDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "podtrace_inspections_dropped_total",
			Help: "Issue instances not tracked because the budget was full. Non-zero means some issues are going unreported.",
		}),

		untriggerable: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "podtrace_inspections_untriggerable_total",
			Help: "Activated issues that named no pod, so they could be graphed but could not start a session. Non-zero means the metric-to-session loop is open.",
		}),
	}

	if opts.Registerer != nil {
		for _, c := range []prometheus.Collector{
			e.issueActive, e.evaluations, e.evalFailures, e.transitions,
			e.trackedActive, e.budgetDropped, e.untriggerable,
		} {
			if err := opts.Registerer.Register(c); err != nil {
				return nil, err
			}
		}
	}
	return e, nil
}

// Active returns the currently firing issues, ordered for stable output.
func (e *Engine) Active() []detector.Issue {
	active := e.ActiveIssues()
	out := make([]detector.Issue, 0, len(active))
	for _, a := range active {
		out = append(out, a.Issue)
	}
	return out
}

// ActiveIssue is a firing issue as of the latest evaluation, with the time
// it activated and its likely causes among the issues active with it.
type ActiveIssue struct {
	detector.Issue
	Since time.Time
}

// Edges returns the workload-to-Service calls the latest evaluation saw.
func (e *Engine) Edges() []Edge {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Edge(nil), e.edges...)
}

// ActiveIssues returns the firing issues as the latest evaluation saw them:
// their message and evidence are current, not those of the moment they
// activated. Safe to call while Evaluate runs.
func (e *Engine) ActiveIssues() []ActiveIssue {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ActiveIssue, 0, len(e.active))
	for key, issue := range e.active {
		issue.Causes = e.causes[issue.Ref()]
		out = append(out, ActiveIssue{Issue: issue, Since: e.since[key]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// Evaluate runs one pass: gather, evaluate every rule, apply each rule's hold
// time, and report the transitions.
func (e *Engine) Evaluate() ([]detector.Issue, error) {
	now := e.now()

	var snapshot Snapshot
	var gatherErr error
	if e.source != nil {
		snapshot = TakeFrom(e.source, now)
	} else {
		snapshot, gatherErr = Take(e.gatherer, now)
		if gatherErr != nil {
			e.evalFailures.Inc()
			if snapshot.IsZero() {
				return nil, gatherErr
			}
		}
	}

	window := Window{Prev: e.previous, Cur: snapshot}
	e.previous = snapshot
	e.evaluations.Inc()

	firing := map[string]detector.Issue{}
	forDuration := map[string]time.Duration{}
	for _, rule := range e.rules {
		hold := e.limits.holdTimeFor(rule)
		for _, issue := range rule.Eval(window, e.limits) {
			key := issue.Key()
			forDuration[key] = hold
			if existing, ok := firing[key]; ok && severityRank(existing.Severity) >= severityRank(issue.Severity) {
				continue
			}
			firing[key] = issue
		}
	}

	e.mu.Lock()
	activated := e.applyHoldTime(firing, forDuration, now)
	cleared := e.clearResolved(firing)
	e.causes = localCauses(e.active)
	e.edges = Edges(window)
	for i := range activated {
		activated[i].Causes = e.causes[activated[i].Ref()]
	}
	e.trackedActive.Set(float64(len(e.active)))
	e.mu.Unlock()

	var notify []func()
	if e.observer != nil {
		for _, issue := range activated {
			notify = append(notify, func() { e.observer.IssueActivated(issue) })
		}
		for _, issue := range cleared {
			notify = append(notify, func() { e.observer.IssueCleared(issue) })
		}
	}

	for _, n := range notify {
		n()
	}
	return activated, gatherErr
}

// applyHoldTime promotes conditions that have held long enough and keeps an
// active issue current. It returns the issues that activated or escalated.
func (e *Engine) applyHoldTime(firing map[string]detector.Issue, forDuration map[string]time.Duration, now time.Time) []detector.Issue {
	var activated []detector.Issue

	for _, key := range sortedIssueKeys(firing) {
		issue := firing[key]

		since, tracked := e.pending[key]
		if !tracked {
			if _, alreadyActive := e.active[key]; !alreadyActive && len(e.pending) >= e.budget {
				e.budgetDropped.Inc()
				continue
			}
			e.pending[key] = now
			since = now
		}

		if now.Sub(since) < forDuration[key] {
			continue
		}

		if previous, ok := e.active[key]; ok {
			e.active[key] = issue
			if previous.Severity == issue.Severity {
				continue
			}
			e.setInactive(previous)
			e.setActive(issue)
			if severityRank(issue.Severity) < severityRank(previous.Severity) {
				continue
			}
			e.transitions.WithLabelValues(string(issue.ID), "escalated").Inc()
		} else {
			e.active[key] = issue
			e.since[key] = now
			e.setActive(issue)
			e.transitions.WithLabelValues(string(issue.ID), "activated").Inc()
		}

		if issue.Subject.Pod == "" {
			e.untriggerable.Inc()
		}
		activated = append(activated, issue)
	}
	return activated
}

// clearResolved drops issues whose condition no longer holds and returns
// them.
func (e *Engine) clearResolved(firing map[string]detector.Issue) []detector.Issue {
	var cleared []detector.Issue
	for key := range e.pending {
		if _, still := firing[key]; !still {
			delete(e.pending, key)
		}
	}
	for _, key := range sortedIssueKeys(e.active) {
		if _, still := firing[key]; still {
			continue
		}
		issue := e.active[key]
		delete(e.active, key)
		delete(e.since, key)
		e.setInactive(issue)
		e.transitions.WithLabelValues(string(issue.ID), "cleared").Inc()
		cleared = append(cleared, issue)
	}
	return cleared
}

func (e *Engine) setActive(issue detector.Issue) {
	e.issueActive.WithLabelValues(gaugeLabels(issue)...).Set(1)
}

func (e *Engine) setInactive(issue detector.Issue) {
	e.issueActive.DeleteLabelValues(gaugeLabels(issue)...)
}

// gaugeLabels renders podtrace_issue_active's label values.
func gaugeLabels(issue detector.Issue) []string {
	return []string{
		string(issue.ID),
		issue.Subject.Namespace,
		issue.Subject.Workload,
		issue.Subject.Pod,
		issue.Subject.Resource,
		string(issue.Severity),
	}
}

func sortedIssueKeys(m map[string]detector.Issue) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func severityRank(s alerting.AlertSeverity) int {
	switch s {
	case alerting.SeverityFatal:
		return 4
	case alerting.SeverityCritical:
		return 3
	case alerting.SeverityError:
		return 2
	case alerting.SeverityWarning:
		return 1
	default:
		return 0
	}
}
