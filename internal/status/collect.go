package status

import (
	"context"
	"fmt"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/inspect"
)

const (
	defaultWindow        = 10 * time.Second
	defaultScrapeTimeout = 10 * time.Second
	defaultProfileWait   = 30 * time.Second
	defaultConcurrency   = 16

	drainSettle     = 500 * time.Millisecond
	maxReadAttempts = 4

	familyDrainedAt     = "podtrace_agent_kernel_metrics_drained_timestamp_seconds"
	familyDrainInterval = "podtrace_agent_kernel_metrics_drain_interval_seconds"
	familySinceDrain    = "podtrace_agent_kernel_metrics_seconds_since_drain"
)

// Collector reads every agent and builds the report.
type Collector struct {
	Cluster Cluster
	Options Options

	Window        time.Duration
	ScrapeTimeout time.Duration
	ProfileWait   time.Duration
	Concurrency   int

	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error

	previous map[string]scrapeResult
}

type scrapeResult struct {
	snapshot inspect.Snapshot
	readAt   time.Time
	err      error
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Collector) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func orDefault(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return d
}

// bounded gives one API read the scrape deadline. The pod proxy is a
// long-running request the API server never times out, so without it one
// wedged agent or half-open connection would hang the command for good.
func (c *Collector) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, orDefault(c.ScrapeTimeout, defaultScrapeTimeout))
}

func (c *Collector) agents(ctx context.Context) ([]Agent, error) {
	actx, cancel := c.bounded(ctx)
	defer cancel()
	return c.Cluster.Agents(actx)
}

func (c *Collector) components(ctx context.Context) ([]Component, error) {
	actx, cancel := c.bounded(ctx)
	defer cancel()
	return c.Cluster.Components(actx)
}

// liveIssues reads every agent's /issues concurrently, each within the
// scrape deadline; an agent that fails is simply absent.
func (c *Collector) liveIssues(ctx context.Context, agents []Agent) map[string][]LiveIssue {
	out := make(map[string][]LiveIssue, len(agents))
	var mu sync.Mutex
	sem := c.semaphore()
	var wg sync.WaitGroup
	for _, a := range agents {
		wg.Add(1)
		go func(a Agent) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			actx, cancel := c.bounded(ctx)
			defer cancel()
			live, err := c.Cluster.ActiveIssues(actx, a)
			if err != nil {
				return
			}
			mu.Lock()
			out[a.Name] = live
			mu.Unlock()
		}(a)
	}
	wg.Wait()
	return out
}

// Collect reads the agents and returns the report.
func (c *Collector) Collect(ctx context.Context) (Report, error) {
	agents, err := c.agents(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("list podtrace agents: %w", err)
	}

	prev := c.previous
	window := time.Nanosecond
	if prev == nil {
		first := c.scrapeAll(ctx, agents, func(Agent) readAfter { return readAfter{fresh: true} })
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		prev = succeeded(first)
		window = orDefault(c.Window, defaultWindow)
	}
	cur := c.scrapeAll(ctx, agents, func(a Agent) readAfter {
		p := prev[a.Name]
		return readAfter{previous: p.snapshot, previousReadAt: p.readAt, window: window}
	})
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	readable := make([]Agent, 0, len(agents))
	for _, a := range agents {
		if cur[a.Name].err == nil {
			readable = append(readable, a)
		}
	}
	live := c.liveIssues(ctx, readable)

	scrapes := make([]AgentScrape, 0, len(agents))
	for _, a := range agents {
		res := cur[a.Name]
		s := AgentScrape{Agent: a, Err: res.err}
		if res.err == nil {
			s.Window = inspect.Window{Prev: prev[a.Name].snapshot, Cur: res.snapshot}
			if issues, ok := live[a.Name]; ok {
				s.Live, s.LiveRead = issues, true
			}
		}
		scrapes = append(scrapes, s)
	}
	c.previous = succeeded(cur)

	ectx, cancelEvents := c.bounded(ctx)
	events, eventsErr := c.Cluster.IssueEvents(ectx, c.Options.Namespace)
	cancelEvents()
	report := Build(scrapes, events, c.Options, c.now())
	if eventsErr != nil {
		report.Warnings = append(report.Warnings, "could not read the issue Events, so issues show "+
			"no message or start time: "+oneLine(eventsErr.Error()))
	}
	cctx, cancelCorrelations := c.bounded(ctx)
	correlation, err := c.Cluster.Correlations(cctx)
	cancelCorrelations()
	if err == nil {
		report.AttachCauses(correlation)
	} else if len(report.Issues) > 0 {
		report.Warnings = append(report.Warnings, "could not read the operator's issue correlation, "+
			"so likely causes are limited to each issue's own workload: "+oneLine(err.Error()))
	}
	report.Assess(c.components(ctx))
	return report, nil
}

// Health reads each agent once, with no rate window, and the components,
// and says whether podtrace is healthy.
func (c *Collector) Health(ctx context.Context) (Report, error) {
	agents, err := c.agents(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("list podtrace agents: %w", err)
	}
	reads := c.scrapeAll(ctx, agents, func(Agent) readAfter { return readAfter{} })
	scrapes := make([]AgentScrape, 0, len(agents))
	for _, a := range agents {
		res := reads[a.Name]
		scrapes = append(scrapes, AgentScrape{Agent: a, Err: res.err, Window: inspect.Window{Cur: res.snapshot}})
	}
	report := Build(scrapes, nil, c.Options, c.now())
	report.Assess(c.components(ctx))
	return report, nil
}

func succeeded(results map[string]scrapeResult) map[string]scrapeResult {
	out := make(map[string]scrapeResult, len(results))
	for name, r := range results {
		if r.err == nil {
			out[name] = r
		}
	}
	return out
}

// readAfter says when a read counts: fresh wants one taken just after a
// drain; otherwise the read must stand for a moment at least window after
// previous.
type readAfter struct {
	fresh          bool
	previous       inspect.Snapshot
	previousReadAt time.Time
	window         time.Duration
}

// before is how long to wait before the first read: the previous read says
// when the next useful one is, on the agent's clock and in elapsed time only.
func (want readAfter) before(now time.Time) time.Duration {
	if want.fresh || want.previous.IsZero() {
		return 0
	}
	clock, drained := drainClockOf(want.previous)
	if !drained {
		return want.previous.At.Add(want.window).Sub(now)
	}
	drains := (want.window + clock.interval - 1) / clock.interval
	return time.Duration(drains)*clock.interval - clock.since - now.Sub(want.previousReadAt) + drainSettle
}

// drainClock is what an agent says about its kernel drains, measured on its
// own clock, so no comparison with the reader's clock is ever needed.
type drainClock struct {
	at       time.Time
	since    time.Duration
	interval time.Duration
}

func drainClockOf(s inspect.Snapshot) (drainClock, bool) {
	gauge := func(name string) (float64, bool) {
		samples := s.Family(name)
		if len(samples) == 0 {
			return 0, false
		}
		return samples[0].Value, true
	}
	at, okAt := gauge(familyDrainedAt)
	since, okSince := gauge(familySinceDrain)
	interval, okInterval := gauge(familyDrainInterval)
	if !okAt || !okSince || !okInterval || at <= 0 || since < 0 || interval <= 0 {
		return drainClock{}, false
	}
	return drainClock{
		at:       time.Unix(0, int64(at*1e9)),
		since:    time.Duration(since * float64(time.Second)),
		interval: time.Duration(interval * float64(time.Second)),
	}, true
}

// wait is how long to sleep before a read that satisfies want, given the one
// just taken at now; zero means that read already does.
func (want readAfter) wait(snap inspect.Snapshot, now time.Time) time.Duration {
	clock, drained := drainClockOf(snap)
	if !drained {
		if want.fresh || want.previous.IsZero() {
			return 0
		}
		return want.previous.At.Add(want.window).Sub(now)
	}
	if want.fresh || want.previous.IsZero() {
		if clock.since <= 2*drainSettle {
			return 0
		}
		return clock.interval - clock.since + drainSettle
	}
	target := want.previous.At.Add(want.window)
	if !clock.at.Before(target.Add(-clock.interval / 10)) {
		return 0
	}
	drains := (target.Sub(clock.at) + clock.interval - 1) / clock.interval
	return time.Duration(drains)*clock.interval - clock.since + drainSettle
}

// stamp is the snapshot of a read, timed at its drain on the agent's clock
// when there is one and on the reader's clock otherwise.
func stamp(families []*dto.MetricFamily, now time.Time) inspect.Snapshot {
	snap := inspect.TakeFamilies(families, now)
	if clock, ok := drainClockOf(snap); ok {
		return inspect.TakeFamilies(families, clock.at)
	}
	return snap
}

func (c *Collector) semaphore() chan struct{} {
	limit := c.Concurrency
	if limit <= 0 {
		limit = defaultConcurrency
	}
	return make(chan struct{}, limit)
}

// scrapeAll reads every agent in its own goroutine. The semaphore bounds
// concurrent requests, not concurrent waits: an agent sleeping until its next
// drain holds no slot, so a large cluster is not read in slow batches.
func (c *Collector) scrapeAll(ctx context.Context, agents []Agent, want func(Agent) readAfter) map[string]scrapeResult {
	out := make(map[string]scrapeResult, len(agents))
	var mu sync.Mutex
	sem := c.semaphore()
	var wg sync.WaitGroup
	for _, a := range agents {
		wg.Add(1)
		go func(a Agent) {
			defer wg.Done()
			res := c.readAgent(ctx, a, want(a), sem)
			mu.Lock()
			out[a.Name] = res
			mu.Unlock()
		}(a)
	}
	wg.Wait()
	return out
}

// readAgent reads one agent until the read satisfies want.
func (c *Collector) readAgent(ctx context.Context, a Agent, want readAfter, sem chan struct{}) scrapeResult {
	if d := want.before(c.now()); d > 0 {
		if err := c.sleep(ctx, d); err != nil {
			return scrapeResult{err: err}
		}
	}
	var res scrapeResult
	for attempt := 0; attempt < maxReadAttempts; attempt++ {
		sem <- struct{}{}
		actx, cancel := context.WithTimeout(ctx, orDefault(c.ScrapeTimeout, defaultScrapeTimeout))
		families, err := c.Cluster.Scrape(actx, a)
		cancel()
		<-sem
		if err != nil {
			return scrapeResult{err: err}
		}
		now := c.now()
		res = scrapeResult{snapshot: stamp(families, now), readAt: now}
		d := want.wait(inspect.TakeFamilies(families, now), now)
		if d <= 0 {
			return res
		}
		if err := c.sleep(ctx, d); err != nil {
			return scrapeResult{err: err}
		}
	}
	return res
}

// Profile reads every agent's continuous profile and merges one workload's.
// A profile is symbolised on request, which can take a while on a busy node,
// hence the separate, longer deadline.
func (c *Collector) Profile(ctx context.Context, namespace, workload string, top int) (*WorkloadHotFrames, []string, error) {
	agents, err := c.agents(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list podtrace agents: %w", err)
	}
	var (
		mu       sync.Mutex
		profiles []Profile
		failed   []string
	)
	sem := c.semaphore()
	var wg sync.WaitGroup
	for _, a := range agents {
		wg.Add(1)
		go func(a Agent) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			actx, cancel := context.WithTimeout(ctx, orDefault(c.ProfileWait, defaultProfileWait))
			defer cancel()
			p, err := c.Cluster.Profile(actx, a)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, fmt.Sprintf("no profile from %s on %s: %s", a.Name, a.Node, oneLine(err.Error())))
				return
			}
			profiles = append(profiles, p)
		}(a)
	}
	wg.Wait()
	return MergeProfiles(profiles, namespace, workload, top), failed, nil
}
