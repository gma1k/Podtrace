package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"

	"github.com/gma1k/podtrace/internal/profiling"
	"github.com/gma1k/podtrace/internal/status"
)

type statusFake struct {
	mu         sync.Mutex
	components func(call int) []status.Component
	compCalls  int
	requests   *prometheus.CounterVec
	reg        *prometheus.Registry
	agentsErr  error
	profile    status.Profile
	profErr    error
	stacks     []byte
	stacksErr  error
	stacksSel  profiling.StackSelection
	scrapes    int
}

func newStatusFake() *statusFake {
	f := &statusFake{reg: prometheus.NewRegistry()}
	f.requests = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "podtrace_workload_l7_requests_total", Help: "r"},
		[]string{"namespace", "workload", "workload_kind", "container", "protocol", "status_class", "outcome"})
	f.reg.MustRegister(f.requests)
	return f
}

func (f *statusFake) Agents(context.Context) ([]status.Agent, error) {
	return []status.Agent{{Name: "podtrace-agent-a", Node: "n1", Ready: true, Port: 9090}}, f.agentsErr
}

func (f *statusFake) Scrape(context.Context, status.Agent) ([]*dto.MetricFamily, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scrapes++
	f.requests.WithLabelValues("shop", "checkout", "Deployment", "app", "http", "2xx", "ok").Add(50)
	return f.reg.Gather()
}

func (f *statusFake) Profile(context.Context, status.Agent) (status.Profile, error) {
	return f.profile, f.profErr
}

func (f *statusFake) ProfileStacks(_ context.Context, _ status.Agent, _ status.StackFormat, sel profiling.StackSelection) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stacksSel = sel
	return f.stacks, f.stacksErr
}

func (f *statusFake) IssueEvents(context.Context, string) ([]corev1.Event, error) { return nil, nil }

func (f *statusFake) ActiveIssues(context.Context, status.Agent) ([]status.LiveIssue, error) {
	return nil, errors.New("404 page not found")
}

func (f *statusFake) Correlations(context.Context) (status.Correlation, error) {
	return status.Correlation{}, errors.New("no running operator pod")
}

func (f *statusFake) Components(context.Context) ([]status.Component, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.compCalls++
	if f.components != nil {
		return f.components(f.compCalls), nil
	}
	return []status.Component{
		{Kind: status.KindOperator, Name: "podtrace-operator", Desired: 1, Ready: 1, Updated: 1},
		{Kind: status.KindFleet, Name: "podtrace-agent", Fleet: "default", Desired: 1, Ready: 1, Updated: 1},
	}, nil
}

func useStatusFake(t *testing.T, f *statusFake) {
	t.Helper()
	orig := statusClusterFactory
	statusClusterFactory = func(statusOptions) (status.Cluster, error) { return f, nil }
	t.Cleanup(func() { statusClusterFactory = orig })
}

func defaultStatusOptions() statusOptions {
	return statusOptions{SystemNamespace: "podtrace-system", Output: "table", Top: 10, Window: time.Second, Interval: time.Second}
}

func TestStatusFlagsAreChecked(t *testing.T) {
	for name, tt := range map[string]struct {
		mod  func(*statusOptions)
		want string
	}{
		"output":           {func(o *statusOptions) { o.Output = "yaml" }, "--output"},
		"top":              {func(o *statusOptions) { o.Top = 0 }, "--top"},
		"window":           {func(o *statusOptions) { o.Window = 100 * time.Millisecond }, "--window"},
		"interval":         {func(o *statusOptions) { o.Watch, o.Interval = true, 0 }, "--interval"},
		"system namespace": {func(o *statusOptions) { o.SystemNamespace = "" }, "--system-namespace"},
		"profile shape":    {func(o *statusOptions) { o.Profile = "a/b/c" }, "namespace/workload"},
		"profile empty ns": {func(o *statusOptions) { o.Profile = "/checkout" }, "namespace/workload"},
		"profile needs ns": {func(o *statusOptions) { o.Profile = "checkout" }, "-n"},
		"slow table":       {func(o *statusOptions) { o.SlowRequests = true }, "--slow-requests"},
		"folded no target": {func(o *statusOptions) { o.Output = "folded" }, "--profile"},
		"pprof and watch":  {func(o *statusOptions) { o.Output, o.Profile, o.Watch = "pprof", "a/b", true }, "--watch"},
		"folded and wait":  {func(o *statusOptions) { o.Output, o.Profile, o.Wait = "folded", "a/b", true }, "--wait"},
	} {
		t.Run(name, func(t *testing.T) {
			o := defaultStatusOptions()
			tt.mod(&o)
			if _, _, err := o.validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want one naming %s", err, tt.want)
			}
		})
	}
}

func TestTheProfileTargetIsResolved(t *testing.T) {
	o := defaultStatusOptions()
	o.Profile = "shop/checkout"
	if ns, wl, err := o.validate(); err != nil || ns != "shop" || wl != "checkout" {
		t.Errorf("namespace/workload: %q %q %v", ns, wl, err)
	}
	o.Profile, o.Namespace = "checkout", "shop"
	if ns, wl, err := o.validate(); err != nil || ns != "shop" || wl != "checkout" {
		t.Errorf("workload with -n: %q %q %v", ns, wl, err)
	}
}

func useFakeStatusClock(t *testing.T) {
	t.Helper()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	origNow, origSleep := statusNow, statusSleep
	statusNow = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	statusSleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
		return nil
	}
	t.Cleanup(func() { statusNow, statusSleep = origNow, origSleep })
}

func TestStatusPrintsTheTableOnce(t *testing.T) {
	f := newStatusFake()
	useStatusFake(t, f)
	useFakeStatusClock(t)
	var out bytes.Buffer
	if err := runStatus(context.Background(), defaultStatusOptions(), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1/1 agents healthy", "shop", "checkout", "50.0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), clearScreen) {
		t.Error("a one-shot report cleared the screen")
	}
}

func TestStatusPrintsJSON(t *testing.T) {
	useStatusFake(t, newStatusFake())
	o := defaultStatusOptions()
	o.Output = "json"
	var out bytes.Buffer
	if err := runStatus(context.Background(), o, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var r status.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || r.Summary.Agents != 1 {
		t.Errorf("json = %s (%v)", out.String(), err)
	}
}

type cancelAfter struct {
	buf    bytes.Buffer
	writes int
	after  int
	cancel context.CancelFunc
}

func (w *cancelAfter) String() string { return w.buf.String() }

func (w *cancelAfter) Write(p []byte) (int, error) {
	n, err := w.buf.Write(p)
	w.writes++
	if w.writes >= w.after {
		w.cancel()
	}
	return n, err
}

func TestWatchRedrawsInAPlaceOnATerminal(t *testing.T) {
	f := newStatusFake()
	useStatusFake(t, f)
	origTTY := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = origTTY })

	ctx, cancel := context.WithCancel(context.Background())
	out := &cancelAfter{after: 4, cancel: cancel}
	o := defaultStatusOptions()
	o.Watch = true
	if err := runStatus(ctx, o, out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), clearScreen) < 2 {
		t.Errorf("the screen was cleared %d times, want one per refresh", strings.Count(out.String(), clearScreen))
	}
	if f.scrapes != 3 {
		t.Errorf("scrapes = %d, want 3: two for the first report and one per refresh", f.scrapes)
	}
}

func TestWatchWithoutATerminalSeparatesReports(t *testing.T) {
	useStatusFake(t, newStatusFake())
	ctx, cancel := context.WithCancel(context.Background())
	out := &cancelAfter{after: 2, cancel: cancel}
	o := defaultStatusOptions()
	o.Watch = true
	if err := runStatus(ctx, o, out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), clearScreen) || !strings.Contains(out.String(), "────") {
		t.Errorf("piped --watch output should be separated, not cleared:\n%q", out.String())
	}
}

func TestWatchAsJSONIsOneObjectPerLine(t *testing.T) {
	useStatusFake(t, newStatusFake())
	ctx, cancel := context.WithCancel(context.Background())
	out := &cancelAfter{after: 2, cancel: cancel}
	o := defaultStatusOptions()
	o.Watch, o.Output = true, "json"
	if err := runStatus(ctx, o, out, io.Discard); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 reports", len(lines))
	}
	for _, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Errorf("line is not a JSON object: %s", l)
		}
	}
}

func TestStatusErrorsAreReturned(t *testing.T) {
	bad := defaultStatusOptions()
	bad.Output = "xml"
	if err := runStatus(context.Background(), bad, &bytes.Buffer{}, io.Discard); err == nil {
		t.Error("invalid flags were accepted")
	}

	orig := statusClusterFactory
	statusClusterFactory = func(statusOptions) (status.Cluster, error) { return nil, errors.New("no kubeconfig") }
	if err := runStatus(context.Background(), defaultStatusOptions(), &bytes.Buffer{}, io.Discard); err == nil {
		t.Error("a missing cluster was not an error")
	}
	statusClusterFactory = orig

	f := newStatusFake()
	f.agentsErr = errors.New("pods is forbidden")
	useStatusFake(t, f)
	if err := runStatus(context.Background(), defaultStatusOptions(), &bytes.Buffer{}, io.Discard); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("err = %v", err)
	}
	var none failingOut
	useStatusFake(t, newStatusFake())
	if err := runStatus(context.Background(), defaultStatusOptions(), none, io.Discard); err == nil {
		t.Error("a failed write was not an error")
	}
	o := defaultStatusOptions()
	o.Watch = true
	if err := runStatus(context.Background(), o, none, io.Discard); err == nil {
		t.Error("a failed write in --watch was not an error")
	}
}

type failingOut struct{}

func (failingOut) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestStatusShowsAProfile(t *testing.T) {
	f := newStatusFake()
	f.profile = status.Profile{Profiles: []profiling.WorkloadProfile{{Namespace: "shop", Workload: "checkout", Samples: 10,
		Frames: []profiling.FrameCount{{Frame: "main.price", Count: 5}}}}}
	useStatusFake(t, f)
	o := defaultStatusOptions()
	o.Profile = "shop/checkout"
	var out bytes.Buffer
	if err := runStatus(context.Background(), o, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "50.0%  main.price") {
		t.Errorf("no profile in:\n%s", out.String())
	}
}

func TestAProfileNobodyHasSaysWhy(t *testing.T) {
	f := newStatusFake()
	f.profErr = errors.New("timeout")
	useStatusFake(t, f)
	o := defaultStatusOptions()
	o.Profile = "shop/missing"
	var out bytes.Buffer
	if err := runStatus(context.Background(), o, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"no profile from podtrace-agent-a", "no agent has a profile for shop/missing"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestAProfileListingFailureIsAnError(t *testing.T) {
	f := newStatusFake()
	useStatusFake(t, f)
	o := defaultStatusOptions()
	o.Profile = "shop/checkout"
	calls := 0
	statusClusterFactory = func(statusOptions) (status.Cluster, error) {
		return &failSecondList{statusFake: f, calls: &calls}, nil
	}
	if err := runStatus(context.Background(), o, &bytes.Buffer{}, io.Discard); err == nil {
		t.Error("a failed agent listing for the profile was not an error")
	}
}

type failSecondList struct {
	*statusFake
	calls *int
}

func (f *failSecondList) Agents(ctx context.Context) ([]status.Agent, error) {
	*f.calls++
	if *f.calls > 1 {
		return nil, errors.New("forbidden")
	}
	return f.statusFake.Agents(ctx)
}

func TestTheStatusCommandIsWired(t *testing.T) {
	cmd := newStatusCmd()
	if cmd.Use != "status" {
		t.Fatalf("Use = %q", cmd.Use)
	}
	for flag, want := range map[string]string{
		"system-namespace": "podtrace-system", "output": "table", "top": "10",
		"window": "10s", "interval": "10s", "watch": "false", "namespace": "",
		"wait": "false", "wait-duration": "5m0s",
	} {
		f := cmd.Flags().Lookup(flag)
		if f == nil || f.DefValue != want {
			t.Errorf("--%s default = %v, want %q", flag, f, want)
		}
	}
	if cmd.Flags().ShorthandLookup("w") == nil || cmd.Flags().ShorthandLookup("o") == nil || cmd.Flags().ShorthandLookup("n") == nil {
		t.Error("-w, -o or -n is missing")
	}

	useStatusFake(t, newStatusFake())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--window", "1s", "-o", "json"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil || !json.Valid(out.Bytes()) {
		t.Errorf("execute: %v\n%s", err, out.String())
	}
}

func TestTheRealClusterFactoryReadsTheKubeconfig(t *testing.T) {
	if _, err := realStatusClusterFactory(statusOptions{Kubeconfig: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("a missing kubeconfig was accepted")
	}
	path := filepath.Join(t.TempDir(), "config")
	kubeconfig := `apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://127.0.0.1:1"}}]
users: [{name: u, user: {token: t}}]
contexts: [{name: one, context: {cluster: c, user: u}}, {name: two, context: {cluster: c, user: u}}]
current-context: one
`
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := realStatusClusterFactory(statusOptions{Kubeconfig: path, Context: "two", SystemNamespace: "podtrace-system"})
	if err != nil {
		t.Fatal(err)
	}
	if kc, ok := c.(*status.KubeCluster); !ok || kc.SystemNamespace != "podtrace-system" {
		t.Errorf("cluster = %#v", c)
	}
	if _, err := realStatusClusterFactory(statusOptions{Kubeconfig: path, Context: "nope"}); err == nil {
		t.Error("an unknown --context was accepted")
	}
}

func TestAPipeIsNotATerminal(t *testing.T) {
	if stdoutIsTerminal() {
		t.Skip("stdout is a terminal in this run")
	}
}

func TestAKubeconfigWhoseClientCannotBeBuiltIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	kubeconfig := `apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://127.0.0.1:1", certificate-authority-data: bm90IGEgY2VydGlmaWNhdGU=}}]
users: [{name: u, user: {token: t}}]
contexts: [{name: one, context: {cluster: c, user: u}}]
current-context: one
`
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := realStatusClusterFactory(statusOptions{Kubeconfig: path}); err == nil {
		t.Error("a kubeconfig with an unreadable CA produced a client")
	}
}

func TestAFailedRedrawIsAnError(t *testing.T) {
	o := defaultStatusOptions()
	o.Watch = true
	if err := render(failingOut{}, status.Report{}, o, true); err == nil {
		t.Error("a failed screen clear was not an error")
	}
}

func rollingUntil(healthyFrom int) func(int) []status.Component {
	return func(call int) []status.Component {
		ready := int32(0)
		if call >= healthyFrom {
			ready = 1
		}
		return []status.Component{
			{Kind: status.KindOperator, Name: "podtrace-operator", Desired: 1, Ready: 1, Updated: 1},
			{Kind: status.KindFleet, Name: "podtrace-agent", Desired: 1, Ready: ready, Updated: 1},
		}
	}
}

func fastPolling(t *testing.T) {
	t.Helper()
	orig := statusPollInterval
	statusPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { statusPollInterval = orig })
}

func waitOptions() statusOptions {
	o := defaultStatusOptions()
	o.Wait, o.WaitDuration = true, 5*time.Second
	return o
}

func TestWaitReturnsAtOnceWhenHealthy(t *testing.T) {
	useStatusFake(t, newStatusFake())
	var out, progress bytes.Buffer
	if err := runStatus(context.Background(), waitOptions(), &out, &progress); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(progress.String(), "✓ podtrace is healthy") || strings.Contains(progress.String(), "waiting") {
		t.Errorf("progress = %q", progress.String())
	}
	if !strings.Contains(out.String(), "podtrace is healthy") {
		t.Errorf("the report was not printed after the wait:\n%s", out.String())
	}
}

func TestWaitWaitsUntilTheFleetIsRolledOut(t *testing.T) {
	fastPolling(t)
	f := newStatusFake()
	f.components = rollingUntil(4)
	useStatusFake(t, f)
	var progress bytes.Buffer
	if err := runStatus(context.Background(), waitOptions(), io.Discard, &progress); err != nil {
		t.Fatalf("err = %v\nprogress:\n%s", err, progress.String())
	}
	if n := strings.Count(progress.String(), "… waiting: fleet podtrace-agent: 0 of 1 ready"); n != 1 {
		t.Errorf("the same problem was printed %d times; a line per change keeps the log readable:\n%s", n, progress.String())
	}
	if !strings.HasSuffix(strings.TrimSpace(progress.String()), "✓ podtrace is healthy") {
		t.Errorf("progress = %q", progress.String())
	}
}

func TestWaitGivesUpAfterTheDurationAndSaysWhatIsWrong(t *testing.T) {
	fastPolling(t)
	f := newStatusFake()
	f.components = rollingUntil(1 << 30)
	useStatusFake(t, f)
	o := waitOptions()
	o.WaitDuration = time.Second
	var out, progress bytes.Buffer
	err := runStatus(context.Background(), o, &out, &progress)
	if err == nil || !strings.Contains(err.Error(), "fleet podtrace-agent: 0 of 1 ready") {
		t.Errorf("err = %v; a timed-out wait must fail with what is still wrong", err)
	}
	if !strings.Contains(progress.String(), "✗ podtrace was not healthy within 1s") {
		t.Errorf("progress = %q", progress.String())
	}
	if !strings.Contains(out.String(), "PROBLEMS") {
		t.Errorf("the report after a timeout does not show the problems:\n%s", out.String())
	}
}

func TestAnInterruptedWaitIsNotReportedAsHealthy(t *testing.T) {
	fastPolling(t)
	f := newStatusFake()
	f.components = rollingUntil(1 << 30)
	useStatusFake(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	var progress bytes.Buffer
	if err := runStatus(ctx, waitOptions(), io.Discard, &progress); !errors.Is(err, errInterrupted) {
		t.Errorf("err = %v; a wait a signal cut short must not exit as if podtrace were healthy", err)
	}
	if strings.Contains(progress.String(), "context canceled") {
		t.Errorf("the interrupt was reported as a cluster problem: %q", progress.String())
	}
}

func TestAnInterruptedSingleCollectionIsNotReportedAsHealthy(t *testing.T) {
	useStatusFake(t, newStatusFake())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runStatus(ctx, defaultStatusOptions(), io.Discard, io.Discard); !errors.Is(err, errInterrupted) {
		t.Errorf("err = %v; an interrupted check has no answer and must not exit 0", err)
	}
}

func TestStoppingAWatchIsNotAnError(t *testing.T) {
	useStatusFake(t, newStatusFake())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := defaultStatusOptions()
	opts.Watch = true
	if err := runStatus(ctx, opts, io.Discard, io.Discard); err != nil {
		t.Errorf("err = %v; Ctrl-C is how a watch ends", err)
	}
}

func TestWaitKeepsTryingWhileTheAgentsCannotBeListed(t *testing.T) {
	fastPolling(t)
	f := newStatusFake()
	calls := 0
	useStatusFake(t, f)
	statusClusterFactory = func(statusOptions) (status.Cluster, error) {
		return &listFailsFirst{statusFake: f, calls: &calls}, nil
	}
	var progress bytes.Buffer
	if err := runStatus(context.Background(), waitOptions(), io.Discard, &progress); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(progress.String(), "… waiting: list podtrace agents: not installed yet") {
		t.Errorf("progress = %q; right after an install the agents may not exist yet", progress.String())
	}
}

type listFailsFirst struct {
	*statusFake
	calls *int
}

func (f *listFailsFirst) Agents(ctx context.Context) ([]status.Agent, error) {
	*f.calls++
	if *f.calls <= 2 {
		return nil, errors.New("not installed yet")
	}
	return f.statusFake.Agents(ctx)
}

func TestAnUnhealthyReportExitsNonZero(t *testing.T) {
	f := newStatusFake()
	f.components = rollingUntil(1 << 30)
	useStatusFake(t, f)
	var out bytes.Buffer
	err := runStatus(context.Background(), defaultStatusOptions(), &out, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "podtrace is not healthy") {
		t.Errorf("err = %v; a script needs a non-zero exit when podtrace is broken", err)
	}
	if !strings.Contains(out.String(), "podtrace is NOT healthy") {
		t.Errorf("the report was not printed before failing:\n%s", out.String())
	}
}

func TestWatchDoesNotExitOnAnUnhealthyReport(t *testing.T) {
	f := newStatusFake()
	f.components = rollingUntil(1 << 30)
	useStatusFake(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	out := &cancelAfter{after: 4, cancel: cancel}
	o := defaultStatusOptions()
	o.Watch = true
	if err := runStatus(ctx, o, out, io.Discard); err != nil {
		t.Errorf("err = %v; --watch keeps showing an unhealthy install rather than quitting", err)
	}
}

func TestWaitDurationIsChecked(t *testing.T) {
	o := waitOptions()
	o.WaitDuration = 0
	if _, _, err := o.validate(); err == nil || !strings.Contains(err.Error(), "--wait-duration") {
		t.Errorf("err = %v", err)
	}
}

func TestWaitProgressCountsAgentsPastAFew(t *testing.T) {
	var problems []string
	for i := 0; i < 5; i++ {
		problems = append(problems, fmt.Sprintf("agent on node-%d is not ready", i))
	}
	got := progressLine(append([]string{"fleet podtrace-agent: 0 of 5 ready, 5 updated"}, problems...))
	if !strings.HasPrefix(got, "fleet podtrace-agent") || !strings.Contains(got, "node-2") ||
		strings.Contains(got, "node-3") || !strings.HasSuffix(got, "and 2 more agents") {
		t.Errorf("progress = %q; a rollout on a large cluster must stay one readable line", got)
	}
	if few := progressLine(problems[:2]); strings.Contains(few, "more agents") {
		t.Errorf("progress = %q; two agents are listed, not counted", few)
	}
}
