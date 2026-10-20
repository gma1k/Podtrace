package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/inspect"
	"github.com/gma1k/podtrace/internal/podworkload"
)

// Correlating issues across the cluster.
//
// Each agent sees one node, so it can only link issues on the same workload.
// "The checkout is slow because the payments service it calls is slow"
// needs every node's issues and every node's calls, and a map from the
// Service a call went to onto the workload behind it. The operator has the
// one cluster-wide Pod cache, so the map is built here once, not on every
// node.

const (
	defaultCorrelationInterval = 30 * time.Second
	agentReadTimeout           = 5 * time.Second
	agentReadConcurrency       = 8
	maxIssuesBody              = 4 << 20

	CorrelationsPath = "/correlations"

	EventReasonLikelyCause = "PodtraceLikelyCause"
)

// CorrelatedIssue is one active issue, cluster-wide, and what likely caused
// it.
type CorrelatedIssue struct {
	detector.IssueRef
	Causes []detector.Cause `json:"causes,omitempty"`
}

// Correlation is the latest cluster-wide pass.
type Correlation struct {
	GeneratedAt  time.Time         `json:"generatedAt"`
	AgentsRead   int               `json:"agentsRead"`
	AgentsFailed int               `json:"agentsFailed"`
	Issues       []CorrelatedIssue `json:"issues"`
}

// agentIssues is the part of an agent's /issues the correlation reads.
type agentIssues struct {
	Issues []struct {
		ID        detector.ID `json:"id"`
		Namespace string      `json:"namespace"`
		Workload  string      `json:"workload"`
		Pod       string      `json:"pod"`
	} `json:"issues"`
	Edges []inspect.Edge `json:"edges"`
}

// IssueCorrelator links active issues across the cluster on an interval.
// Only the leader runs it, so exactly one operator replica publishes the
// links.
type IssueCorrelator struct {
	Client          client.Reader
	Writer          client.Writer
	SystemNamespace string
	Interval        time.Duration
	HTTP            *http.Client
	Logger          logr.Logger

	mu     sync.Mutex
	latest *Correlation

	causes      *prometheus.GaugeVec
	readFailed  prometheus.Counter
	published   map[string][]string
	announced   map[string]bool
	initialized bool
}

// Register adds the correlator's metrics to reg.
func (c *IssueCorrelator) Register(reg prometheus.Registerer) error {
	c.init()
	for _, collector := range []prometheus.Collector{c.causes, c.readFailed} {
		if err := reg.Register(collector); err != nil {
			return err
		}
	}
	return nil
}

func (c *IssueCorrelator) init() {
	if c.initialized {
		return
	}
	c.initialized = true
	c.causes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "podtrace_issue_cause",
		Help: "1 while an active issue's likely root cause is another active issue, cluster-wide. " +
			"A likely cause, never a verdict: it annotates and changes nothing about when an issue fires.",
	}, []string{"id", "namespace", "workload", "cause_id", "cause_namespace", "cause_workload"})
	c.readFailed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "podtrace_correlation_agent_reads_failed_total",
		Help: "Agent /issues reads the correlation could not complete. While it rises, " +
			"links that involve those agents' workloads are missing.",
	})
	c.published = map[string][]string{}
	c.announced = map[string]bool{}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: agentReadTimeout}
	}
	if c.Interval <= 0 {
		c.Interval = defaultCorrelationInterval
	}
}

// NeedLeaderElection keeps the correlation on the leader.
func (c *IssueCorrelator) NeedLeaderElection() bool { return true }

// Start runs the correlation until ctx ends.
func (c *IssueCorrelator) Start(ctx context.Context) error {
	c.init()
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		c.Correlate(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Correlate runs one pass and publishes it.
func (c *IssueCorrelator) Correlate(ctx context.Context) Correlation {
	c.init()
	agents, err := c.agents(ctx)
	if err != nil {
		c.Logger.Error(err, "cannot list the agents to correlate their issues")
	}
	reads := c.readAll(ctx, agents)

	result := Correlation{GeneratedAt: time.Now(), Issues: []CorrelatedIssue{}}
	var refs []detector.IssueRef
	var edges []inspect.Edge
	pods := map[detector.IssueRef]string{}
	for _, r := range reads {
		if r.err != nil {
			result.AgentsFailed++
			c.readFailed.Inc()
			c.Logger.V(1).Info("cannot read an agent's issues", "agent", r.agent, "err", r.err.Error())
			continue
		}
		if r.body == nil {
			continue
		}
		result.AgentsRead++
		for _, is := range r.body.Issues {
			ref := detector.IssueRef{ID: is.ID, Namespace: is.Namespace, Workload: is.Workload}
			refs = append(refs, ref)
			if is.Pod != "" && pods[ref] == "" {
				pods[ref] = is.Pod
			}
		}
		edges = append(edges, r.body.Edges...)
	}

	deps := inspect.Dependencies(edges, c.workloadsBehind(ctx))
	causes := detector.RootCauses(refs, deps)

	seen := map[detector.IssueRef]bool{}
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		result.Issues = append(result.Issues, CorrelatedIssue{IssueRef: ref, Causes: causes[ref]})
	}
	sort.Slice(result.Issues, func(i, j int) bool {
		return result.Issues[i].String() < result.Issues[j].String()
	})

	c.publish(result)
	c.announce(ctx, result, pods)
	return result
}

// announce writes one Event, on a pod of the affected workload, for each
// issue whose likely cause is on another workload, when that link first
// appears.
func (c *IssueCorrelator) announce(ctx context.Context, result Correlation, pods map[detector.IssueRef]string) {
	current := map[string]bool{}
	for _, is := range result.Issues {
		var elsewhere []string
		for _, cause := range is.Causes {
			if !cause.SameWorkload(is.IssueRef) {
				elsewhere = append(elsewhere, cause.String())
			}
		}
		if len(elsewhere) == 0 {
			continue
		}
		causes := strings.Join(elsewhere, "; ")
		key := is.String() + "|" + causes
		current[key] = true
		if c.announced[key] || c.Writer == nil {
			continue
		}
		pod := c.namedPod(ctx, is.Namespace, pods[is.IssueRef])
		if pod == nil {
			pod = c.podOf(ctx, is.Namespace, is.Workload)
		}
		if pod == nil {
			continue
		}
		if err := c.Writer.Create(ctx, likelyCauseEvent(is.IssueRef, pod, causes)); err != nil {
			c.Logger.Error(err, "cannot write the likely-cause Event",
				"issue", is.ID, "namespace", is.Namespace, "workload", is.Workload)
			continue
		}
		c.announced[key] = true
	}
	for key := range c.announced {
		if !current[key] {
			delete(c.announced, key)
		}
	}
}

// namedPod reads the pod an agent named, or nil when it named none or the
// pod is gone or leaving.
func (c *IssueCorrelator) namedPod(ctx context.Context, namespace, name string) *corev1.Pod {
	if name == "" {
		return nil
	}
	var pod corev1.Pod
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil || pod.DeletionTimestamp != nil {
		return nil
	}
	return &pod
}

// podOf picks a pod of the workload, by name order so it is stable.
func (c *IssueCorrelator) podOf(ctx context.Context, namespace, workload string) *corev1.Pod {
	var pods corev1.PodList
	if err := c.Client.List(ctx, &pods, client.InNamespace(namespace)); err != nil {
		return nil
	}
	sort.Slice(pods.Items, func(i, j int) bool { return pods.Items[i].Name < pods.Items[j].Name })
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp != nil {
			continue
		}
		if _, name := podworkload.Of(p); name == workload {
			return p
		}
	}
	return nil
}

// likelyCauseEvent names the pod by UID as well as name: kubectl describe
// lists only the Events whose involved object carries the pod's UID.
func likelyCauseEvent(issue detector.IssueRef, pod *corev1.Pod, causes string) *corev1.Event {
	now := metav1.NewTime(time.Now())
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "podtrace-cause-",
			Namespace:    issue.Namespace,
			Annotations: map[string]string{
				alerting.AnnotationIssueID:      string(issue.ID),
				alerting.AnnotationWorkload:     issue.Workload,
				alerting.AnnotationLikelyCauses: causes,
			},
		},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", APIVersion: "v1", Namespace: issue.Namespace, Name: pod.Name, UID: pod.UID},
		Reason:         EventReasonLikelyCause,
		Message:        string(issue.ID) + " on " + issue.Namespace + "/" + issue.Workload + ": likely cause " + causes,
		Type:           corev1.EventTypeWarning,
		Source:         corev1.EventSource{Component: "podtrace-operator"},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
	}
}

// Latest returns the latest pass, or false before the first.
func (c *IssueCorrelator) Latest() (Correlation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.latest == nil {
		return Correlation{}, false
	}
	return *c.latest, true
}

// Handler serves the latest pass as JSON. A replica that is not the leader
// has none and says so.
func (c *IssueCorrelator) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		latest, ok := c.Latest()
		if !ok {
			http.Error(w, "no correlation yet: this replica is not the leader, or its first pass has not run",
				http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(latest)
	})
}

// publish replaces the cause series with the pass's links, removing only the
// series that no longer hold so a scrape never sees a link blink out.
func (c *IssueCorrelator) publish(result Correlation) {
	next := map[string][]string{}
	for _, is := range result.Issues {
		for _, cause := range is.Causes {
			labels := []string{
				string(is.ID), is.Namespace, is.Workload,
				string(cause.ID), cause.Namespace, cause.Workload,
			}
			next[fmt.Sprint(labels)] = labels
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for key, labels := range c.published {
		if _, still := next[key]; !still {
			c.causes.DeleteLabelValues(labels...)
		}
	}
	for _, labels := range next {
		c.causes.WithLabelValues(labels...).Set(1)
	}
	c.published = next
	c.latest = &result
}

type agentRead struct {
	agent string
	body  *agentIssues
	err   error
}

// agents lists the agent pods that can be read: ready ones. An agent that is
// starting is not a failed read, and one that is not ready because its eBPF
// backend is down has nothing current to report.
func (c *IssueCorrelator) agents(ctx context.Context) ([]corev1.Pod, error) {
	namespaces, err := fleetSystemNamespaces(ctx, c.Client, c.SystemNamespace)
	if err != nil {
		return nil, err
	}
	var out []corev1.Pod
	for _, ns := range namespaces {
		var pods corev1.PodList
		if err := c.Client.List(ctx, &pods,
			client.InNamespace(ns),
			client.MatchingLabels{LabelComponent: ComponentAgent},
		); err != nil {
			return nil, err
		}
		for _, p := range pods.Items {
			if p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" && p.DeletionTimestamp == nil && podReady(&p) {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func (c *IssueCorrelator) readAll(ctx context.Context, agents []corev1.Pod) []agentRead {
	out := make([]agentRead, len(agents))
	sem := make(chan struct{}, agentReadConcurrency)
	var wg sync.WaitGroup
	for i := range agents {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			body, err := c.read(ctx, &agents[i])
			out[i] = agentRead{agent: agents[i].Name, body: body, err: err}
		}(i)
	}
	wg.Wait()
	return out
}

// read fetches one agent's /issues. An agent whose inspections are off
// answers 404, which is not a failure: it has nothing to correlate.
func (c *IssueCorrelator) read(ctx context.Context, pod *corev1.Pod) (*agentIssues, error) {
	ctx, cancel := context.WithTimeout(ctx, agentReadTimeout)
	defer cancel()
	url := "http://" + net.JoinHostPort(pod.Status.PodIP, agentPort(pod)) + "/issues"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("agent answered %s", resp.Status)
	}
	var body agentIssues
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIssuesBody)).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode the agent's issues: %w", err)
	}
	return &body, nil
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// agentPort is the port the agent serves /issues on, by name, so a fleet
// that moved it is still read. Agents from before the inspect port served
// /issues on the metrics port, so that is the fallback while a fleet rolls.
func agentPort(pod *corev1.Pod) string {
	metrics := agentMetricsPort
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			switch port.Name {
			case agentInspectPortName:
				return fmt.Sprint(port.ContainerPort)
			case "metrics":
				metrics = fmt.Sprint(port.ContainerPort)
			}
		}
	}
	return metrics
}

// workloadsBehind maps a Service to the workloads of the pods its
// EndpointSlices point at, named exactly as the agents name them. Each
// Service is resolved once per pass.
func (c *IssueCorrelator) workloadsBehind(ctx context.Context) func(namespace, service string) []string {
	memo := map[[2]string][]string{}
	return func(namespace, service string) []string {
		key := [2]string{namespace, service}
		if w, ok := memo[key]; ok {
			return w
		}
		var slices discoveryv1.EndpointSliceList
		if err := c.Client.List(ctx, &slices,
			client.InNamespace(namespace),
			client.MatchingLabels{discoveryv1.LabelServiceName: service},
		); err != nil {
			c.Logger.V(1).Info("cannot resolve a Service to its workloads",
				"namespace", namespace, "service", service, "err", err.Error())
			memo[key] = nil
			return nil
		}
		names := map[string]bool{}
		for _, slice := range slices.Items {
			for _, endpoint := range slice.Endpoints {
				ref := endpoint.TargetRef
				if ref == nil || ref.Kind != "Pod" {
					continue
				}
				var pod corev1.Pod
				if err := c.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, &pod); err != nil {
					continue
				}
				_, name := podworkload.Of(&pod)
				names[name] = true
			}
		}
		out := make([]string, 0, len(names))
		for name := range names {
			out = append(out, name)
		}
		sort.Strings(out)
		memo[key] = out
		return out
	}
}

// trimEndpointSlice keeps only what workloadsBehind reads, so caching every
// EndpointSlice in the cluster costs little: the Service name and each
// endpoint's pod reference.
func trimEndpointSlice(obj interface{}) (interface{}, error) {
	slice, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return obj, nil
	}
	slice.ManagedFields = nil
	slice.Annotations = nil
	slice.OwnerReferences = nil
	slice.Ports = nil
	if name, present := slice.Labels[discoveryv1.LabelServiceName]; present {
		slice.Labels = map[string]string{discoveryv1.LabelServiceName: name}
	} else {
		slice.Labels = nil
	}
	for i := range slice.Endpoints {
		endpoint := &slice.Endpoints[i]
		endpoint.Addresses = nil
		endpoint.Hostname = nil
		endpoint.NodeName = nil
		endpoint.Zone = nil
		endpoint.Hints = nil
		endpoint.DeprecatedTopology = nil
		if endpoint.TargetRef != nil {
			endpoint.TargetRef = &corev1.ObjectReference{Kind: endpoint.TargetRef.Kind, Name: endpoint.TargetRef.Name}
		}
	}
	return slice, nil
}
