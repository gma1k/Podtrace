package operator

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

type fakeAgent struct {
	server *httptest.Server
	status int
	body   string
}

func newFakeAgent(t *testing.T, body string) *fakeAgent {
	a := &fakeAgent{status: http.StatusOK, body: body}
	a.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/issues" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(a.status)
		_, _ = w.Write([]byte(a.body))
	}))
	t.Cleanup(a.server.Close)
	return a
}

func (a *fakeAgent) pod(name string) *corev1.Pod {
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(a.server.URL, "http://"))
	p, _ := strconv.Atoi(port)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "podtrace-system", Labels: map[string]string{LabelComponent: ComponentAgent}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "agent", Ports: []corev1.ContainerPort{{Name: "metrics", ContainerPort: int32(p)}},
		}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: host, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

func deploymentPod(namespace, name, deployment string) *corev1.Pod {
	controller := true
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: namespace,
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: deployment + "-7d8c9c", Controller: &controller}},
	}}
}

func serviceSlice(namespace, service string, pods ...string) *discoveryv1.EndpointSlice {
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Name: service + "-abc", Namespace: namespace, Labels: map[string]string{discoveryv1.LabelServiceName: service}},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	for _, p := range pods {
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{
			Addresses: []string{"10.0.0.1"},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: p, Namespace: namespace},
		})
	}
	return slice
}

func newCorrelator(t *testing.T, objects ...client.Object) (*IssueCorrelator, *prometheus.Registry) {
	t.Helper()
	scheme, err := NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	c := &IssueCorrelator{
		Client:          fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build(),
		SystemNamespace: "podtrace-system",
		Logger:          logr.Discard(),
	}
	reg := prometheus.NewRegistry()
	if err := c.Register(reg); err != nil {
		t.Fatal(err)
	}
	return c, reg
}

const frontNode = `{"issues":[{"id":"l7.latency_degraded","namespace":"shop","workload":"front"}],
"edges":[{"namespace":"shop","workload":"front","targetNamespace":"shop","targetService":"backend","requests":12}]}`

const backendNode = `{"issues":[{"id":"l7.latency_degraded","namespace":"shop","workload":"backend"},
{"id":"db.pool_saturated","namespace":"shop","workload":"backend"}],"edges":[]}`

func causesOf(c Correlation, id detector.ID, workload string) []detector.Cause {
	for _, is := range c.Issues {
		if is.ID == id && is.Workload == workload {
			return is.Causes
		}
	}
	return nil
}

func TestACallersIssueIsTracedToTheRootOnTheWorkloadItCalls(t *testing.T) {
	a, b := newFakeAgent(t, frontNode), newFakeAgent(t, backendNode)
	c, reg := newCorrelator(t, a.pod("agent-a"), b.pod("agent-b"),
		deploymentPod("shop", "backend-7d8c9c-x1", "backend"), serviceSlice("shop", "backend", "backend-7d8c9c-x1"))

	got := c.Correlate(context.Background())
	if got.AgentsRead != 2 || got.AgentsFailed != 0 {
		t.Fatalf("read %d agents, %d failed", got.AgentsRead, got.AgentsFailed)
	}
	pool := detector.IssueRef{ID: detector.IDDBPoolSaturated, Namespace: "shop", Workload: "backend"}
	backend := detector.IssueRef{ID: detector.IDL7LatencyDegraded, Namespace: "shop", Workload: "backend"}
	if want := []detector.Cause{{IssueRef: pool, Via: []detector.IssueRef{backend}}}; !reflect.DeepEqual(causesOf(got, detector.IDL7LatencyDegraded, "front"), want) {
		t.Errorf("front causes %v, want %v", causesOf(got, detector.IDL7LatencyDegraded, "front"), want)
	}
	want := `
# HELP podtrace_issue_cause 1 while an active issue's likely root cause is another active issue, cluster-wide. A likely cause, never a verdict: it annotates and changes nothing about when an issue fires.
# TYPE podtrace_issue_cause gauge
podtrace_issue_cause{cause_id="db.pool_saturated",cause_namespace="shop",cause_workload="backend",id="l7.latency_degraded",namespace="shop",workload="backend"} 1
podtrace_issue_cause{cause_id="db.pool_saturated",cause_namespace="shop",cause_workload="backend",id="l7.latency_degraded",namespace="shop",workload="front"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "podtrace_issue_cause"); err != nil {
		t.Error(err)
	}
}

func TestALinkThatNoLongerHoldsIsRemovedFromTheMetric(t *testing.T) {
	a, b := newFakeAgent(t, frontNode), newFakeAgent(t, backendNode)
	c, reg := newCorrelator(t, a.pod("agent-a"), b.pod("agent-b"),
		deploymentPod("shop", "backend-7d8c9c-x1", "backend"), serviceSlice("shop", "backend", "backend-7d8c9c-x1"))
	c.Correlate(context.Background())
	b.body = `{"issues":[{"id":"l7.latency_degraded","namespace":"shop","workload":"backend"}],"edges":[]}`
	c.Correlate(context.Background())

	want := `
# HELP podtrace_issue_cause 1 while an active issue's likely root cause is another active issue, cluster-wide. A likely cause, never a verdict: it annotates and changes nothing about when an issue fires.
# TYPE podtrace_issue_cause gauge
podtrace_issue_cause{cause_id="l7.latency_degraded",cause_namespace="shop",cause_workload="backend",id="l7.latency_degraded",namespace="shop",workload="front"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "podtrace_issue_cause"); err != nil {
		t.Error(err)
	}
}

func TestACallToAServiceThatResolvesToNoWorkloadLinksNothing(t *testing.T) {
	a, b := newFakeAgent(t, frontNode), newFakeAgent(t, backendNode)
	c, _ := newCorrelator(t, a.pod("agent-a"), b.pod("agent-b"))
	got := c.Correlate(context.Background())
	if causes := causesOf(got, detector.IDL7LatencyDegraded, "front"); len(causes) != 0 {
		t.Errorf("front blamed on %v though no workload is known behind the Service", causes)
	}
}

func TestAnEndpointThatIsNotAPodIsIgnored(t *testing.T) {
	a, b := newFakeAgent(t, frontNode), newFakeAgent(t, backendNode)
	slice := serviceSlice("shop", "backend")
	slice.Endpoints = []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.9"}}, {Addresses: []string{"10.0.0.8"}, TargetRef: &corev1.ObjectReference{Kind: "Node", Name: "n1"}}}
	c, _ := newCorrelator(t, a.pod("agent-a"), b.pod("agent-b"), slice)
	if causes := causesOf(c.Correlate(context.Background()), detector.IDL7LatencyDegraded, "front"); len(causes) != 0 {
		t.Errorf("front blamed on %v", causes)
	}
}

func TestAnAgentWithInspectionsOffIsNotAFailure(t *testing.T) {
	a := newFakeAgent(t, "")
	a.status = http.StatusNotFound
	c, reg := newCorrelator(t, a.pod("agent-a"))
	got := c.Correlate(context.Background())
	if got.AgentsRead != 0 || got.AgentsFailed != 0 {
		t.Errorf("read %d, failed %d; want neither", got.AgentsRead, got.AgentsFailed)
	}
	if n := testutil.ToFloat64(c.readFailed); n != 0 {
		t.Errorf("failed reads counted %v", n)
	}
	_ = reg
}

func TestAnUnreadableAgentIsCountedAndTheRestStillCorrelate(t *testing.T) {
	broken := newFakeAgent(t, "")
	broken.status = http.StatusInternalServerError
	garbled := newFakeAgent(t, "{not json")
	healthy := newFakeAgent(t, backendNode)
	c, _ := newCorrelator(t, broken.pod("agent-a"), garbled.pod("agent-b"), healthy.pod("agent-c"))
	got := c.Correlate(context.Background())
	if got.AgentsFailed != 2 || got.AgentsRead != 1 {
		t.Errorf("read %d, failed %d; want 1 and 2", got.AgentsRead, got.AgentsFailed)
	}
	if n := testutil.ToFloat64(c.readFailed); n != 2 {
		t.Errorf("failed reads counted %v, want 2", n)
	}
	if causes := causesOf(got, detector.IDL7LatencyDegraded, "backend"); len(causes) != 1 {
		t.Errorf("the readable agent's issues were not correlated: %v", causes)
	}
}

func TestOnlyReadyRunningAgentsWithAnAddressAreRead(t *testing.T) {
	a := newFakeAgent(t, backendNode)
	pending := a.pod("agent-pending")
	pending.Status.Phase = corev1.PodPending
	noIP := a.pod("agent-no-ip")
	noIP.Status.PodIP = ""
	other := a.pod("not-an-agent")
	other.Labels = nil
	starting := a.pod("agent-starting")
	starting.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	unknown := a.pod("agent-no-conditions")
	unknown.Status.Conditions = nil
	c, _ := newCorrelator(t, pending, noIP, other, starting, unknown)
	if got := c.Correlate(context.Background()); got.AgentsRead != 0 || got.AgentsFailed != 0 {
		t.Errorf("read %d, failed %d; want no agents at all", got.AgentsRead, got.AgentsFailed)
	}
}

func TestTheSameIssueOnSeveralNodesIsListedOnce(t *testing.T) {
	a, b := newFakeAgent(t, backendNode), newFakeAgent(t, backendNode)
	c, _ := newCorrelator(t, a.pod("agent-a"), b.pod("agent-b"))
	got := c.Correlate(context.Background())
	if len(got.Issues) != 2 {
		t.Errorf("issues %+v, want each of the two listed once", got.Issues)
	}
}

func TestTheHandlerServesTheLatestPassOrSaysThereIsNone(t *testing.T) {
	c, _ := newCorrelator(t, newFakeAgent(t, backendNode).pod("agent-a"))
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, CorrelationsPath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d before the first pass, want 503", rec.Code)
	}
	c.Correlate(context.Background())
	rec = httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, CorrelationsPath, nil))
	var body Correlation
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.AgentsRead != 1 || len(causesOf(body, detector.IDL7LatencyDegraded, "backend")) != 1 {
		t.Errorf("served %+v", body)
	}
}

func TestTheCorrelationRunsUntilItsContextEnds(t *testing.T) {
	c, _ := newCorrelator(t, newFakeAgent(t, backendNode).pod("agent-a"))
	c.Interval = 1
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- c.Start(ctx) }()
	for {
		if _, ok := c.Latest(); ok {
			break
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Start returned %v", err)
	}
	if !c.NeedLeaderElection() {
		t.Error("the correlation must run on the leader only, or every replica publishes the links")
	}
}

func TestTheAgentPortIsReadByName(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Ports: []corev1.ContainerPort{{Name: "health", ContainerPort: 9091}, {Name: "metrics", ContainerPort: 9190}}}}}}
	if got := agentPort(pod); got != "9190" {
		t.Errorf("port %s, want 9190", got)
	}
	if got := agentPort(&corev1.Pod{}); got != agentMetricsPort {
		t.Errorf("port %s, want the default %s", got, agentMetricsPort)
	}
}

func TestIssuesAreReadFromTheInspectPortWhenTheAgentHasOne(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Ports: []corev1.ContainerPort{
		{Name: "metrics", ContainerPort: 9090},
		{Name: "health", ContainerPort: 9091},
		{Name: "inspect", ContainerPort: 9192},
	}}}}}
	if got := agentPort(pod); got != "9192" {
		t.Errorf("port %s, want the inspect port 9192; the metrics port no longer serves /issues", got)
	}
}

func TestTheCachedEndpointSliceKeepsOnlyTheServiceAndThePods(t *testing.T) {
	slice := serviceSlice("shop", "backend", "backend-1")
	slice.Labels["extra"] = "x"
	slice.Annotations = map[string]string{"a": "b"}
	node := "n1"
	slice.Endpoints[0].NodeName = &node
	got, err := trimEndpointSlice(slice)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := got.(*discoveryv1.EndpointSlice)
	if !reflect.DeepEqual(trimmed.Labels, map[string]string{discoveryv1.LabelServiceName: "backend"}) || trimmed.Annotations != nil {
		t.Errorf("labels %v annotations %v", trimmed.Labels, trimmed.Annotations)
	}
	e := trimmed.Endpoints[0]
	if e.Addresses != nil || e.NodeName != nil || e.TargetRef == nil || e.TargetRef.Name != "backend-1" || e.TargetRef.Kind != "Pod" {
		t.Errorf("endpoint %+v", e)
	}
	unlabelled := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"x": "y"}}}
	if got, _ := trimEndpointSlice(unlabelled); got.(*discoveryv1.EndpointSlice).Labels != nil {
		t.Error("a slice of no Service kept its labels")
	}
	other := &corev1.Pod{}
	if got, _ := trimEndpointSlice(other); got != other {
		t.Error("a non-slice object was changed")
	}
}
