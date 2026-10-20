// Package status builds the view behind `podtrace status`: what every agent
// sees, read from the agents themselves through the API server, so a cluster
// with no metrics backend still has one place to look.
package status

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/profiling"
)

const (
	agentSelector      = "podtrace.io/component=agent"
	operatorSelector   = "app.kubernetes.io/name=podtrace,app.kubernetes.io/component=operator"
	tracerConfigLabel  = "podtrace.io/tracer-config"
	metricsPortName    = "metrics"
	defaultMetricsPort = 9090
	inspectPortName    = "inspect"

	operatorMetricsPort = 8080

	protobufAccept = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.9,text/plain;version=0.0.4;q=0.1"
)

// Agent is one agent pod.
type Agent struct {
	Name     string
	Node     string
	Fleet    string
	Ready    bool
	Phase    corev1.PodPhase
	Restarts int32
	Port     int32

	InspectPort int32
}

// Component is the operator Deployment or one fleet's agent DaemonSet, and
// how far it is rolled out.
type Component struct {
	Kind    string
	Name    string
	Fleet   string
	Desired int32
	Ready   int32
	Updated int32
}

// Component kinds.
const (
	KindOperator = "operator"
	KindFleet    = "fleet"
)

// Profile is one agent's /profile response.
type Profile struct {
	Profiles []profiling.WorkloadProfile `json:"profiles"`
	Dropped  uint64                      `json:"droppedSamples"`
}

// Cluster is what the view reads. The real implementation goes through the
// API server; tests substitute their own.
type Cluster interface {
	Agents(ctx context.Context) ([]Agent, error)
	Scrape(ctx context.Context, agent Agent) ([]*dto.MetricFamily, error)
	Profile(ctx context.Context, agent Agent) (Profile, error)
	ProfileStacks(ctx context.Context, agent Agent, format StackFormat, sel profiling.StackSelection) ([]byte, error)
	IssueEvents(ctx context.Context, namespace string) ([]corev1.Event, error)
	ActiveIssues(ctx context.Context, agent Agent) ([]LiveIssue, error)
	Components(ctx context.Context) ([]Component, error)
	Correlations(ctx context.Context) (Correlation, error)
}

// Correlation is the operator's latest cluster-wide link of each active
// issue to its likely root causes.
type Correlation struct {
	GeneratedAt  time.Time         `json:"generatedAt"`
	AgentsRead   int               `json:"agentsRead"`
	AgentsFailed int               `json:"agentsFailed"`
	Issues       []CorrelatedIssue `json:"issues"`
}

// CorrelatedIssue is one issue of a Correlation.
type CorrelatedIssue struct {
	detector.IssueRef
	Causes []detector.Cause `json:"causes,omitempty"`
}

// LiveIssue is one firing issue as an agent's /issues serves it: its latest
// message and the time it activated.
type LiveIssue struct {
	ID        string    `json:"id"`
	Severity  string    `json:"severity"`
	Namespace string    `json:"namespace"`
	Workload  string    `json:"workload"`
	Pod       string    `json:"pod,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	Since     time.Time `json:"since"`
	Message   string    `json:"message"`

	Causes []detector.Cause `json:"causes,omitempty"`
}

// KubeCluster reads the agents through the API server's pod proxy, so it
// needs nothing beyond the user's kubeconfig: no port-forward, and no route
// from the workstation to the pod network.
type KubeCluster struct {
	Client          kubernetes.Interface
	SystemNamespace string
}

// Agents lists the agent pods of every fleet.
func (k *KubeCluster) Agents(ctx context.Context) ([]Agent, error) {
	pods, err := k.Client.CoreV1().Pods(k.SystemNamespace).List(ctx, metav1.ListOptions{LabelSelector: agentSelector})
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(pods.Items))
	for i := range pods.Items {
		if pods.Items[i].DeletionTimestamp != nil {
			continue
		}
		out = append(out, agentOf(&pods.Items[i]))
	}
	return out, nil
}

func agentOf(p *corev1.Pod) Agent {
	a := Agent{
		Name:  p.Name,
		Node:  p.Spec.NodeName,
		Fleet: p.Labels[tracerConfigLabel],
		Phase: p.Status.Phase,
		Port:  defaultMetricsPort,
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			a.Ready = c.Status == corev1.ConditionTrue
		}
	}
	for _, cs := range p.Status.ContainerStatuses {
		a.Restarts += cs.RestartCount
	}
	for _, c := range p.Spec.Containers {
		for _, port := range c.Ports {
			switch port.Name {
			case metricsPortName:
				a.Port = port.ContainerPort
			case inspectPortName:
				a.InspectPort = port.ContainerPort
			}
		}
	}
	if a.InspectPort == 0 {
		a.InspectPort = a.Port
	}
	return a
}

// inspectTarget addresses an agent's inspection endpoints.
func inspectTarget(agent Agent) Agent {
	if agent.InspectPort != 0 {
		agent.Port = agent.InspectPort
	}
	return agent
}

// proxyGet fetches path from agent.Port through the API server's pod proxy.
func (k *KubeCluster) proxyGet(ctx context.Context, agent Agent, path, accept string, params ...[2]string) ([]byte, string, error) {
	var contentType string
	req := k.Client.CoreV1().RESTClient().Get().
		Namespace(k.SystemNamespace).
		Resource("pods").
		Name(agent.Name + ":" + strconv.Itoa(int(agent.Port))).
		SubResource("proxy").
		Suffix(path)
	for _, p := range params {
		req = req.Param(p[0], p[1])
	}
	if accept != "" {
		req = req.SetHeader("Accept", accept)
	}
	raw, err := req.Do(ctx).ContentType(&contentType).Raw()
	return raw, contentType, err
}

// Scrape reads one agent's /metrics.
func (k *KubeCluster) Scrape(ctx context.Context, agent Agent) ([]*dto.MetricFamily, error) {
	raw, contentType, err := k.proxyGet(ctx, agent, "metrics", protobufAccept)
	if err != nil {
		return nil, err
	}
	return DecodeMetrics(raw, contentType)
}

// DecodeMetrics decodes a /metrics body in whichever format the agent chose.
func DecodeMetrics(raw []byte, contentType string) ([]*dto.MetricFamily, error) {
	format := expfmt.ResponseFormat(http.Header{"Content-Type": []string{contentType}})
	if format.FormatType() == expfmt.TypeTextPlain || format.FormatType() == expfmt.TypeUnknown {
		parser := expfmt.NewTextParser(model.UTF8Validation)
		families, err := parser.TextToMetricFamilies(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("decode metrics: %w", err)
		}
		out := make([]*dto.MetricFamily, 0, len(families))
		for _, f := range families {
			out = append(out, f)
		}
		return out, nil
	}
	dec := expfmt.NewDecoder(bytes.NewReader(raw), format)
	var out []*dto.MetricFamily
	for {
		f := &dto.MetricFamily{}
		if err := dec.Decode(f); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, fmt.Errorf("decode metrics: %w", err)
		}
		out = append(out, f)
	}
}

// ActiveIssues reads one agent's /issues. An agent older than the endpoint,
// or one with inspections off, answers with an error, and the caller falls
// back to the issues' Events.
func (k *KubeCluster) ActiveIssues(ctx context.Context, agent Agent) ([]LiveIssue, error) {
	raw, _, err := k.proxyGet(ctx, inspectTarget(agent), "issues", "application/json")
	if err != nil {
		return nil, err
	}
	var body struct {
		Issues []LiveIssue `json:"issues"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("decode issues: %w", err)
	}
	return body.Issues, nil
}

// Profile reads one agent's /profile.
func (k *KubeCluster) Profile(ctx context.Context, agent Agent) (Profile, error) {
	raw, _, err := k.proxyGet(ctx, inspectTarget(agent), "profile", "application/json")
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return Profile{}, fmt.Errorf("decode profile: %w", err)
	}
	return p, nil
}

// ProfileStacks reads one workload's whole stacks from one agent's /profile,
// as folded text or a gzipped pprof profile.
func (k *KubeCluster) ProfileStacks(ctx context.Context, agent Agent, format StackFormat, sel profiling.StackSelection) ([]byte, error) {
	params := [][2]string{{"format", string(format)}, {"namespace", sel.Namespace}, {"workload", sel.Workload}}
	if sel.SlowRequests {
		params = append(params, [2]string{"requests", "slow"})
	}
	raw, _, err := k.proxyGet(ctx, inspectTarget(agent), "profile", "", params...)
	return raw, err
}

// IssueEvents lists the Events the agents wrote for issues.
func (k *KubeCluster) IssueEvents(ctx context.Context, namespace string) ([]corev1.Event, error) {
	list, err := k.Client.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("reason", alerting.EventReasonAlert).String(),
	})
	if err != nil {
		return nil, err
	}
	out := list.Items[:0]
	for _, e := range list.Items {
		if e.Reason == alerting.EventReasonAlert && e.Annotations[alerting.AnnotationAlertSource] == alerting.AlertSourceIssue {
			out = append(out, e)
		}
	}
	return out, nil
}

// Correlations reads the operator's /correlations through the pod proxy.
func (k *KubeCluster) Correlations(ctx context.Context) (Correlation, error) {
	pods, err := k.Client.CoreV1().Pods(k.SystemNamespace).List(ctx, metav1.ListOptions{LabelSelector: operatorSelector})
	if err != nil {
		return Correlation{}, err
	}
	lastErr := errors.New("no running operator pod")
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
			continue
		}
		target := Agent{Name: p.Name, Port: operatorMetricsPort}
		for _, c := range p.Spec.Containers {
			for _, port := range c.Ports {
				if port.Name == metricsPortName {
					target.Port = port.ContainerPort
				}
			}
		}
		raw, _, err := k.proxyGet(ctx, target, "correlations", "application/json")
		if err != nil {
			lastErr = err
			continue
		}
		var c Correlation
		if err := json.Unmarshal(raw, &c); err != nil {
			lastErr = fmt.Errorf("decode correlations: %w", err)
			continue
		}
		return c, nil
	}
	return Correlation{}, lastErr
}

// Components lists the operator Deployment and every fleet's agent
// DaemonSet. Helm and OLM installs label the operator the same way.
func (k *KubeCluster) Components(ctx context.Context) ([]Component, error) {
	deployments, err := k.Client.AppsV1().Deployments(k.SystemNamespace).List(ctx, metav1.ListOptions{LabelSelector: operatorSelector})
	if err != nil {
		return nil, err
	}
	daemonSets, err := k.Client.AppsV1().DaemonSets(k.SystemNamespace).List(ctx, metav1.ListOptions{LabelSelector: agentSelector})
	if err != nil {
		return nil, err
	}
	out := make([]Component, 0, len(deployments.Items)+len(daemonSets.Items))
	for _, d := range deployments.Items {
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		out = append(out, Component{Kind: KindOperator, Name: d.Name, Desired: desired,
			Ready: d.Status.AvailableReplicas, Updated: d.Status.UpdatedReplicas})
	}
	for _, ds := range daemonSets.Items {
		out = append(out, Component{Kind: KindFleet, Name: ds.Name, Fleet: ds.Labels[tracerConfigLabel],
			Desired: ds.Status.DesiredNumberScheduled, Ready: ds.Status.NumberReady, Updated: ds.Status.UpdatedNumberScheduled})
	}
	return out, nil
}
