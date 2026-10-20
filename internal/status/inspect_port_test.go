package status

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestAgentsKnowTheirInspectPort(t *testing.T) {
	p := agentPod("a", "n1", true, 0, 9090)
	p.Spec.Containers[0].Ports = append(p.Spec.Containers[0].Ports, corev1.ContainerPort{Name: inspectPortName, ContainerPort: 9192})
	if got := agentOf(p); got.Port != 9090 || got.InspectPort != 9192 {
		t.Errorf("ports = metrics %d, inspect %d; want 9090 and 9192", got.Port, got.InspectPort)
	}
}

func TestAnAgentFromBeforeTheInspectPortIsReadOnItsMetricsPort(t *testing.T) {
	if got := agentOf(agentPod("a", "n1", true, 0, 9095)).InspectPort; got != 9095 {
		t.Errorf("inspect port = %d, want the metrics port 9095 that such an agent serves /issues on", got)
	}
}

func TestIssuesAndProfilesGoToTheInspectPortAndMetricsDoNot(t *testing.T) {
	profile, _ := json.Marshal(Profile{})
	s := &apiServer{t: t, profile: profile, issues: []byte(`{"issues":[]}`), metrics: []byte{}, mtype: "text/plain"}
	k := &KubeCluster{Client: s.start(), SystemNamespace: "podtrace-system"}
	agent := Agent{Name: "a", Port: 9090, InspectPort: 9092}

	if _, err := k.ActiveIssues(context.Background(), agent); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Profile(context.Background(), agent); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Scrape(context.Background(), agent); err != nil {
		t.Fatal(err)
	}

	want := []string{"pods/a:9092/proxy/issues", "pods/a:9092/proxy/profile", "pods/a:9090/proxy/metrics"}
	if len(s.paths) != len(want) {
		t.Fatalf("paths = %v", s.paths)
	}
	for i, suffix := range want {
		if !strings.HasSuffix(s.paths[i], suffix) {
			t.Errorf("request %d went to %s, want …%s", i, s.paths[i], suffix)
		}
	}
}
