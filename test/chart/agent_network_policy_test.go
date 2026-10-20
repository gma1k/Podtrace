package chart_test

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
)

func agentPolicy(t *testing.T, flags ...string) networkingv1.NetworkPolicy {
	t.Helper()
	var np networkingv1.NetworkPolicy
	mustFindObject(t, renderChart(t, flags...), "NetworkPolicy", "podtrace-agent").decode(t, &np)
	return np
}

func rulesForPort(np networkingv1.NetworkPolicy, port string) []networkingv1.NetworkPolicyIngressRule {
	var out []networkingv1.NetworkPolicyIngressRule
	for _, rule := range np.Spec.Ingress {
		for _, p := range rule.Ports {
			if p.Port != nil && p.Port.String() == port {
				out = append(out, rule)
			}
		}
	}
	return out
}

func TestTheInspectPortIsClosedToOtherPodsOnceThePolicyIsOn(t *testing.T) {
	rules := rulesForPort(agentPolicy(t, "networkPolicy.enabled=true"), "inspect")
	if len(rules) != 1 {
		t.Fatalf("%d rules name the inspect port, want 1", len(rules))
	}
	if len(rules[0].From) != 1 || rules[0].From[0].PodSelector == nil ||
		rules[0].From[0].PodSelector.MatchLabels["app.kubernetes.io/component"] != "operator" {
		t.Errorf("inspect port is open to %+v; by default only the operator may read /issues and /profile", rules[0].From)
	}
	if rules[0].From[0].NamespaceSelector != nil {
		t.Error("the operator peer must not carry a namespaceSelector; it would admit operator-labelled pods in any namespace")
	}
}

func TestMetricsStayOpenToScrapersWhenThePolicyIsOn(t *testing.T) {
	for _, rule := range rulesForPort(agentPolicy(t, "networkPolicy.enabled=true"), "metrics") {
		if len(rule.From) == 0 {
			return
		}
	}
	t.Error("no rule admits every source to the metrics port; turning the policy on " +
		"would cut off Prometheus in any namespace not named in metricsFrom")
}

func TestInspectFromAddsPeers(t *testing.T) {
	rules := rulesForPort(agentPolicy(t, "networkPolicy.enabled=true", "networkPolicy.inspectFrom[0].ipBlock.cidr=10.0.0.0/24"), "inspect")
	if len(rules) != 1 || len(rules[0].From) != 2 || rules[0].From[1].IPBlock == nil ||
		rules[0].From[1].IPBlock.CIDR != "10.0.0.0/24" {
		t.Errorf("inspect peers = %+v, want the operator plus 10.0.0.0/24", rules)
	}
}

func TestThePolicyIsOptIn(t *testing.T) {
	if _, ok := findObject(t, renderChart(t), "NetworkPolicy", "podtrace-agent"); ok {
		t.Error("the agent policy renders by default; on a CNI that enforces it but is not " +
			"Cilium it cuts kubectl podtrace status off from /issues and /profile")
	}
}
