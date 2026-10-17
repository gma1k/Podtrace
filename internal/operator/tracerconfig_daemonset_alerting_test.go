package operator

import (
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestBuildAgentDaemonSetSpec_AlertingWiresWebhookEnv(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.Alerting = &podtracev1alpha1.AgentAlertingSpec{
			Enabled:              true,
			WebhookURL:           "https://alerts.example.com/hook",
			AllowInsecureWebhook: true,
		}
	}), "podtrace-system")

	env := spec.Template.Spec.Containers[0].Env
	if v, ok := envValue(env, "PODTRACE_ALERTING_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_ALERTING_ENABLED=%q ok=%v want true", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_ALERT_WEBHOOK_URL"); !ok || v != "https://alerts.example.com/hook" {
		t.Errorf("PODTRACE_ALERT_WEBHOOK_URL=%q ok=%v want the webhook url", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_ALERT_WEBHOOK_ALLOW_HTTP"); !ok || v != "true" {
		t.Errorf("PODTRACE_ALERT_WEBHOOK_ALLOW_HTTP=%q ok=%v want true", v, ok)
	}
}

func TestBuildAgentDaemonSetSpec_AlertingEnabledWithoutOptionalFields(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.Alerting = &podtracev1alpha1.AgentAlertingSpec{Enabled: true}
	}), "podtrace-system")

	env := spec.Template.Spec.Containers[0].Env
	if v, ok := envValue(env, "PODTRACE_ALERTING_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_ALERTING_ENABLED=%q ok=%v want true", v, ok)
	}
	if _, ok := envValue(env, "PODTRACE_ALERT_WEBHOOK_URL"); ok {
		t.Error("PODTRACE_ALERT_WEBHOOK_URL must be absent when WebhookURL is empty")
	}
	if _, ok := envValue(env, "PODTRACE_ALERT_WEBHOOK_ALLOW_HTTP"); ok {
		t.Error("PODTRACE_ALERT_WEBHOOK_ALLOW_HTTP must be absent when AllowInsecureWebhook is false")
	}
}

func TestBuildAgentDaemonSetSpec_AlertingDisabledOmitsEnv(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.Alerting = &podtracev1alpha1.AgentAlertingSpec{Enabled: false, WebhookURL: "https://x"}
	}), "podtrace-system")

	if _, ok := envValue(spec.Template.Spec.Containers[0].Env, "PODTRACE_ALERTING_ENABLED"); ok {
		t.Error("PODTRACE_ALERTING_ENABLED must be absent when alerting is disabled")
	}
}

func TestBuildAgentDaemonSetSpec_GracePeriodCoversProbeDetach(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(nil), "podtrace-system")
	grace := spec.Template.Spec.TerminationGracePeriodSeconds
	if grace == nil || *grace < 90 {
		t.Fatalf("terminationGracePeriodSeconds = %v; an agent with hundreds of uprobes needs about 40s to detach them, and a SIGKILL first leaves the kernel to do it far more slowly", grace)
	}
}

func TestBuildAgentDaemonSetSpec_UprobeMultiToggle(t *testing.T) {
	on := buildAgentDaemonSetSpec(tc(nil), "podtrace-system").Template.Spec.Containers[0].Env
	if v, ok := envValue(on, "PODTRACE_UPROBE_MULTI"); !ok || v != "true" {
		t.Errorf("PODTRACE_UPROBE_MULTI=%q ok=%v, want true by default", v, ok)
	}
	disabled := false
	off := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.UprobeMulti = &disabled
	}), "podtrace-system").Template.Spec.Containers[0].Env
	if v, _ := envValue(off, "PODTRACE_UPROBE_MULTI"); v != "false" {
		t.Errorf("PODTRACE_UPROBE_MULTI=%q, want false when agent.uprobeMulti is off", v)
	}
}
