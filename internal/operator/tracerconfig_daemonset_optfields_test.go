package operator

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func envValue(env []corev1.EnvVar, name string) (string, bool) {
	for _, e := range env {
		if e.Name == name {
			return e.Value, true
		}
	}
	return "", false
}

func TestBuildAgentDaemonSetSpec_OptionalAgentFields(t *testing.T) {
	dpcOff := false
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.ImagePullPolicy = corev1.PullAlways
		x.Spec.Agent.LogLevel = "debug"
		x.Spec.Agent.EventBufferSize = 4096
		x.Spec.Agent.DNSPacketCapture = &dpcOff
		x.Spec.Agent.StatusReportInterval = &metav1.Duration{Duration: 15 * time.Second}
	}), "podtrace-system")

	c := spec.Template.Spec.Containers[0]

	if c.ImagePullPolicy != corev1.PullAlways {
		t.Errorf("ImagePullPolicy=%q want Always", c.ImagePullPolicy)
	}
	if v, ok := envValue(c.Env, "PODTRACE_LOG_LEVEL"); !ok || v != "debug" {
		t.Errorf("PODTRACE_LOG_LEVEL=%q ok=%v want debug", v, ok)
	}
	if v, ok := envValue(c.Env, "PODTRACE_EVENT_BUFFER_SIZE"); !ok || v != "4096" {
		t.Errorf("PODTRACE_EVENT_BUFFER_SIZE=%q ok=%v want 4096", v, ok)
	}
	if v, ok := envValue(c.Env, "PODTRACE_DNS_PACKET_CAPTURE"); !ok || v != "false" {
		t.Errorf("PODTRACE_DNS_PACKET_CAPTURE=%q ok=%v want false", v, ok)
	}

	joined := ""
	for _, a := range c.Args {
		joined += a + " "
	}
	if !contains(joined, "--status-report-interval 15s") {
		t.Errorf("--status-report-interval not wired: %v", c.Args)
	}
}

func TestBuildAgentDaemonSetSpec_CapabilitySwitches(t *testing.T) {
	on := true
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.USDT = &on
		x.Spec.Agent.DNSFullAnswers = &on
	}), "podtrace-system")
	env := spec.Template.Spec.Containers[0].Env

	if v, ok := envValue(env, "PODTRACE_USDT_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_USDT_ENABLED=%q ok=%v want true", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_DNS_PAYLOAD_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_DNS_PAYLOAD_ENABLED=%q ok=%v want true", v, ok)
	}
}

func TestBuildAgentDaemonSetSpec_CapabilityDefaults(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {}), "podtrace-system")
	env := spec.Template.Spec.Containers[0].Env
	if v, ok := envValue(env, "PODTRACE_USDT_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_USDT_ENABLED=%q ok=%v want true (default on)", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_DNS_PAYLOAD_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_DNS_PAYLOAD_ENABLED=%q ok=%v want true (default on)", v, ok)
	}
}

func TestBuildAgentDaemonSetSpec_CapabilityExplicitDisable(t *testing.T) {
	off := false
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.USDT = &off
		x.Spec.Agent.DNSFullAnswers = &off
	}), "podtrace-system")
	env := spec.Template.Spec.Containers[0].Env
	if v, ok := envValue(env, "PODTRACE_USDT_ENABLED"); !ok || v != "false" {
		t.Errorf("PODTRACE_USDT_ENABLED=%q ok=%v want false (explicit disable)", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_DNS_PAYLOAD_ENABLED"); !ok || v != "false" {
		t.Errorf("PODTRACE_DNS_PAYLOAD_ENABLED=%q ok=%v want false (explicit disable)", v, ok)
	}
}

func TestBuildAgentDaemonSetSpec_DNSPacketCaptureIsWrittenOut(t *testing.T) {
	for name, field := range map[string]*bool{"unset": nil, "on": ptr(true)} {
		t.Run(name, func(t *testing.T) {
			spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
				x.Spec.Agent.DNSPacketCapture = field
			}), "podtrace-system")
			if v, ok := envValue(spec.Template.Spec.Containers[0].Env, "PODTRACE_DNS_PACKET_CAPTURE"); !ok || v != "true" {
				t.Errorf("PODTRACE_DNS_PACKET_CAPTURE=%q ok=%v, want true", v, ok)
			}
		})
	}
}

func TestRolloutMaxUnavailableReachesTheUpdateStrategy(t *testing.T) {
	for name, want := range map[string]intstr.IntOrString{
		"percentage": intstr.FromString("100%"),
		"count":      intstr.FromInt32(2),
	} {
		t.Run(name, func(t *testing.T) {
			value := want
			ds := buildAgentDaemonSetSpec(&podtracev1alpha1.TracerConfig{
				Spec: podtracev1alpha1.TracerConfigSpec{
					Agent: podtracev1alpha1.AgentSpec{RolloutMaxUnavailable: &value},
				},
			}, "podtrace-system")

			if ds.UpdateStrategy.Type != appsv1.RollingUpdateDaemonSetStrategyType {
				t.Fatalf("strategy type = %q, want RollingUpdate", ds.UpdateStrategy.Type)
			}
			if ds.UpdateStrategy.RollingUpdate == nil {
				t.Fatal("rolloutMaxUnavailable was set but no RollingUpdate block was " +
					"rendered.\n\nThe chart surfaces this value and the agent fleet then " +
					"rolls one pod at a time, so a fleet-wide restart takes minutes longer " +
					"than the operator asked for.")
			}
			if got := ds.UpdateStrategy.RollingUpdate.MaxUnavailable; got == nil || *got != want {
				t.Errorf("MaxUnavailable = %v, want %v", got, want)
			}
		})
	}
}

func TestRolloutMaxUnavailableCountWrittenAsStringBecomesAnInteger(t *testing.T) {
	for in, want := range map[string]intstr.IntOrString{
		"2":   intstr.FromInt32(2),
		"0":   intstr.FromInt32(0),
		"25%": intstr.FromString("25%"),
		"-1":  intstr.FromString("-1"),
		"2x":  intstr.FromString("2x"),
	} {
		t.Run(in, func(t *testing.T) {
			value := intstr.FromString(in)
			ds := buildAgentDaemonSetSpec(&podtracev1alpha1.TracerConfig{
				Spec: podtracev1alpha1.TracerConfigSpec{
					Agent: podtracev1alpha1.AgentSpec{RolloutMaxUnavailable: &value},
				},
			}, "podtrace-system")

			got := ds.UpdateStrategy.RollingUpdate.MaxUnavailable
			if got == nil || *got != want {
				t.Errorf("MaxUnavailable for %q = %v, want %v: the API server rejects a "+
					"string that is not a percentage, so every DaemonSet write would fail",
					in, got, want)
			}
		})
	}
}

func TestNoRolloutMaxUnavailableLeavesTheDefaultStrategy(t *testing.T) {
	ds := buildAgentDaemonSetSpec(&podtracev1alpha1.TracerConfig{}, "podtrace-system")

	if ds.UpdateStrategy.Type != appsv1.RollingUpdateDaemonSetStrategyType {
		t.Errorf("strategy type = %q, want RollingUpdate", ds.UpdateStrategy.Type)
	}
	if ds.UpdateStrategy.RollingUpdate != nil {
		t.Errorf("RollingUpdate = %+v with nothing configured; the Kubernetes default "+
			"should stand rather than being pinned here", ds.UpdateStrategy.RollingUpdate)
	}
}

func TestTheAgentDaemonSetDeclaresTheInspectPort(t *testing.T) {
	spec := buildAgentDaemonSetSpec(&podtracev1alpha1.TracerConfig{}, "podtrace-system")
	pod := &corev1.Pod{Spec: spec.Template.Spec}
	if got := agentPort(pod); got != "9092" {
		t.Errorf("issues are read from port %s, want 9092, the agent's --inspect-addr default", got)
	}
}
