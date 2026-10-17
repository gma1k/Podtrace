package operator

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func bootstrappedAgentEnv(t *testing.T) map[string]string {
	t.Helper()
	c := bootstrapTestScheme(t)
	b := &BootstrapDefaultTracerConfig{
		Client:          c,
		SystemNamespace: "podtrace-system",
		FallbackImage:   "ghcr.io/gma1k/podtrace:test",
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	var got podtracev1alpha1.TracerConfig
	if err := c.Get(context.Background(), types.NamespacedName{Name: DefaultTracerConfigName}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	spec := buildAgentDaemonSetSpec(&got, "podtrace-system")
	return envMap(spec.Template.Spec.Containers[0].Env)
}

func TestTheBootstrappedTracerConfigRunsTheWholePlane(t *testing.T) {
	env := bootstrappedAgentEnv(t)
	for _, name := range []string{
		envMetricsEnabled,
		envMetricsNativeHistograms,
		envMetricsKernelAggregation,
		envInspectionsEnabled,
		envInspectionsAlerts,
		"PODTRACE_CONTINUOUS_PROFILING_ENABLED",
		"PODTRACE_SOCKOPS_RTT_ENABLED",
		"PODTRACE_DNS_PACKET_CAPTURE",
		"PODTRACE_USDT_ENABLED",
		"PODTRACE_UPROBE_MULTI",
		"PODTRACE_DNS_PAYLOAD_ENABLED",
	} {
		if env[name] != "true" {
			t.Errorf("%s = %q, want true; OLM and raw-manifest installs run on this object, "+
				"and with it off they get no continuous APM", name, env[name])
		}
	}
}

func TestTheBootstrappedTracerConfigKeepsPodtraceOutOfItsOwnMetrics(t *testing.T) {
	if got := bootstrappedAgentEnv(t)[envMetricsExcludeNamespaces]; got != "podtrace-system" {
		t.Errorf("%s = %q, want podtrace-system, as a chart install excludes it",
			envMetricsExcludeNamespaces, got)
	}
}

func TestABootstrapWithoutASystemNamespaceExcludesNothing(t *testing.T) {
	tc := NewBootstrapTracerConfig("default", "ghcr.io/gma1k/podtrace:test", "")
	if tc.Spec.Agent.Metrics != nil {
		t.Errorf("metrics block = %+v, want none; an exclusion of \"\" is not a namespace",
			tc.Spec.Agent.Metrics)
	}
	if !tc.Spec.Agent.Metrics.MetricsEnabled() {
		t.Error("the plane is off without a metrics block")
	}
}
