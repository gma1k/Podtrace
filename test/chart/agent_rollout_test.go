package chart_test

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func bootstrapTracerConfig(t *testing.T, args ...string) podtracev1alpha1.TracerConfig {
	t.Helper()
	out := renderChartArgs(t, args...)
	var cm corev1.ConfigMap
	mustFindObject(t, out, "ConfigMap", "podtrace-cr-bootstrap").decode(t, &cm)
	var tc podtracev1alpha1.TracerConfig
	if err := yaml.Unmarshal([]byte(cm.Data["tracerconfig.yaml"]), &tc); err != nil {
		t.Fatalf("parse bootstrap TracerConfig: %v\n%s", err, cm.Data["tracerconfig.yaml"])
	}
	return tc
}

func TestRolloutMaxUnavailableKeepsCountsAsIntegers(t *testing.T) {
	for name, tt := range map[string]struct {
		flag string
		want intstr.IntOrString
	}{
		"integer count":        {"--set=agent.rolloutMaxUnavailable=2", intstr.FromInt32(2)},
		"count given as text":  {"--set-string=agent.rolloutMaxUnavailable=3", intstr.FromInt32(3)},
		"percentage":           {"--set=agent.rolloutMaxUnavailable=25%", intstr.FromString("25%")},
		"hundred percent text": {"--set-string=agent.rolloutMaxUnavailable=100%", intstr.FromString("100%")},
	} {
		t.Run(name, func(t *testing.T) {
			tc := bootstrapTracerConfig(t, tt.flag)
			got := tc.Spec.Agent.RolloutMaxUnavailable
			if got == nil || *got != tt.want {
				t.Errorf("rolloutMaxUnavailable = %v, want %v: the API server accepts a string "+
					"only as a percentage, so a quoted count is rejected on every DaemonSet write", got, tt.want)
			}
		})
	}
}

func TestRolloutMaxUnavailableIsLeftOutByDefault(t *testing.T) {
	if got := bootstrapTracerConfig(t).Spec.Agent.RolloutMaxUnavailable; got != nil {
		t.Errorf("rolloutMaxUnavailable = %v, want unset so the Kubernetes default stands", got)
	}
}

func TestRolloutMaxUnavailableRejectsAValueThatIsNeitherCountNorPercentage(t *testing.T) {
	if _, err := helmTemplate(t, "--set", "agent.rolloutMaxUnavailable=fast"); err == nil {
		t.Error("helm template accepted rolloutMaxUnavailable=fast; the schema should refuse it " +
			"before the operator's DaemonSet write does")
	}
}
