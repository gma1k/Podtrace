package operator

import (
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestASessionJobMayReachTheSameCleartextCollectorsAsTheAgent(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{Spec: podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"}}
	spec := buildSessionJobSpec(newSession(nil), tc, "node-a", sessionTargets{})

	env := map[string]string{}
	for _, e := range spec.Template.Spec.Containers[0].Env {
		env[e.Name] = e.Value
	}
	for _, name := range []string{"PODTRACE_OTLP_INSECURE", "PODTRACE_EXPORTER_INSECURE"} {
		if env[name] != "1" {
			t.Errorf("%s = %q, want 1", name, env[name])
		}
	}
}
