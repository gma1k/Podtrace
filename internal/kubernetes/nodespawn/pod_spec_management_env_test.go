package nodespawn

import "testing"

func TestBuildPodSpec_ForwardsProfilingManagementEnvironment(t *testing.T) {
	t.Setenv("PODTRACE_MANAGEMENT_PORT", "9191")
	t.Setenv("PODTRACE_PROFILING_PPROF_PORTS", "6060,7070")

	pod, err := BuildPodSpec(baseOpts())
	if err != nil {
		t.Fatalf("BuildPodSpec: %v", err)
	}
	got := map[string]string{}
	for _, e := range pod.Spec.Containers[0].Env {
		got[e.Name] = e.Value
	}
	if got["PODTRACE_MANAGEMENT_PORT"] != "9191" {
		t.Errorf("PODTRACE_MANAGEMENT_PORT = %q, want 9191", got["PODTRACE_MANAGEMENT_PORT"])
	}
	if got["PODTRACE_PROFILING_PPROF_PORTS"] != "6060,7070" {
		t.Errorf("PODTRACE_PROFILING_PPROF_PORTS = %q, want 6060,7070", got["PODTRACE_PROFILING_PPROF_PORTS"])
	}
}

func TestBuildPodSpec_OmitsUnsetProfilingManagementEnvironment(t *testing.T) {
	t.Setenv("PODTRACE_MANAGEMENT_PORT", "")
	t.Setenv("PODTRACE_PROFILING_PPROF_PORTS", "")

	pod, err := BuildPodSpec(baseOpts())
	if err != nil {
		t.Fatalf("BuildPodSpec: %v", err)
	}
	for _, e := range pod.Spec.Containers[0].Env {
		if e.Name == "PODTRACE_MANAGEMENT_PORT" || e.Name == "PODTRACE_PROFILING_PPROF_PORTS" {
			t.Fatalf("%s forwarded although unset", e.Name)
		}
	}
}
