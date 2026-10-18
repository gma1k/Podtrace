package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
)

func spawnFlagsCommand(t *testing.T, set map[string]string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "podtrace"}
	for _, name := range []string{"tracing-otlp-endpoint", "tracing-jaeger-endpoint", "tracing-splunk-endpoint", "tracing-splunk-token", "kubeconfig", "context", "filter"} {
		cmd.Flags().String(name, "", "")
	}
	for name, value := range set {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	return cmd
}

func TestCredentialsInEndpointsReachTheSpawnPodOnlyThroughItsSecret(t *testing.T) {
	cmd := spawnFlagsCommand(t, map[string]string{
		"tracing-otlp-endpoint":   "https://user:s3cr3t@otel.example:4318",
		"tracing-jaeger-endpoint": "jaeger.example:4318",
		"tracing-splunk-endpoint": "admin:hunter2@splunk.example:8088",
	})
	secretEnv := credentialFlags(cmd)
	want := map[string]string{
		"PODTRACE_OTLP_ENDPOINT":   "https://user:s3cr3t@otel.example:4318",
		"PODTRACE_SPLUNK_ENDPOINT": "admin:hunter2@splunk.example:8088",
	}
	if len(secretEnv) != len(want) {
		t.Fatalf("secret env = %v, want %v", secretEnv, want)
	}
	for k, v := range want {
		if secretEnv[k] != v {
			t.Errorf("%s = %q, want %q", k, secretEnv[k], v)
		}
	}

	args := strings.Join(newChildArgsBuilder(cmd, false, secretEnv)("node-1", []nodespawn.PodRef{
		{Namespace: "ns", Name: "p", ContainerID: "abc", ContainerName: "app"},
	}), " ")
	for _, secret := range []string{"s3cr3t", "hunter2"} {
		if strings.Contains(args, secret) {
			t.Errorf("a credential reached the spawn pod's args: %s", args)
		}
	}
	if !strings.Contains(args, "--tracing-jaeger-endpoint=jaeger.example:4318") {
		t.Errorf("an endpoint without credentials must stay in the args: %s", args)
	}
}

func TestWorkstationOnlyFlagsAreNotPassedToTheSpawnPod(t *testing.T) {
	cmd := spawnFlagsCommand(t, map[string]string{
		"kubeconfig":           "/home/me/.kube/prod",
		"context":              "prod",
		"tracing-splunk-token": "hec",
		"filter":               "dns",
	})
	args := strings.Join(newChildArgsBuilder(cmd, false, nil)("node-1", nil), " ")
	for _, flag := range []string{"--kubeconfig", "--context", "--tracing-splunk-token"} {
		if strings.Contains(args, flag) {
			t.Errorf("%s reached the spawn pod's args: %s", flag, args)
		}
	}
	if !strings.Contains(args, "--filter=dns") {
		t.Errorf("a trace flag was dropped: %s", args)
	}
}
