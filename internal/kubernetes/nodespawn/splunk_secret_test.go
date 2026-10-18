package nodespawn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const testSplunkToken = "super-secret-hec-token-value-01234"

func splunkTokenEnvVar(t *testing.T, opts PodSpecOptions) (*corev1.EnvVar, string) {
	t.Helper()
	pod, err := BuildPodSpec(opts)
	if err != nil {
		t.Fatalf("BuildPodSpec: %v", err)
	}
	var env *corev1.EnvVar
	for i := range pod.Spec.Containers[0].Env {
		if pod.Spec.Containers[0].Env[i].Name == "PODTRACE_SPLUNK_TOKEN" {
			env = &pod.Spec.Containers[0].Env[i]
		}
	}
	blob, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	if opts.SplunkToken != "" && strings.Contains(string(blob), opts.SplunkToken) {
		t.Fatalf("raw Splunk token leaked into the pod spec: %s", blob)
	}
	return env, pod.Name
}

func TestBuildPodSpec_SplunkTokenViaSecretRef(t *testing.T) {
	o := baseOpts()
	o.SplunkToken = testSplunkToken
	env, podName := splunkTokenEnvVar(t, o)
	if env == nil {
		t.Fatalf("%s env not present when a token is set", "PODTRACE_SPLUNK_TOKEN")
		return
	}
	if env.Value != "" {
		t.Errorf("%s carried a plaintext value %q; must use a SecretKeyRef", "PODTRACE_SPLUNK_TOKEN", env.Value)
	}
	if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
		t.Fatalf("%s must be sourced from a SecretKeyRef", "PODTRACE_SPLUNK_TOKEN")
	}
	ref := env.ValueFrom.SecretKeyRef
	if ref.Key != SplunkSecretKey {
		t.Errorf("SecretKeyRef key = %q, want %q", ref.Key, SplunkSecretKey)
	}
	if ref.Name != SpawnSecretName(podName) {
		t.Errorf("SecretKeyRef name = %q, want %q", ref.Name, SpawnSecretName(podName))
	}
}

func TestBuildPodSpec_NoSplunkTokenNoEnv(t *testing.T) {
	env, _ := splunkTokenEnvVar(t, baseOpts())
	if env != nil {
		t.Errorf("%s env must be absent when no token is set", "PODTRACE_SPLUNK_TOKEN")
	}
}

func TestSpawnSecretName_Deterministic(t *testing.T) {
	if got := SpawnSecretName("podtrace-cli-worker-1-abc"); got != "podtrace-cli-worker-1-abc-credentials" {
		t.Errorf("SpawnSecretName = %q", got)
	}
}

func TestSplunkTokenSecretLifecycle(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset()
	const ns, name = "kube-system", "podtrace-cli-worker-1-splunk"

	if err := createSplunkTokenSecret(ctx, cs, ns, name, map[string]string{"k": "v"}, testSplunkToken); err != nil {
		t.Fatalf("create: %v", err)
	}
	sec, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := sec.StringData[SplunkSecretKey]; got != testSplunkToken {
		t.Errorf("stored token = %q, want %q", got, testSplunkToken)
	}

	if err := createSplunkTokenSecret(ctx, cs, ns, name, nil, testSplunkToken); err != nil {
		t.Errorf("re-create should be idempotent: %v", err)
	}

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podtrace-cli-worker-1", Namespace: ns, UID: "pod-uid-123"}}
	if err := ownSecretByPod(ctx, cs, pod, name); err != nil {
		t.Fatalf("own: %v", err)
	}
	sec, _ = cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if len(sec.OwnerReferences) != 1 || sec.OwnerReferences[0].UID != "pod-uid-123" {
		t.Errorf("owner references = %+v, want one ref to pod-uid-123", sec.OwnerReferences)
	}

	if err := DeleteSecret(ctx, cs, ns, name); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{}); !IsNotFound(err) {
		t.Errorf("secret should be gone after delete, got err=%v", err)
	}
	if err := DeleteSecret(ctx, cs, ns, name); err != nil {
		t.Errorf("delete of absent secret should be nil, got %v", err)
	}
}
