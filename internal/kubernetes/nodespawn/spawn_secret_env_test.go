package nodespawn

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestSecretEnvIsReferencedNotInlinedInTheSpawnPod(t *testing.T) {
	pod, err := BuildPodSpec(PodSpecOptions{
		NodeName: "n1", Namespace: "ns1", Image: "img",
		SecretEnv: map[string]string{"PODTRACE_OTLP_ENDPOINT": "https://u:s3cr3t@otel:4318"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var found *corev1.EnvVar
	for i, e := range pod.Spec.Containers[0].Env {
		if strings.Contains(e.Value, "s3cr3t") {
			t.Fatalf("credential inlined in env %s", e.Name)
		}
		if e.Name == "PODTRACE_OTLP_ENDPOINT" {
			found = &pod.Spec.Containers[0].Env[i]
		}
	}
	if found == nil || found.ValueFrom == nil || found.ValueFrom.SecretKeyRef == nil {
		t.Fatalf("PODTRACE_OTLP_ENDPOINT is not read from the spawn Secret: %+v", found)
	}
	if ref := found.ValueFrom.SecretKeyRef; ref.Name != SpawnSecretName(pod.Name) || ref.Key != "PODTRACE_OTLP_ENDPOINT" {
		t.Fatalf("SecretKeyRef = %+v", ref)
	}
}

func TestTheSpawnSecretCarriesSecretEnvAndIsCleanedUp(t *testing.T) {
	useClassicListWatch(t)
	cs := fake.NewClientset()
	runningOnCreate(cs)
	spec := spawnPodSpec(t, "ns1")
	var stored map[string]string
	var wmu sync.Mutex
	_ = runOneNode(context.Background(), RunOptions{
		Clientset:  cs,
		RestConfig: &rest.Config{},
		Streams:    genericiooptions.IOStreams{Out: &strings.Builder{}, ErrOut: &strings.Builder{}},
		SecretEnv:  map[string]string{"PODTRACE_OTLP_ENDPOINT": "https://u:s3cr3t@otel:4318"},
		OnPodRunning: func(context.Context, *corev1.Pod) error {
			sec, err := cs.CoreV1().Secrets("ns1").Get(context.Background(), SpawnSecretName(spec.Name), metav1.GetOptions{})
			if err == nil {
				stored = sec.StringData
			}
			return errors.New("stop before attach")
		},
	}, spec, false, &wmu, "")
	if stored["PODTRACE_OTLP_ENDPOINT"] != "https://u:s3cr3t@otel:4318" {
		t.Fatalf("spawn Secret data = %v", stored)
	}
	if _, err := cs.CoreV1().Secrets("ns1").Get(context.Background(), SpawnSecretName(spec.Name), metav1.GetOptions{}); err == nil {
		t.Fatal("the spawn Secret outlived its pod")
	}
}
