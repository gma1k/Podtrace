package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/gma1k/podtrace/internal/config"
	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func TestExitCodes(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
	}{
		"plain error":           {errors.New("boom"), 1},
		"spawn pod exit code":   {fmt.Errorf("run: %w", &nodespawn.ExitError{Code: 3}), 3},
		"spawn pod exit code 0": {&nodespawn.ExitError{Code: 0}, 1},
		"interrupted spawn":     {fmt.Errorf("run: %w", nodespawn.ErrInterrupted), 130},
		"interrupted status":    {errInterrupted, 130},
	}
	for name, tc := range cases {
		if got := exitCode(tc.err); got != tc.want {
			t.Errorf("%s: exitCode = %d, want %d", name, got, tc.want)
		}
	}
}

func TestTheFirstSignalStopsAndTheSecondAborts(t *testing.T) {
	exited := make(chan int, 1)
	orig := exitFunc
	exitFunc = func(code int) { exited <- code }
	t.Cleanup(func() { exitFunc = orig })

	signals := make(chan os.Signal, 2)
	done := make(chan struct{})
	stopped, aborted := make(chan struct{}), make(chan struct{})
	go watchSignals(signals, func() { close(stopped) }, func() { close(aborted) }, done, io.Discard)

	signals <- syscall.SIGINT
	<-stopped
	select {
	case <-aborted:
		t.Fatal("the first signal aborted")
	default:
	}
	signals <- syscall.SIGINT
	<-aborted
	close(done)
	select {
	case code := <-exited:
		if code != 130 {
			t.Fatalf("exit code %d, want 130", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second signal did not exit")
	}
}

func TestSignalWatchingEndsWithTheCommand(t *testing.T) {
	done := make(chan struct{})
	close(done)
	returned := make(chan struct{})
	go func() {
		watchSignals(make(chan os.Signal), func() { t.Error("cancelled without a signal") }, func() {}, done, io.Discard)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("watchSignals outlived its command")
	}

	signals := make(chan os.Signal, 1)
	done = make(chan struct{})
	stopped := make(chan struct{})
	returned = make(chan struct{})
	go func() {
		watchSignals(signals, func() { close(stopped) }, func() { t.Error("aborted without a second signal") }, done, io.Discard)
		close(returned)
	}()
	signals <- syscall.SIGTERM
	<-stopped
	close(done)
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("watchSignals outlived its command after a graceful stop")
	}
}

func TestBlankPodRefsAreIgnoredWhenScoping(t *testing.T) {
	if err := validatePodRefScope([]string{" ", "a/x"}, "default", nil, true); err != nil {
		t.Fatal(err)
	}
}

func TestABareNameWithAllNamespacesStopsTheCommand(t *testing.T) {
	orig, origNamespace := watchAllNamespaces, namespace
	watchAllNamespaces, namespace = true, "default"
	t.Cleanup(func() { watchAllNamespaces, namespace = orig, origNamespace })
	useEmptyKubeconfig(t)
	err := runPodtrace(&cobra.Command{}, []string{"x"})
	if err == nil || !strings.Contains(err.Error(), "has no namespace") {
		t.Fatalf("err = %v", err)
	}
}

func TestTheDefaultResolverUsesTheKubeconfigFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	const content = "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster: {server: https://127.0.0.1:6443}\ncontexts:\n- name: c\n  context: {cluster: c, user: u}\ncurrent-context: c\nusers:\n- name: u\n  user: {token: t}\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := kubeconfigPath
	kubeconfigPath = path
	t.Cleanup(func() { kubeconfigPath = orig })
	r, err := pkgkube.NewPodResolverFor(clusterAccess())
	if err != nil {
		t.Fatal(err)
	}
	if got := r.GetRestConfig().Host; got != "https://127.0.0.1:6443" {
		t.Fatalf("resolver reached %q", got)
	}
	def, err := defaultResolverFactory()
	if err != nil || def == nil {
		t.Fatalf("default factory: %v", err)
	}
}

func TestMigrateStorageRefusesAnUnusableKubeconfig(t *testing.T) {
	cmd := newMigrateStorageCmd()
	cmd.SetArgs([]string{"--kubeconfig", filepath.Join(t.TempDir(), "absent"), "--dry-run"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected a kubeconfig error")
	}
}

func TestEndpointCredentialDetectionEdgeCases(t *testing.T) {
	cases := map[string]bool{
		"":                          false,
		"   ":                       false,
		"http://[::1":               false,
		"http://u:p@[::1":           true,
		"otel.example:4318":         false,
		"https://otel.example:4318": false,
	}
	for endpoint, want := range cases {
		if got := endpointHasCredentials(endpoint); got != want {
			t.Errorf("endpointHasCredentials(%q) = %v, want %v", endpoint, got, want)
		}
	}
}

type sharedClusterResolver struct{ cs *fake.Clientset }

func (r sharedClusterResolver) ResolvePod(context.Context, string, string, string) (*pkgkube.PodInfo, error) {
	return nil, errors.New("unused")
}
func (r sharedClusterResolver) GetClientset() k8s.Interface { return r.cs }
func (r sharedClusterResolver) GetRestConfig() *rest.Config { return &rest.Config{} }

func TestTheSpawnFlowHandsTheSelectionToNodespawn(t *testing.T) {
	saveSpawnGlobals(t)
	saveNodespawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	t.Setenv("PODTRACE_SPAWN_NAMESPACE", "")
	localMode = false
	spawnImage = "ghcr.io/gma1k/podtrace:test"
	cs := fake.NewClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", ContainerID: "containerd://abcdef0123456789",
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	})
	cs.PrependReactor("create", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("admission denied")
	})

	handled, err := maybeSpawnOnNode(context.Background(), nil, &cobra.Command{}, sharedClusterResolver{cs},
		pkgkube.TargetSelection{DefaultNamespace: "shop", Pods: []string{"api"}})
	if !handled || err == nil || !strings.Contains(err.Error(), "admission denied") {
		t.Fatalf("handled=%v err=%v; want the spawn pod creation to have been attempted", handled, err)
	}
}

func TestAnInterruptBeforeTheFirstHealthReadIsNotReportedAsAProblem(t *testing.T) {
	useStatusFake(t, newStatusFake())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var progress strings.Builder
	if err := runStatus(ctx, waitOptions(), io.Discard, &progress); !errors.Is(err, errInterrupted) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(progress.String(), "waiting") {
		t.Fatalf("progress = %q", progress.String())
	}
}

func TestSessionHeaderAndCredentialErrorsStopTheSession(t *testing.T) {
	defer resetTracingConfig()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.yaml")
	if err := os.WriteFile(bundlePath, []byte("type: otlp\nendpoint: otel:4318\nheaderName: Authorization\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PODTRACE_EXPORTER_CREDENTIAL", "Bearer x")
	t.Setenv("PODTRACE_EXPORTER_CREDENTIAL_FILE", filepath.Join(notADir, "credential"))
	if err := applyExporterFromFile(bundlePath); err == nil || !strings.Contains(err.Error(), "credential directory") {
		t.Fatalf("an unreadable credential directory: err = %v", err)
	}

	t.Setenv("PODTRACE_EXPORTER_CREDENTIAL", "")
	t.Setenv("PODTRACE_EXPORTER_CREDENTIAL_FILE", filepath.Join(dir, "no-such-dir", "credential"))
	if err := applyExporterFromFile(bundlePath); err == nil || !strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("a Secret-backed header without its credential: err = %v", err)
	}

	credentialDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(credentialDir, bundle.SecretHeaderKeyPrefix+"X-Api-Key"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretHeaders(credentialDir); err == nil {
		t.Fatal("an unreadable header file must be an error")
	}
	if headers, err := readSecretHeaders(filepath.Join(dir, "absent")); err != nil || headers != nil {
		t.Fatalf("a missing credential directory: %v %v", headers, err)
	}
}

func TestAnInvalidHeaderNameStopsTheSession(t *testing.T) {
	defer resetTracingConfig()
	err := applyPayloadToConfig(&bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel:4318", Headers: map[string]string{"bad header": "v"}})
	if err == nil || !strings.Contains(err.Error(), "bad header") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnsupportedExporterSettingsAreWarnedNotFatal(t *testing.T) {
	defer resetTracingConfig()
	if err := applyPayloadToConfig(&bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel:4317", Protocol: "grpc"}); err != nil {
		t.Fatal(err)
	}
	if err := applyPayloadToConfig(&bundle.Payload{Type: bundle.TypeZipkin, Endpoint: "http://zipkin:9411", Headers: map[string]string{"X-Tenant": "a"}}); err != nil {
		t.Fatal(err)
	}
	if config.OTLPHeaders != nil {
		t.Fatalf("headers for a non-OTLP exporter leaked into OTLPHeaders: %v", config.OTLPHeaders)
	}
}

func TestASecondSignalExitsEvenIfTheCommandNeverUnwinds(t *testing.T) {
	exited := make(chan int, 1)
	origExit, origGrace := exitFunc, secondSignalGracePeriod
	exitFunc = func(code int) { exited <- code }
	secondSignalGracePeriod = 10 * time.Millisecond
	t.Cleanup(func() { exitFunc, secondSignalGracePeriod = origExit, origGrace })

	signals := make(chan os.Signal, 2)
	signals <- syscall.SIGINT
	signals <- syscall.SIGINT
	go watchSignals(signals, func() {}, func() {}, make(chan struct{}), io.Discard)
	select {
	case code := <-exited:
		if code != 130 {
			t.Fatalf("exit code %d, want 130", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a wedged command kept the process alive after the second signal")
	}
}
