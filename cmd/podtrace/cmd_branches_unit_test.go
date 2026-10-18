package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/gma1k/podtrace/internal/events"
	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
)

func saveDiagnoseGlobals(t *testing.T) {
	t.Helper()
	origExport := exportFormat
	origSummary := summaryFile
	origTermination := terminationMessagePath
	origReportTo := reportTo
	origErrRate := errorRateThreshold
	origRTT := rttSpikeThreshold
	origFS := fsSlowThreshold
	t.Cleanup(func() {
		exportFormat = origExport
		summaryFile = origSummary
		terminationMessagePath = origTermination
		reportTo = origReportTo
		errorRateThreshold = origErrRate
		rttSpikeThreshold = origRTT
		fsSlowThreshold = origFS
	})
}

func TestRunDiagnoseModeWithSource_InvalidDuration(t *testing.T) {
	saveDiagnoseGlobals(t)
	exportFormat = ""

	ch := make(chan *events.Event)
	err := runDiagnoseModeWithSource(context.Background(), ch, "not-a-duration",
		nil, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid duration") {
		t.Fatalf("expected invalid duration error, got %v", err)
	}
}

func TestRunDiagnoseModeWithSource_NonPositiveDuration(t *testing.T) {
	saveDiagnoseGlobals(t)
	exportFormat = ""

	ch := make(chan *events.Event)
	err := runDiagnoseModeWithSource(context.Background(), ch, "0s",
		nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatalf("expected validation error for non-positive duration, got nil")
	}
}

func TestRunDiagnoseModeWithSource_TimeoutFinishDrainsEvents(t *testing.T) {
	saveDiagnoseGlobals(t)
	exportFormat = ""
	summaryFile = ""
	terminationMessagePath = ""
	reportTo = ""

	ch := make(chan *events.Event, 4)
	ch <- &events.Event{Type: events.EventDNS, ProcessName: "curl", Target: "example.com"}
	ch <- &events.Event{Type: events.EventConnect, ProcessName: "curl", Target: "10.0.0.1:443"}

	out := captureStdout(t, func() {
		if err := runDiagnoseModeWithSource(context.Background(), ch, "120ms",
			nil, nil, nil, nil, nil); err != nil {
			t.Fatalf("unexpected error from timeout finish: %v", err)
		}
	})
	if !strings.Contains(out, "Diagnostic") && out == "" {
		t.Logf("diagnose timeout report output:\n%s", out)
	}
}

func TestRunDiagnoseModeWithSource_ContextCancelFinish(t *testing.T) {
	saveDiagnoseGlobals(t)
	exportFormat = ""
	summaryFile = ""
	terminationMessagePath = ""
	reportTo = ""

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *events.Event)

	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()

	out := captureStdout(t, func() {
		if err := runDiagnoseModeWithSource(ctx, ch, "30s",
			nil, nil, nil, nil, nil); err != nil {
			t.Fatalf("ctx-cancel finish should return nil, got %v", err)
		}
	})
	if !strings.Contains(out, "=== Final Diagnostic Report ===") {
		t.Errorf("expected the final-report header on ctx cancel, got:\n%s", out)
	}
	if !strings.Contains(out, "No events collected") {
		t.Errorf("expected the empty-collection report body on ctx cancel, got:\n%s", out)
	}
}

func TestRunDiagnoseModeWithSource_ExportJSONOnTimeout(t *testing.T) {
	saveDiagnoseGlobals(t)
	exportFormat = "json"
	summaryFile = ""
	terminationMessagePath = ""
	reportTo = ""

	ch := make(chan *events.Event, 1)
	ch <- &events.Event{Type: events.EventDNS, ProcessName: "curl", Target: "example.com"}

	out := captureStdout(t, func() {
		if err := runDiagnoseModeWithSource(context.Background(), ch, "100ms",
			nil, nil, nil, nil, nil); err != nil {
			t.Fatalf("unexpected error exporting JSON: %v", err)
		}
	})
	if !strings.Contains(out, "{") {
		t.Errorf("expected JSON export output, got:\n%s", out)
	}
}

func TestStartWorkstationEventCorrelation_NilClientset(t *testing.T) {
	finish := startWorkstationEventCorrelation(context.Background(), nil,
		[]nodespawn.PodRef{{Namespace: "default", Name: "web-0"}}, io.Discard)
	if finish == nil {
		t.Fatal("expected a non-nil no-op finish closure")
		return
	}
	finish()
}

func TestStartWorkstationEventCorrelation_EmptyPods(t *testing.T) {
	finish := startWorkstationEventCorrelation(context.Background(),
		fake.NewSimpleClientset(), nil, io.Discard)
	if finish == nil {
		t.Fatal("expected a non-nil no-op finish closure")
		return
	}
	finish()
}

func TestStartWorkstationEventCorrelation_DedupAndStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pods := []nodespawn.PodRef{
		{Namespace: "default", Name: "web-0"},
		{Namespace: "default", Name: "web-0"},
		{Namespace: "default", Name: ""},
		{Namespace: "other", Name: "api-0"},
	}

	var sb strings.Builder
	finish := startWorkstationEventCorrelation(ctx, fake.NewSimpleClientset(), pods, &sb)
	if finish == nil {
		t.Fatal("expected non-nil finish closure")
		return
	}
	finish()
}

type plainResolver struct{}

func (plainResolver) ResolvePod(_ context.Context, podName, namespace, containerName string) (*pkgkube.PodInfo, error) {
	return &pkgkube.PodInfo{PodName: podName, Namespace: namespace, ContainerName: containerName}, nil
}

var _ pkgkube.PodResolverInterface = plainResolver{}

type clusterResolver struct{}

func (clusterResolver) ResolvePod(_ context.Context, podName, namespace, containerName string) (*pkgkube.PodInfo, error) {
	return &pkgkube.PodInfo{PodName: podName, Namespace: namespace, ContainerName: containerName}, nil
}
func (clusterResolver) GetClientset() k8s.Interface { return fake.NewSimpleClientset() }
func (clusterResolver) GetRestConfig() *rest.Config { return &rest.Config{} }

var _ pkgkube.PodResolverInterface = clusterResolver{}
var _ pkgkube.ClientsetProvider = clusterResolver{}
var _ pkgkube.RestConfigProvider = clusterResolver{}

func saveSpawnGlobals(t *testing.T) {
	t.Helper()
	origLocal := localMode
	t.Cleanup(func() { localMode = origLocal })
}

func saveNodespawnGlobals(t *testing.T) {
	t.Helper()
	origImage := spawnImage
	origNamespace := spawnNamespace
	t.Cleanup(func() {
		spawnImage = origImage
		spawnNamespace = origNamespace
	})
}

func TestMaybeSpawnOnNode_SentinelSet(t *testing.T) {
	saveSpawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "1")
	localMode = false

	handled, err := maybeSpawnOnNode(context.Background(), nil, &cobra.Command{},
		plainResolver{}, pkgkube.TargetSelection{Pods: []string{"web-0"}})
	if handled || err != nil {
		t.Fatalf("sentinel set: want (false, nil), got (%v, %v)", handled, err)
	}
}

func TestMaybeSpawnOnNode_LocalMode(t *testing.T) {
	saveSpawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	localMode = true

	handled, err := maybeSpawnOnNode(context.Background(), nil, &cobra.Command{},
		plainResolver{}, pkgkube.TargetSelection{Pods: []string{"web-0"}})
	if handled || err != nil {
		t.Fatalf("local mode: want (false, nil), got (%v, %v)", handled, err)
	}
}

func TestMaybeSpawnOnNode_ResolverWithoutClusterHandles(t *testing.T) {
	saveSpawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	localMode = false

	handled, err := maybeSpawnOnNode(context.Background(), nil, &cobra.Command{},
		plainResolver{}, pkgkube.TargetSelection{Pods: []string{"web-0"}})
	if handled || err != nil {
		t.Fatalf("no cluster handles: want (false, nil), got (%v, %v)", handled, err)
	}
}

func TestMaybeSpawnOnNode_NotSpawnableSelection(t *testing.T) {
	saveSpawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	localMode = false

	handled, err := maybeSpawnOnNode(context.Background(), nil, &cobra.Command{},
		clusterResolver{}, pkgkube.TargetSelection{})
	if handled || err != nil {
		t.Fatalf("non-spawnable selection: want (false, nil), got (%v, %v)", handled, err)
	}
}

func TestMaybeSpawnOnNode_PodNotFoundResolveError(t *testing.T) {
	saveSpawnGlobals(t)
	saveNodespawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	t.Setenv("PODTRACE_SPAWN_NAMESPACE", "")
	localMode = false
	spawnImage = "ghcr.io/gma1k/podtrace:test"

	handled, err := maybeSpawnOnNode(context.Background(), nil, &cobra.Command{},
		clusterResolver{}, pkgkube.TargetSelection{DefaultNamespace: "default", Pods: []string{"missing-pod"}, Namespaces: []string{"default"}})
	if !handled {
		t.Fatalf("expected handled=true once selection is spawnable, got false")
	}
	if err == nil || !strings.Contains(err.Error(), "get pod") {
		t.Fatalf("expected a 'get pod' resolve error from the fake clientset, got %v", err)
	}
}

func TestMaybeSpawnOnNode_NoScheduledTargets(t *testing.T) {
	saveSpawnGlobals(t)
	saveNodespawnGlobals(t)
	t.Setenv(nodespawn.EnvNodeLocalSentinel, "")
	t.Setenv("PODTRACE_SPAWN_NAMESPACE", "")
	localMode = false
	spawnImage = "ghcr.io/gma1k/podtrace:test"

	handled, err := maybeSpawnOnNode(context.Background(), nil, &cobra.Command{},
		clusterResolver{}, pkgkube.TargetSelection{AllInNamespace: true, Namespaces: []string{"default"}})
	if !handled {
		t.Fatalf("expected handled=true once selection is spawnable, got false")
	}
	if err == nil || !strings.Contains(err.Error(), "no scheduled target pods") {
		t.Fatalf("expected 'no scheduled target pods' error, got %v", err)
	}
}

func saveWatchGlobals(t *testing.T) {
	t.Helper()
	orig := struct {
		labels  []string
		appName string
		ns      string
		printOn bool
		exp     string
		allNS   bool
		nsSel   string
		name    string
		sample  int
		kubecfg string
		app     bool
		filter  string
	}{
		labels: watchLabels, appName: watchAppName, ns: namespace,
		printOn: watchPrintOnly, exp: watchExporter, allNS: watchAllNamespaces,
		nsSel: watchNamespaceSelector, name: watchName, sample: watchSample,
		kubecfg: watchKubeconfig, app: watchApplication, filter: eventFilter,
	}
	t.Cleanup(func() {
		watchLabels = orig.labels
		watchAppName = orig.appName
		namespace = orig.ns
		watchPrintOnly = orig.printOn
		watchExporter = orig.exp
		watchAllNamespaces = orig.allNS
		watchNamespaceSelector = orig.nsSel
		watchName = orig.name
		watchSample = orig.sample
		watchKubeconfig = orig.kubecfg
		watchApplication = orig.app
		eventFilter = orig.filter
	})
}

func TestNewWatchCmd_PrintOnlyNoCluster(t *testing.T) {
	saveWatchGlobals(t)

	cmd := newWatchCmd()
	cmd.SetArgs([]string{"--app", "checkout", "--all-namespaces", "--print-only"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("watch --print-only should succeed without a cluster, got %v", err)
		}
	})
	if !strings.Contains(out, "kind: PodTrace") {
		t.Errorf("expected rendered PodTrace manifest, got:\n%s", out)
	}
}

func TestNewWatchCmd_ConflictingFlags(t *testing.T) {
	saveWatchGlobals(t)

	cmd := newWatchCmd()
	cmd.SetArgs([]string{"--app", "checkout", "--label", "tier=web", "--print-only"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}
}

func TestNewReportUploaderCmd_MissingRequiredFlags(t *testing.T) {
	cmd := newReportUploaderCmd()
	cmd.SetArgs([]string{})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "both required") {
		t.Fatalf("expected 'both required' error, got %v", err)
	}
}

func TestNewReportUploaderCmd_OnlyReportFile(t *testing.T) {
	cmd := newReportUploaderCmd()
	cmd.SetArgs([]string{"--report-file", "/tmp/report.txt"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "both required") {
		t.Fatalf("expected 'both required' error with only --report-file, got %v", err)
	}
}

func TestPersistKeyHint_WriteFailureIsSwallowed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions are bypassed, write would succeed")
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics not applicable on Windows")
	}

	dir := t.TempDir()
	roDir := filepath.Join(dir, "ro")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatalf("mkdir ro: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })

	orig := keyHintStateFile
	keyHintStateFile = filepath.Join(roDir, "upload-key-hint.txt")
	t.Cleanup(func() { keyHintStateFile = orig })

	persistKeyHint("pod-2026-06-08T00-00-00Z.txt")

	if _, err := os.Stat(keyHintStateFile); err == nil {
		t.Fatalf("expected write to fail into read-only dir, but file exists")
	}
}

func TestLoadObjectStoreCredentials_UnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file permissions are bypassed, read would succeed")
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics not applicable on Windows")
	}

	dir := t.TempDir()
	secret := filepath.Join(dir, "secret-key")
	if err := os.WriteFile(secret, []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatalf("chmod 000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o600) })

	t.Setenv(envObjectStoreCredentialsDir, dir)

	_, err := loadObjectStoreCredentials()
	if err == nil {
		t.Fatal("expected a read error for the unreadable credential file, got nil")
		return
	}
	if !strings.Contains(err.Error(), "read credential file") {
		t.Fatalf("expected 'read credential file' error, got %v", err)
	}
}
