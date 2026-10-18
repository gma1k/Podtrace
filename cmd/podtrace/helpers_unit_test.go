package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	pkgkube "github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsObjectStoreURI(t *testing.T) {
	cases := []struct {
		spec string
		want bool
	}{
		{"s3://bucket/key", true},
		{"gs://bucket/key", true},
		{"azblob://container/blob", true},
		{"configmap/default/report", false},
		{"secret/ns/name", false},
		{"", false},
		{"://", true},
	}
	for _, c := range cases {
		if got := isObjectStoreURI(c.spec); got != c.want {
			t.Errorf("isObjectStoreURI(%q) = %v, want %v", c.spec, got, c.want)
		}
	}
}

// writeResolvedLocation targets a fixed const path (/var/run/podtrace/...).
// We can't redirect it without editing the source, so exercise the function
// directly: if the target directory exists and is writable the URI must round
// -trip; otherwise the helper must surface the write error rather than panic.
func TestWriteResolvedLocation(t *testing.T) {
	const uri = "s3://bucket/podtrace/report.txt"
	err := writeResolvedLocation(uri)
	if err != nil {
		t.Logf("writeResolvedLocation returned (expected when %s dir is absent): %v",
			filepath.Dir(reportLocationFile), err)
		return
	}
	got, readErr := os.ReadFile(reportLocationFile)
	if readErr != nil {
		t.Fatalf("read back resolved location: %v", readErr)
	}
	if string(got) != uri {
		t.Fatalf("resolved location = %q, want %q", string(got), uri)
	}
}

func TestSelectionIsSpawnable(t *testing.T) {
	cases := []struct {
		name string
		sel  pkgkube.TargetSelection
		want bool
	}{
		{"empty", pkgkube.TargetSelection{}, false},
		{"pods", pkgkube.TargetSelection{Pods: []string{"web-0"}}, true},
		{"selector", pkgkube.TargetSelection{PodSelector: "app=api"}, true},
		{"all-in-namespace", pkgkube.TargetSelection{AllInNamespace: true}, true},
	}
	for _, c := range cases {
		if got := selectionIsSpawnable(c.sel); got != c.want {
			t.Errorf("%s: selectionIsSpawnable = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestErrorsAs_WrappedExitError(t *testing.T) {
	base := &nodespawn.ExitError{Code: 7, Node: "node-a"}
	wrapped := fmt.Errorf("nodespawn run failed: %w", base)

	var target *nodespawn.ExitError
	if !errorsAs(wrapped, &target) {
		t.Fatalf("errorsAs returned false for a wrapped *ExitError")
	}
	if target == nil || target.Code != 7 || target.Node != "node-a" {
		t.Fatalf("errorsAs did not assign the unwrapped ExitError: %#v", target)
	}
}

func TestErrorsAs_PlainError(t *testing.T) {
	var target *nodespawn.ExitError
	if errorsAs(fmt.Errorf("just a plain error"), &target) {
		t.Fatalf("errorsAs returned true for a non-ExitError chain")
	}
	if target != nil {
		t.Fatalf("target should remain nil, got %#v", target)
	}
}

func TestNewChildArgsBuilder(t *testing.T) {
	cmd := &cobra.Command{Use: "podtrace"}
	cmd.Flags().String("filter", "", "event filter")
	cmd.Flags().String("output", "", "output format")
	cmd.Flags().String("image", "", "spawn image")
	cmd.Flags().Bool("metrics", false, "expose metrics")

	if err := cmd.Flags().Set("filter", "dns,net"); err != nil {
		t.Fatalf("set filter: %v", err)
	}
	if err := cmd.Flags().Set("image", "ghcr.io/example/podtrace:dev"); err != nil {
		t.Fatalf("set image: %v", err)
	}
	if err := cmd.Flags().Set("metrics", "true"); err != nil {
		t.Fatalf("set metrics: %v", err)
	}

	pods := []nodespawn.PodRef{
		{Namespace: "default", Name: "web-0", ContainerID: "cid-1", ContainerName: "app"},
		{Namespace: "default", Name: "web-1", ContainerID: "cid-2", ContainerName: "app"},
		{Namespace: "default", Name: "web-2", ContainerName: "app"},
	}

	t.Run("passMetrics=false strips metrics and control flags", func(t *testing.T) {
		build := newChildArgsBuilder(cmd, false, nil)
		args := build("node-a", pods)
		joined := strings.Join(args, " ")

		if !contains(args, "--filter=dns,net") {
			t.Errorf("expected changed --filter flag in args, got %v", args)
		}
		if strings.Contains(joined, "--image=") {
			t.Errorf("spawn-control flag --image must be stripped, got %v", args)
		}
		if strings.Contains(joined, "--metrics") {
			t.Errorf("--metrics must be stripped when passMetrics=false, got %v", args)
		}
		if !contains(args, "--preresolved-pod=default/web-0/cid-1/app") {
			t.Errorf("expected preresolved entry for web-0, got %v", args)
		}
		if !contains(args, "--preresolved-pod=default/web-1/cid-2/app") {
			t.Errorf("expected preresolved entry for web-1, got %v", args)
		}
		if strings.Contains(joined, "web-2") {
			t.Errorf("pod without ContainerID must be skipped, got %v", args)
		}
	})

	t.Run("passMetrics=true keeps changed metrics flag", func(t *testing.T) {
		build := newChildArgsBuilder(cmd, true, nil)
		args := build("node-a", pods)
		if !contains(args, "--metrics=true") {
			t.Errorf("expected --metrics=true when passMetrics=true, got %v", args)
		}
	})
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func TestMarshalSessionYAML(t *testing.T) {
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-session",
			Namespace: "default",
		},
	}
	out, err := marshalSessionYAML(s)
	if err != nil {
		t.Fatalf("marshalSessionYAML: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, "apiVersion:") {
		t.Errorf("expected apiVersion in output, got:\n%s", text)
	}
	if !strings.Contains(text, "kind: PodTraceSession") {
		t.Errorf("expected kind: PodTraceSession in output, got:\n%s", text)
	}
	if s.Kind != "PodTraceSession" {
		t.Errorf("expected Kind stamped on object, got %q", s.Kind)
	}
	if s.APIVersion != podtracev1alpha1.GroupVersion.String() {
		t.Errorf("expected APIVersion stamped, got %q", s.APIVersion)
	}
}

func TestPrintSessionYAML(t *testing.T) {
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"},
	}

	out := captureStdout(t, func() {
		if err := printSessionYAML(s); err != nil {
			t.Fatalf("printSessionYAML: %v", err)
		}
	})
	if !strings.Contains(out, "kind: PodTraceSession") {
		t.Errorf("printSessionYAML output missing kind, got:\n%s", out)
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns what
// was written. Restores the original on completion.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, rerr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	return string(buf)
}

func TestWatchOptionsFromFlags(t *testing.T) {
	save := struct {
		labels    []string
		appName   string
		allNS     bool
		nsSel     string
		ns        string
		exporter  string
		name      string
		filter    string
		sample    int
		kubecfg   string
		printOnly bool
		app       bool
	}{
		labels:    watchLabels,
		appName:   watchAppName,
		allNS:     watchAllNamespaces,
		nsSel:     watchNamespaceSelector,
		ns:        namespace,
		exporter:  watchExporter,
		name:      watchName,
		filter:    eventFilter,
		sample:    watchSample,
		kubecfg:   watchKubeconfig,
		printOnly: watchPrintOnly,
		app:       watchApplication,
	}
	t.Cleanup(func() {
		watchLabels = save.labels
		watchAppName = save.appName
		watchAllNamespaces = save.allNS
		watchNamespaceSelector = save.nsSel
		namespace = save.ns
		watchExporter = save.exporter
		watchName = save.name
		eventFilter = save.filter
		watchSample = save.sample
		watchKubeconfig = save.kubecfg
		watchPrintOnly = save.printOnly
		watchApplication = save.app
	})

	watchLabels = []string{"  app=api  ", "", "   ", "tier=web"}
	watchAppName = "  checkout  "
	watchAllNamespaces = true
	watchNamespaceSelector = "  team=payments  "
	namespace = "production"
	watchExporter = "  otlp-default  "
	watchName = "  my-trace  "
	eventFilter = "dns,net"
	watchSample = 42
	watchKubeconfig = "/tmp/kubeconfig"
	watchPrintOnly = true
	watchApplication = true

	opts := watchOptionsFromFlags()

	wantLabels := []string{"app=api", "tier=web"}
	gotLabels := append([]string(nil), opts.Labels...)
	sort.Strings(gotLabels)
	sort.Strings(wantLabels)
	if strings.Join(gotLabels, ",") != strings.Join(wantLabels, ",") {
		t.Errorf("Labels = %v, want %v (trimmed, empties dropped)", opts.Labels, wantLabels)
	}
	if opts.AppName != "checkout" {
		t.Errorf("AppName = %q, want %q", opts.AppName, "checkout")
	}
	if !opts.AllNamespaces {
		t.Errorf("AllNamespaces = false, want true")
	}
	if opts.NamespaceSelector != "team=payments" {
		t.Errorf("NamespaceSelector = %q, want %q", opts.NamespaceSelector, "team=payments")
	}
	if opts.Namespace != "production" {
		t.Errorf("Namespace = %q, want %q", opts.Namespace, "production")
	}
	if opts.Exporter != "otlp-default" {
		t.Errorf("Exporter = %q, want %q", opts.Exporter, "otlp-default")
	}
	if opts.Name != "my-trace" {
		t.Errorf("Name = %q, want %q", opts.Name, "my-trace")
	}
	if opts.Filter != "dns,net" {
		t.Errorf("Filter = %q, want %q", opts.Filter, "dns,net")
	}
	if opts.SamplePercent != 42 {
		t.Errorf("SamplePercent = %d, want 42", opts.SamplePercent)
	}
	if opts.Kubeconfig != "/tmp/kubeconfig" {
		t.Errorf("Kubeconfig = %q, want %q", opts.Kubeconfig, "/tmp/kubeconfig")
	}
	if !opts.PrintOnly {
		t.Errorf("PrintOnly = false, want true")
	}
	if !opts.Application {
		t.Errorf("Application = false, want true")
	}
}
