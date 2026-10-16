package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/kubernetes"
)

// ---------------------------------------------------------------------------
// main.go: attachTracerToCgroups
//
// The mockTracer/fakeTracer fakes do NOT implement the optional
// AttachToCgroups(plural) interface, so these tests exercise the
// single-path fallback: the empty-slice error guard and the delegation
// to AttachToCgroup(paths[0]) (success and propagated-error).
// ---------------------------------------------------------------------------

func TestAttachTracerToCgroups_NoPaths(t *testing.T) {
	tr := &mockTracer{}
	if err := attachTracerToCgroups(tr, nil); err == nil {
		t.Fatal("expected error when no cgroup paths are provided")
	}
}

func TestAttachTracerToCgroups_DelegatesFirstPath(t *testing.T) {
	var got string
	tr := &mockTracer{
		attachToCgroupFunc: func(p string) error {
			got = p
			return nil
		},
	}
	if err := attachTracerToCgroups(tr, []string{"/sys/fs/cgroup/a", "/sys/fs/cgroup/b"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/sys/fs/cgroup/a" {
		t.Errorf("delegated path = %q, want first path %q", got, "/sys/fs/cgroup/a")
	}
}

func TestAttachTracerToCgroups_PropagatesError(t *testing.T) {
	wantErr := errors.New("attach boom")
	tr := &mockTracer{
		attachToCgroupFunc: func(string) error { return wantErr },
	}
	if err := attachTracerToCgroups(tr, []string{"/p"}); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

// ---------------------------------------------------------------------------
// main.go: setTracerContainerIDs
// ---------------------------------------------------------------------------

func TestSetTracerContainerIDs_NoIDs(t *testing.T) {
	tr := &mockTracer{}
	if err := setTracerContainerIDs(tr, nil); err == nil {
		t.Fatal("expected error when no container IDs are provided")
	}
}

func TestSetTracerContainerIDs_DelegatesFirstID(t *testing.T) {
	var got string
	tr := &mockTracer{
		setContainerIDFunc: func(id string) error {
			got = id
			return nil
		},
	}
	if err := setTracerContainerIDs(tr, []string{"cid-1", "cid-2"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "cid-1" {
		t.Errorf("delegated id = %q, want first id %q", got, "cid-1")
	}
}

func TestSetTracerContainerIDs_PropagatesError(t *testing.T) {
	wantErr := errors.New("setid boom")
	tr := &mockTracer{
		setContainerIDFunc: func(string) error { return wantErr },
	}
	if err := setTracerContainerIDs(tr, []string{"x"}); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

// ---------------------------------------------------------------------------
// main.go: attachSourcePod
// ---------------------------------------------------------------------------

func TestAttachSourcePod_StampsResolvedIdentity(t *testing.T) {
	e := &events.Event{}
	resolve := func(*events.Event) *kubernetes.PodInfo {
		return &kubernetes.PodInfo{
			PodName:       "src-pod",
			Namespace:     "src-ns",
			ContainerName: "src-container",
		}
	}
	attachSourcePod(e, resolve)
	if e.K8s == nil {
		t.Fatal("expected K8s metadata to be stamped onto the event")
	}
	if e.K8s.PodName != "src-pod" || e.K8s.Namespace != "src-ns" || e.K8s.ContainerName != "src-container" {
		t.Errorf("stamped metadata = %+v, want src-pod/src-ns/src-container", e.K8s)
	}
}

func TestAttachSourcePod_NilEventIsNoOp(t *testing.T) {
	called := false
	attachSourcePod(nil, func(*events.Event) *kubernetes.PodInfo {
		called = true
		return nil
	})
	if called {
		t.Error("resolve must not be called for a nil event")
	}
}

func TestAttachSourcePod_NilResolveIsNoOp(t *testing.T) {
	e := &events.Event{}
	attachSourcePod(e, nil)
	if e.K8s != nil {
		t.Errorf("expected K8s to stay nil with a nil resolver, got %+v", e.K8s)
	}
}

func TestAttachSourcePod_AlreadyStampedIsNoOp(t *testing.T) {
	e := &events.Event{K8s: &events.K8sMetadata{PodName: "existing"}}
	called := false
	attachSourcePod(e, func(*events.Event) *kubernetes.PodInfo {
		called = true
		return &kubernetes.PodInfo{PodName: "other"}
	})
	if called {
		t.Error("resolve must not be called when K8s metadata is already present")
	}
	if e.K8s.PodName != "existing" {
		t.Errorf("existing metadata overwritten: %+v", e.K8s)
	}
}

func TestAttachSourcePod_EmptyResolvedPodNameIsNoOp(t *testing.T) {
	e := &events.Event{}
	attachSourcePod(e, func(*events.Event) *kubernetes.PodInfo {
		return &kubernetes.PodInfo{PodName: ""} // empty PodName -> not stamped
	})
	if e.K8s != nil {
		t.Errorf("expected no stamp for empty PodName, got %+v", e.K8s)
	}
}

func TestAttachSourcePod_NilResolvedInfoIsNoOp(t *testing.T) {
	e := &events.Event{}
	attachSourcePod(e, func(*events.Event) *kubernetes.PodInfo { return nil })
	if e.K8s != nil {
		t.Errorf("expected no stamp for nil resolved info, got %+v", e.K8s)
	}
}

// ---------------------------------------------------------------------------
// session_sink.go: writeSummaryFile error branch
//
// hostfs.WriteFile validates the path (must be absolute, no ".." segment),
// so a relative path drives the error return without needing root or a
// real privileged location.
// ---------------------------------------------------------------------------

func TestWriteSummaryFile_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.json")
	if err := writeSummaryFile(path, SessionSummary{TotalEvents: 7, Node: "n1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("summary file not written: %v", err)
	}
	if len(raw) == 0 {
		t.Error("summary file is empty")
	}
}

func TestWriteSummaryFile_InvalidPathError(t *testing.T) {
	if err := writeSummaryFile("relative/summary.json", SessionSummary{}); err == nil {
		t.Fatal("expected error for a non-absolute summary path")
	}
}

// ---------------------------------------------------------------------------
// session_sink.go: uploadReport reachable error branch (parse failure)
//
// A spec without "://" and not in kind/namespace/name form fails in
// parseReportToSpec, before any in-cluster client is constructed.
// ---------------------------------------------------------------------------

func TestUploadReport_ParseError(t *testing.T) {
	err := uploadReport(context.Background(), "not-a-valid-spec", "report body")
	if err == nil {
		t.Fatal("expected parse error for malformed report-to spec")
	}
}

// ---------------------------------------------------------------------------
// session_sink.go: upsertReportConfigMap / upsertReportSecret error branches
//
// Existing tests cover create + update. These force the create call to
// fail with a non-AlreadyExists error (covering the wrapped-create-error
// return) and the AlreadyExists-then-Get-fails path.
// ---------------------------------------------------------------------------

func TestUpsertReportConfigMap_CreateErrorPropagates(t *testing.T) {
	client := fake.NewSimpleClientset()
	wantErr := errors.New("forbidden")
	client.PrependReactor("create", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, wantErr
	})
	err := upsertReportConfigMap(context.Background(), client, "ns", "rpt", "report.txt", "body")
	if err == nil {
		t.Fatal("expected error when ConfigMap create fails")
	}
}

func TestUpsertReportConfigMap_GetErrorAfterAlreadyExists(t *testing.T) {
	client := fake.NewSimpleClientset()
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	client.PrependReactor("create", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(gvr.GroupResource(), "rpt")
	})
	client.PrependReactor("get", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("get failed")
	})
	err := upsertReportConfigMap(context.Background(), client, "ns", "rpt", "report.txt", "body")
	if err == nil {
		t.Fatal("expected error when Get after AlreadyExists fails")
	}
}

func TestUpsertReportSecret_CreateErrorPropagates(t *testing.T) {
	client := fake.NewSimpleClientset()
	wantErr := errors.New("forbidden")
	client.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, wantErr
	})
	err := upsertReportSecret(context.Background(), client, "ns", "rpt", "report.txt", "body")
	if err == nil {
		t.Fatal("expected error when Secret create fails")
	}
}

func TestUpsertReportSecret_UpdateErrorPropagates(t *testing.T) {
	existing := &corev1.Secret{}
	existing.Name = "rpt"
	existing.Namespace = "ns"
	client := fake.NewSimpleClientset(existing)
	client.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("update failed")
	})
	// Create will return AlreadyExists (object seeded), Get succeeds, Update fails.
	err := upsertReportSecret(context.Background(), client, "ns", "rpt", "report.txt", "body")
	if err == nil {
		t.Fatal("expected error when Secret update fails")
	}
}

func TestUpsertReportConfigMap_RetriesOnConflict(t *testing.T) {
	existing := &corev1.ConfigMap{}
	existing.Name = "rpt"
	existing.Namespace = "ns"
	existing.Data = map[string]string{"report-other.txt": "keep"}
	client := fake.NewSimpleClientset(existing)

	updates := 0
	client.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		if updates == 1 {
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Resource: "configmaps"}, "rpt", errors.New("stale revision"))
		}
		return false, nil, nil // let the default tracker apply subsequent updates
	})

	if err := upsertReportConfigMap(context.Background(), client, "ns", "rpt", "report-node-a.txt", "A"); err != nil {
		t.Fatalf("expected retry to succeed after conflict, got %v", err)
	}
	if updates < 2 {
		t.Errorf("expected a retry after the 409, updates=%d", updates)
	}
	cm, err := client.CoreV1().ConfigMaps("ns").Get(context.Background(), "rpt", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cm.Data["report-node-a.txt"] != "A" {
		t.Errorf("this node's key not written after retry: %+v", cm.Data)
	}
	if cm.Data["report-other.txt"] != "keep" {
		t.Errorf("sibling node's key lost during retry: %+v", cm.Data)
	}
}

// ---------------------------------------------------------------------------
// report_uploader.go: writeResolvedLocation error branch
//
// reportLocationFile is the privileged /var/run/podtrace path. In a
// non-root unit-test environment the underlying write fails, which is
// exactly the error branch we want to cover. We assert an error is
// returned without asserting on its specific cause (so the test stays
// green if it ever happens to be runnable as root, where the success
// branch is already exercised elsewhere is not the case here).
// ---------------------------------------------------------------------------

func TestWriteResolvedLocation_PrivilegedPathErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: privileged /var/run/podtrace path may be writable")
	}
	if err := writeResolvedLocation("s3://bucket/key"); err == nil {
		t.Fatal("expected error writing to privileged report-location path as non-root")
	}
}

// ---------------------------------------------------------------------------
// report_uploader.go: uploadIfPresent object-store branch
//
// A present report file plus an object-store-shaped spec routes through
// uploadToObjectStore. An unsupported scheme makes objectstore.New fail
// deterministically (no network), covering that branch.
// ---------------------------------------------------------------------------

func TestUploadIfPresent_ObjectStoreSchemeError(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.txt")
	if err := os.WriteFile(reportPath, []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envObjectStoreCredentialsDir, "")

	err := uploadIfPresent(context.Background(), reportUploaderOptions{
		ReportFile:   reportPath,
		ReportToSpec: "unsupported://bucket/key",
	})
	if err == nil {
		t.Fatal("expected error from unsupported object-store scheme")
	}
}

// ---------------------------------------------------------------------------
// schedule.go: newScheduleTriggerCmd RunE early validation branch
//
// trigger requires a positional schedule-name (ExactArgs(1)) and a
// required --namespace flag. Omitting the namespace makes cobra's
// required-flag validation fail before any client is built.
// ---------------------------------------------------------------------------

func TestNewScheduleTriggerCmd_MissingNamespaceErrors(t *testing.T) {
	cmd := newScheduleTriggerCmd()
	cmd.SetArgs([]string{"my-schedule"}) // no --namespace
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when required --namespace is missing")
	}
}

func TestNewScheduleTriggerCmd_MissingArgErrors(t *testing.T) {
	cmd := newScheduleTriggerCmd()
	cmd.SetArgs([]string{"--namespace", "ns"}) // no positional schedule-name
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when positional schedule-name is missing")
	}
}

func TestUpsertReportSecret_ForbiddenUpdateReplacesAndKeepsLabels(t *testing.T) {
	existing := &corev1.Secret{}
	existing.Name = "staging"
	existing.Namespace = "podtrace-system"
	existing.UID = "uid-1"
	existing.Labels = map[string]string{"podtrace.io/session": "s"}
	client := fake.NewSimpleClientset(existing)
	client.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "staging", errors.New("no update verb"))
	})

	if err := upsertReportSecret(context.Background(), client, "podtrace-system", "staging", "report-n1.txt", "body"); err != nil {
		t.Fatalf("a forbidden update must fall back to delete and create: %v", err)
	}
	got, err := client.CoreV1().Secrets("podtrace-system").Get(context.Background(), "staging", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data["report-n1.txt"]) != "body" {
		t.Errorf("report data = %q, want body", got.Data["report-n1.txt"])
	}
	if got.Labels["podtrace.io/session"] != "s" {
		t.Errorf("the replacement must keep the operator's labels, got %v", got.Labels)
	}
}

func forbiddenUpdateClient() *fake.Clientset {
	existing := &corev1.Secret{}
	existing.Name = "staging"
	existing.Namespace = "podtrace-system"
	client := fake.NewSimpleClientset(existing)
	client.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "staging", errors.New("no update verb"))
	})
	return client
}

func TestUpsertReportSecret_ReplaceDeleteErrorPropagates(t *testing.T) {
	client := forbiddenUpdateClient()
	client.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("delete failed")
	})
	if err := upsertReportSecret(context.Background(), client, "podtrace-system", "staging", "report-n1.txt", "body"); err == nil {
		t.Fatal("a failed delete during the replace must be surfaced")
	}
}

func TestUpsertReportSecret_ReplaceRaceRetries(t *testing.T) {
	client := forbiddenUpdateClient()
	creates := 0
	client.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		creates++
		if creates == 1 {
			return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, "staging")
		}
		return false, nil, nil
	})
	if err := upsertReportSecret(context.Background(), client, "podtrace-system", "staging", "report-n1.txt", "body"); err != nil {
		t.Fatalf("a replacement racing another writer must be retried: %v", err)
	}
	if creates < 2 {
		t.Errorf("creates = %d, want a retry after the race", creates)
	}
}
