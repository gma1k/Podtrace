package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/sysfs"
	"github.com/gma1k/podtrace/pkg/tracer"
)

func TestReconcile_ListPodTraceError(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.PodTraceList); ok {
					return errors.New("apiserver down")
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()

	r := &AgentReconciler{Client: c, NodeName: "n", Router: NewRouter(nil), exporterCache: map[CRKey]cachedExporter{}}
	_, err := r.Reconcile(context.Background(), ctrl.Request{})
	if err == nil || !strings.Contains(err.Error(), "list PodTrace") {
		t.Fatalf("expected 'list PodTrace' error, got %v", err)
	}
}

func TestReconcile_ListPodsError(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.PodList); ok {
					return errors.New("apiserver down")
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()

	r := &AgentReconciler{Client: c, NodeName: "n", Router: NewRouter(nil), exporterCache: map[CRKey]cachedExporter{}}
	_, err := r.Reconcile(context.Background(), ctrl.Request{})
	if err == nil || !strings.Contains(err.Error(), "list Pods") {
		t.Fatalf("expected 'list Pods' error, got %v", err)
	}
}

func TestReconcile_CategoryGateErrorIsNonFatal(t *testing.T) {
	const node, sysNS, ns = "node-1", "podtrace-system", "default"
	uid := types.UID("uid-cat")

	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: uid},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Filters:  []podtracev1alpha1.EventFilter{podtracev1alpha1.FilterDNS},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(pt, pod, makeBundleCM(sysNS, uid, "10")).
		Build()

	gateCalls := 0
	r := &AgentReconciler{
		Client:          c,
		NodeName:        node,
		SystemNamespace: sysNS,
		Router:          NewRouter(nil),
		Metrics:         NewMetrics(),
		TargetsCh:       make(chan tracer.TargetSet, 4),
		ExporterBuilder: func(_ *BundlePayload, _ CRKey) (tracer.Exporter, error) { return &fakeExporter{}, nil },
		CgroupResolver:  func(pods []*corev1.Pod) (map[uint64]struct{}, error) { return map[uint64]struct{}{7: {}}, nil },
		CategoryGate: func(categories []string) error {
			gateCalls++
			return errors.New("backend rejected category set")
		},
		exporterCache: map[CRKey]cachedExporter{},
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: "pt"},
	}); err != nil {
		t.Fatalf("Reconcile must swallow CategoryGate errors, got: %v", err)
	}
	if gateCalls != 1 {
		t.Errorf("CategoryGate calls = %d, want 1", gateCalls)
	}
}

func TestEnqueueAllPodTraces_ListErrorReturnsNil(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errors.New("list failed")
			},
		}).Build()

	r := &AgentReconciler{Client: c, NodeName: "n"}
	if reqs := r.enqueueAllPodTraces(context.Background(), &corev1.Pod{}); reqs != nil {
		t.Errorf("expected nil requests on list error, got %v", reqs)
	}
}

func TestFilterToEventTypes_USDT(t *testing.T) {
	got := filterToEventTypes(podtracev1alpha1.FilterUSDT)
	if len(got) != 1 || got[0] != events.EventUSDT {
		t.Errorf("FilterUSDT mapping = %v, want [EventUSDT]", got)
	}
}

func TestMainPIDFromCgroupProcs_OutsideBaseReturnsZero(t *testing.T) {
	if got := mainPIDFromCgroupProcs("/tmp/definitely-not-under-cgroup-base"); got != 0 {
		t.Errorf("mainPIDFromCgroupProcs outside base = %d, want 0", got)
	}
}

func TestMainPIDFromCgroupProcs_ReadsLowestPID(t *testing.T) {
	base := t.TempDir()
	saved := config.CgroupBasePath
	config.SetCgroupBasePath(base)
	sysfs.ResetForTesting()
	t.Cleanup(func() {
		config.SetCgroupBasePath(saved)
		sysfs.ResetForTesting()
	})

	groupDir := filepath.Join(base, "mygroup")
	if err := os.MkdirAll(groupDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(groupDir, "cgroup.procs"), []byte("9\n3\n7\nnotanumber\n0\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.procs: %v", err)
	}

	withProcessStartTimes(t, nil)
	if got := mainPIDFromCgroupProcs(groupDir); got != 3 {
		t.Errorf("mainPIDFromCgroupProcs = %d, want 3 (lowest valid PID)", got)
	}
}

func TestMainPIDFromCgroupProcs_UnreadableProcsReturnsZero(t *testing.T) {
	base := t.TempDir()
	saved := config.CgroupBasePath
	config.SetCgroupBasePath(base)
	sysfs.ResetForTesting()
	t.Cleanup(func() {
		config.SetCgroupBasePath(saved)
		sysfs.ResetForTesting()
	})

	groupDir := filepath.Join(base, "empty")
	if err := os.MkdirAll(groupDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if got := mainPIDFromCgroupProcs(groupDir); got != 0 {
		t.Errorf("missing cgroup.procs → %d, want 0", got)
	}
}

func TestResolveCgroupIDs_MapsScannedEntries(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "kubepods.slice")
	uidUnder := strings.ReplaceAll(testPodUID, "-", "_")
	podSlice := filepath.Join(root,
		"kubepods-besteffort.slice",
		"kubepods-besteffort-pod"+uidUnder+".slice",
	)
	if err := os.MkdirAll(filepath.Join(podSlice, "cri-containerd-abc123.scope"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	withKubepodsRoot(t, root)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns", UID: types.UID(testPodUID)},
		Status:     corev1.PodStatus{QOSClass: corev1.PodQOSBestEffort},
	}
	ids, err := resolveCgroupIDs([]*corev1.Pod{pod})
	if err != nil {
		t.Fatalf("resolveCgroupIDs: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("resolved %d cgroup IDs, want 2 (pod + 1 container)", len(ids))
	}
}

func withKubepodsRoot(t *testing.T, root string) {
	t.Helper()
	saved := kubepodsRootOverride
	kubepodsRootOverride = root
	t.Cleanup(func() { kubepodsRootOverride = saved })
}

func TestScanPodCgroups_WalksPodAndContainerCgroups(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "kubepods.slice")
	uidUnder := strings.ReplaceAll(testPodUID, "-", "_")
	podSlice := filepath.Join(root,
		"kubepods-besteffort.slice",
		"kubepods-besteffort-pod"+uidUnder+".slice",
	)
	if err := os.MkdirAll(filepath.Join(podSlice, "cri-containerd-abc123.scope"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(podSlice, "cgroup.procs"), []byte("1\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.procs: %v", err)
	}
	withKubepodsRoot(t, root)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns", UID: types.UID(testPodUID)},
		Status: corev1.PodStatus{
			QOSClass: corev1.PodQOSBestEffort,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ContainerID: "containerd://abc123"},
			},
		},
	}

	entries := scanPodCgroups([]*corev1.Pod{pod})
	if len(entries) != 2 {
		t.Fatalf("scanPodCgroups returned %d entries, want 2 (pod + 1 container)", len(entries))
	}

	var sawPodLevel, sawContainer bool
	for _, e := range entries {
		if e.Pod != pod {
			t.Errorf("entry pod pointer mismatch: %+v", e)
		}
		if e.ContainerName == "" && e.CgroupPath == podSlice {
			sawPodLevel = true
		}
		if e.ContainerName == "app" {
			sawContainer = true
		}
	}
	if !sawPodLevel {
		t.Error("missing pod-level entry")
	}
	if !sawContainer {
		t.Error("container entry did not resolve its name from pod.status")
	}
}

func TestScanPodCgroups_NoRootReturnsNil(t *testing.T) {
	withKubepodsRoot(t, filepath.Join(t.TempDir(), "does-not-exist"))
	if got := scanPodCgroups([]*corev1.Pod{{}}); got != nil {
		t.Errorf("scanPodCgroups with no root = %v, want nil", got)
	}
}

func TestFallbackLegacyTarget_AppendsMatchingPod(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "kubepods.slice")

	makeSlice := func(uid string) string {
		uidUnder := strings.ReplaceAll(uid, "-", "_")
		p := filepath.Join(root,
			"kubepods-besteffort.slice",
			"kubepods-besteffort-pod"+uidUnder+".slice",
		)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		return p
	}

	const targetUID = "aaaa1111-bbbb-2222-cccc-333344445555"
	const decoyUID = "dddd6666-eeee-7777-ffff-888899990000"
	targetSlice := makeSlice(targetUID)
	makeSlice(decoyUID)
	withKubepodsRoot(t, root)

	targetID, err := cgroupIDFromPath(targetSlice)
	if err != nil {
		t.Fatalf("cgroupIDFromPath: %v", err)
	}

	noDirPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "nodir", Namespace: "ns", UID: "99999999-0000-0000-0000-000000000000"}}
	decoyPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "decoy", Namespace: "ns", UID: types.UID(decoyUID)},
		Status: corev1.PodStatus{QOSClass: corev1.PodQOSBestEffort}}
	targetPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "target", Namespace: "ns", UID: types.UID(targetUID)},
		Status: corev1.PodStatus{QOSClass: corev1.PodQOSBestEffort, PodIP: "10.1.2.3"}}

	noDirPod.Status.QOSClass = corev1.PodQOSBestEffort

	out := tracer.TargetSet{}
	fallbackLegacyTarget(&out, []*corev1.Pod{noDirPod, decoyPod, targetPod}, targetID)

	if len(out) != 1 {
		t.Fatalf("fallbackLegacyTarget appended %d targets, want 1: %+v", len(out), out)
	}
	if out[0].PodName != "target" {
		t.Errorf("appended pod = %q, want target", out[0].PodName)
	}
	if out[0].CgroupPath != targetSlice {
		t.Errorf("CgroupPath = %q, want %q", out[0].CgroupPath, targetSlice)
	}
	if out[0].PodIP != "10.1.2.3" {
		t.Errorf("PodIP = %q, want 10.1.2.3", out[0].PodIP)
	}
}
