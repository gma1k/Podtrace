package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/events"
	podtraceac "github.com/gma1k/podtrace/pkg/client/applyconfiguration/api/v1alpha1"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
	"github.com/gma1k/podtrace/pkg/tracer"
)

func TestDefaultOptions_NonEmptyAddrs(t *testing.T) {
	o := DefaultOptions()
	if o.MetricsAddr == "" {
		t.Error("MetricsAddr should be defaulted")
	}
	if o.HealthAddr == "" {
		t.Error("HealthAddr should be defaulted")
	}
	if o.NodeName != "" || o.SystemNamespace != "" {
		t.Errorf("DefaultOptions must NOT default NodeName/SystemNamespace, got %+v", o)
	}
}

func TestOptionsValidate(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		ok   bool
	}{
		{"missing both", Options{}, false},
		{"missing namespace", Options{NodeName: "n"}, false},
		{"missing node", Options{SystemNamespace: "ns"}, false},
		{"complete", Options{NodeName: "n", SystemNamespace: "ns"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.opts.validate()
			if (err == nil) != c.ok {
				t.Errorf("opts=%+v err=%v ok=%v", c.opts, err, c.ok)
			}
		})
	}
}

func TestRun_RejectsInvalidOptions(t *testing.T) {
	if err := Run(context.Background(), Options{}); err == nil {
		t.Fatal("Run should refuse zero Options")
	}
	if err := Run(context.Background(), Options{NodeName: "n"}); err == nil {
		t.Fatal("Run should refuse missing SystemNamespace")
	}
}

func TestNewAgentScheme_RegistersBothAPIs(t *testing.T) {
	s, err := newAgentScheme()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ObjectKinds(&corev1.Pod{}); err != nil {
		t.Errorf("corev1.Pod not registered: %v", err)
	}
	if _, _, err := s.ObjectKinds(&podtracev1alpha1.PodTrace{}); err != nil {
		t.Errorf("podtracev1alpha1.PodTrace not registered: %v", err)
	}
}

type fakeBackend struct{ name string }

func (b *fakeBackend) AttachToCgroup(_ string) error                         { return nil }
func (b *fakeBackend) SetCgroups(_ []tracer.CgroupTarget) error              { return nil }
func (b *fakeBackend) SetContainerID(_ string) error                         { return nil }
func (b *fakeBackend) Start(_ context.Context, _ chan<- *events.Event) error { return nil }
func (b *fakeBackend) Stop() error                                           { return nil }

func TestBuildBackend_NilFactoryReturnsNoop(t *testing.T) {
	got, err := buildBackend(Options{}, logr.Discard())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got.(*NoopBackend); !ok {
		t.Errorf("expected *NoopBackend, got %T", got)
	}
}

func TestBuildBackend_FactorySuccess(t *testing.T) {
	want := &fakeBackend{name: "fake"}
	got, err := buildBackend(Options{
		BackendFactory: func() (tracer.TracerBackend, error) { return want, nil },
	}, logr.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %T, want supplied factory output", got)
	}
}

func TestBuildBackend_FactoryErrorFallsBackToNoop(t *testing.T) {
	got, err := buildBackend(Options{
		BackendFactory: func() (tracer.TracerBackend, error) {
			return nil, errors.New("boom")
		},
	}, logr.Discard())
	if err == nil {
		t.Error("expected error to surface even with fallback")
	}
	if _, ok := got.(*NoopBackend); !ok {
		t.Errorf("on factory error must fall back to *NoopBackend, got %T", got)
	}
}

func TestNewNoopBackend_ExportedConstructor(t *testing.T) {
	b := NewNoopBackend()
	if b == nil {
		t.Fatal("NewNoopBackend returned nil")
		return
	}
	if err := b.AttachToCgroup("/x"); err != nil {
		t.Errorf("AttachToCgroup on exported noop: %v", err)
	}
}

func TestNoopBackend_BasicLifecycle(t *testing.T) {
	b := newNoopBackend()
	if err := b.AttachToCgroup("/c/a"); err != nil {
		t.Fatal(err)
	}
	if err := b.AttachToCgroup("/c/b"); err != nil {
		t.Fatal(err)
	}
	if len(b.attached) != 2 {
		t.Errorf("attached len = %d, want 2", len(b.attached))
	}
	if err := b.SetContainerID("abc"); err != nil {
		t.Fatal(err)
	}
	if b.Inject(&events.Event{}) {
		t.Error("Inject should return false before Start")
	}
	ch := make(chan *events.Event, 1)
	if err := b.Start(context.Background(), ch); err != nil {
		t.Fatal(err)
	}
	if !b.Inject(&events.Event{Type: events.EventDNS}) {
		t.Fatal("Inject after Start should succeed")
	}
	select {
	case ev := <-ch:
		if ev.Type != events.EventDNS {
			t.Errorf("got type=%v", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("Inject did not deliver to channel")
	}
	if err := b.Stop(); err != nil {
		t.Fatal(err)
	}
	if b.Inject(&events.Event{}) {
		t.Error("Inject after Stop should return false")
	}
}

func TestServeMetrics_EmptyAddrIsNoop(t *testing.T) {
	if err := serveMetrics(context.Background(), "", NewMetrics(), logr.Discard()); err != nil {
		t.Errorf("empty addr should return nil, got %v", err)
	}
	if err := serveMetrics(context.Background(), "0", NewMetrics(), logr.Discard()); err != nil {
		t.Errorf("'0' addr should return nil, got %v", err)
	}
}

func TestServeMetrics_BadAddrErrors(t *testing.T) {
	err := serveMetrics(context.Background(), "not-a-valid-addr", NewMetrics(), logr.Discard())
	if err == nil {
		t.Fatal("expected listen error")
	}
}

func TestServeMetrics_ServesAndShutsDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveMetrics(ctx, addr, NewMetrics(), logr.Discard())
	}()

	deadline := time.Now().Add(2 * time.Second)
	var ok bool
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			_ = resp.Body.Close()
			ok = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Fatal("metrics server never came up")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
			t.Errorf("serveMetrics: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serveMetrics did not shut down within 3s")
	}
}

func TestNormalizeOTLPEndpoint(t *testing.T) {
	b := func(v bool) *bool { return &v }
	cases := []struct {
		in           string
		wantHost     string
		wantPath     string
		wantInsecure *bool
		wantErr      bool
	}{
		{in: "", wantErr: true},
		{in: "collector:4318", wantHost: "collector:4318"},
		{in: "http://collector:4318", wantHost: "collector:4318", wantInsecure: b(true)},
		{in: "https://collector:4318/v1/traces", wantHost: "collector:4318", wantPath: "/v1/traces", wantInsecure: b(false)},
		{in: "://broken", wantErr: true},
	}
	for _, c := range cases {
		got, err := normalizeOTLPEndpoint(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%q: err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if got.host != c.wantHost {
			t.Errorf("%q: host=%q want %q", c.in, got.host, c.wantHost)
		}
		if got.path != c.wantPath {
			t.Errorf("%q: path=%q want %q", c.in, got.path, c.wantPath)
		}
		switch {
		case c.wantInsecure == nil && got.insecure != nil:
			t.Errorf("%q: insecure=%v want nil", c.in, *got.insecure)
		case c.wantInsecure != nil && got.insecure == nil:
			t.Errorf("%q: insecure=nil want %v", c.in, *c.wantInsecure)
		case c.wantInsecure != nil && *got.insecure != *c.wantInsecure:
			t.Errorf("%q: insecure=%v want %v", c.in, *got.insecure, *c.wantInsecure)
		}
	}
}

func TestEventTypeString(t *testing.T) {
	if got := eventTypeString(events.EventDNS); got != "dns" {
		t.Errorf("DNS = %q, want dns", got)
	}
	if got := eventTypeString(events.EventConnect); got != "net.connect" {
		t.Errorf("Connect = %q, want net.connect", got)
	}
	if got := eventTypeString(events.EventUDPSend); got != "net.udp.send" {
		t.Errorf("UDPSend = %q, want net.udp.send", got)
	}
	if got := eventTypeString(events.EventUDPRecv); got != "net.udp.recv" {
		t.Errorf("UDPRecv = %q, want net.udp.recv", got)
	}
	got := eventTypeString(events.EventType(9999))
	if !strings.HasPrefix(got, "event_") {
		t.Errorf("unknown type = %q, want event_NNNN", got)
	}
}

func TestEventSpanName(t *testing.T) {
	if got := eventSpanName(&events.Event{Type: events.EventDNS}); got != "dns" {
		t.Errorf("no target = %q, want dns", got)
	}
	if got := eventSpanName(&events.Event{Type: events.EventDNS, Target: "example.com"}); got != "dns example.com" {
		t.Errorf("with target = %q", got)
	}
}

func TestNewOTLPEventExporter_RejectsEmptyEndpoint(t *testing.T) {
	if _, err := newOTLPEventExporter(CRKey{Namespace: "ns", Name: "n"}, &BundlePayload{}); err == nil {
		t.Fatal("expected error for missing endpoint")
	}
}

func TestNewOTLPEventExporter_RejectsBadEndpoint(t *testing.T) {
	if _, err := newOTLPEventExporter(CRKey{Namespace: "ns", Name: "n"}, &BundlePayload{Endpoint: "://busted"}); err == nil {
		t.Fatal("expected error for unparseable endpoint")
	}
}

func TestNewOTLPEventExporter_RoundTrip(t *testing.T) {
	hits := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hits <- struct{}{}:
		default:
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	exp, err := newOTLPEventExporter(CRKey{Namespace: "ns", Name: "n"}, &BundlePayload{
		Type:     bundle.TypeOTLP,
		Endpoint: host,
		Insecure: true,
		Sample:   samplePtrRT(0.5),
	})
	if err != nil {
		t.Fatalf("newOTLPEventExporter: %v", err)
	}
	if !strings.HasPrefix(exp.Name(), "otlp/ns/n") {
		t.Errorf("Name = %q", exp.Name())
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = exp.Close(ctx)
	}()

	if err := exp.Export(context.Background(), []*events.Event{
		{Type: events.EventDNS, Target: "example.com", Timestamp: uint64(time.Now().UnixNano())},
		{Type: events.EventConnect, PID: 42},
		nil, // skipped
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if err := exp.Export(context.Background(), nil); err != nil {
		t.Errorf("nil batch: %v", err)
	}
}

func TestNewOTLPEventExporter_HeadersAndCredential(t *testing.T) {
	exp, err := newOTLPEventExporter(CRKey{Namespace: "n", Name: "x"}, &BundlePayload{
		Type:       bundle.TypeOTLP,
		Endpoint:   "127.0.0.1:1",
		Insecure:   true,
		Headers:    map[string]string{"X-Tenant": "team-a"},
		HeaderName: "Authorization",
		Credential: []byte("Bearer xxx"),
	})
	if err != nil {
		t.Fatalf("constructor failed: %v", err)
	}
	_ = exp.Close(context.Background())
}

func TestStatusWriter_EmitOnce_NoRulesIsNoop(t *testing.T) {
	router := NewRouter(nil)
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	w := &StatusWriter{Client: c, NodeName: "n", Router: router, Ready: func() bool { return true }}
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("emitOnce: %v", err)
	}
}

type recordingPatcher struct {
	mu    sync.Mutex
	calls []recordedPatch
}

type recordedPatch struct {
	key     types.NamespacedName
	pt      *podtracev1alpha1.PodTrace
	patchTy string
}

// recordApply unpacks an ApplyConfiguration back into a typed PodTrace
// for assertions.
func (rp *recordingPatcher) recordApply(ac *podtraceac.PodTraceApplyConfiguration) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	pt := &podtracev1alpha1.PodTrace{}
	if ac.Name != nil {
		pt.Name = *ac.Name
	}
	if ac.Namespace != nil {
		pt.Namespace = *ac.Namespace
	}
	if ac.Status != nil {
		for _, n := range ac.Status.NodeStatus {
			row := podtracev1alpha1.PodTraceNodeStatus{}
			if n.Node != nil {
				row.Node = *n.Node
			}
			if n.Ready != nil {
				row.Ready = *n.Ready
			}
			if n.Message != nil {
				row.Message = *n.Message
			}
			if n.Reason != nil {
				row.Reason = *n.Reason
			}
			if n.ActiveCgroups != nil {
				row.ActiveCgroups = *n.ActiveCgroups
			}
			if n.TotalEvents != nil {
				row.TotalEvents = *n.TotalEvents
			}
			if n.DroppedEvents != nil {
				row.DroppedEvents = *n.DroppedEvents
			}
			if n.LastHeartbeat != nil {
				row.LastHeartbeat = *n.LastHeartbeat
			}
			if n.PolicyHash != nil {
				row.PolicyHash = *n.PolicyHash
			}
			pt.Status.NodeStatus = append(pt.Status.NodeStatus, row)
		}
	}
	rp.calls = append(rp.calls, recordedPatch{
		key:     types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace},
		pt:      pt,
		patchTy: "application/apply-patch+yaml",
	})
}

func (rp *recordingPatcher) snapshot() []recordedPatch {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	out := make([]recordedPatch, len(rp.calls))
	copy(out, rp.calls)
	return out
}

func newRecordingClient(t *testing.T, rp *recordingPatcher, seed ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(seed...).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(_ context.Context, _ client.Client, sub string, ac runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				if sub == "status" {
					if pt, ok := ac.(*podtraceac.PodTraceApplyConfiguration); ok {
						rp.recordApply(pt)
					}
				}
				return nil
			},
		}).Build()
}

func TestStatusWriter_EmitOnce_PatchesAllActiveCRs(t *testing.T) {
	const ns = "default"
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: "uid-1"},
	}
	rp := &recordingPatcher{}
	c := newRecordingClient(t, rp, pt)

	router := NewRouter(nil)
	router.Publish([]CRRule{{
		Key:       CRKey{Namespace: ns, Name: "pt"},
		CgroupIDs: map[uint64]struct{}{1: {}, 2: {}},
	}})
	router.Stats().incr(CRKey{Namespace: ns, Name: "pt"}, 7)

	w := &StatusWriter{
		Client:   c,
		NodeName: "node-1",
		Router:   router,
		Ready:    func() bool { return true },
	}
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("emitOnce: %v", err)
	}

	calls := rp.snapshot()
	if len(calls) != 1 {
		t.Fatalf("patch calls = %d, want 1", len(calls))
	}
	if calls[0].key.Name != "pt" || calls[0].key.Namespace != ns {
		t.Errorf("patched key = %v", calls[0].key)
	}
	if calls[0].patchTy != "application/apply-patch+yaml" {
		t.Errorf("patchType = %q, want SSA", calls[0].patchTy)
	}
	if len(calls[0].pt.Status.NodeStatus) != 1 {
		t.Fatalf("status rows = %d, want 1", len(calls[0].pt.Status.NodeStatus))
	}
	row := calls[0].pt.Status.NodeStatus[0]
	if row.Node != "node-1" || !row.Ready || row.ActiveCgroups != 2 || row.TotalEvents != 7 {
		t.Errorf("row = %+v", row)
	}
}

func TestStatusWriter_EmitOnce_ReadyNilDefaultsTrue(t *testing.T) {
	router := NewRouter(nil)
	router.Publish([]CRRule{{Key: CRKey{Namespace: "ns", Name: "pt"}}})

	rp := &recordingPatcher{}
	c := newRecordingClient(t, rp, &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "ns"},
	})
	w := &StatusWriter{Client: c, NodeName: "n", Router: router} // Ready nil
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("emitOnce: %v", err)
	}
	calls := rp.snapshot()
	if len(calls) != 1 || !calls[0].pt.Status.NodeStatus[0].Ready {
		t.Errorf("nil Ready func should default to Ready=true; got calls=%+v", calls)
	}
}

func TestStatusWriter_Run_StopsOnContextCancel(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	w := &StatusWriter{
		Client: c, NodeName: "n",
		Router:   NewRouter(nil),
		Interval: 10 * time.Millisecond,
		Ready:    func() bool { return true },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	// Allow at least one tick.
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestStatusWriter_Run_PatchErrorIsLoggedNotFatal(t *testing.T) {
	router := NewRouter(nil)
	router.Publish([]CRRule{{Key: CRKey{Namespace: "ns", Name: "missing"}}})
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
				return errors.New("synthetic patch error")
			},
		}).Build()

	w := &StatusWriter{
		Client: c, NodeName: "n",
		Router:   router,
		Interval: 5 * time.Millisecond,
		Ready:    func() bool { return false },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := w.Run(ctx); err != nil {
		t.Errorf("Run returned %v despite per-tick patch errors", err)
	}
}

func TestComputeNodeReport_AggregatesUniqueCgroups(t *testing.T) {
	router := NewRouter(nil)
	router.Publish([]CRRule{
		{Key: CRKey{Namespace: "ns", Name: "a"}, CgroupIDs: map[uint64]struct{}{1: {}, 2: {}}},
		{Key: CRKey{Namespace: "ns", Name: "b"}, CgroupIDs: map[uint64]struct{}{2: {}, 3: {}}},
	})
	router.Stats().incr(CRKey{Namespace: "ns", Name: "a"}, 4)
	router.Stats().incrDropped(CRKey{Namespace: "ns", Name: "b"}, 1)

	r := ComputeNodeReport("n", router, true)
	if r.Node != "n" || !r.Ready {
		t.Errorf("report wrong: %+v", r)
	}
	if r.ActiveCgroups != 3 {
		t.Errorf("ActiveCgroups = %d, want 3 (deduplicated union)", r.ActiveCgroups)
	}
	if r.TotalEvents != 4 || r.DroppedEvents != 1 {
		t.Errorf("counters = %+v", r)
	}
}

func TestSafeUint64ToInt64(t *testing.T) {
	if got := safeUint64ToInt64(42); got != 42 {
		t.Errorf("small = %d, want 42", got)
	}
	if got := safeUint64ToInt64(uint64(int64(1)<<62) + 1); got <= 0 {
		t.Errorf("under-cap got %d, want positive", got)
	}
	max := uint64(int64(^uint64(0) >> 1))
	if got := safeUint64ToInt64(max); int64(got) != int64(max) {
		t.Errorf("maxint64 conversion lossy: got %d", got)
	}
	huge := uint64(1) << 63 // exactly the wrap-point
	if got := safeUint64ToInt64(huge); got <= 0 {
		t.Errorf("over-cap should clamp to positive maxint64, got %d", got)
	}
}

func TestLenToInt32(t *testing.T) {
	if got := lenToInt32(7); got != 7 {
		t.Errorf("got %d, want 7", got)
	}
	if got := lenToInt32(0); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestResolveNodeName_HostnameFallback(t *testing.T) {
	t.Setenv("NODE_NAME", "")
	got := ResolveNodeName()
	if got == "" {
		t.Error("expected hostname fallback to produce a non-empty name")
	}
}

var _ = sync.Mutex{}

func TestRouter_NameAndStats(t *testing.T) {
	r := NewRouter(nil)
	if r.Name() != "cr-router" {
		t.Errorf("Name = %q, want cr-router", r.Name())
	}
	if r.Stats() == nil {
		t.Error("Stats() should never be nil")
	}
}

type fakeGateableBackend struct {
	*NoopBackend
	mu       sync.Mutex
	captured [][]string
	err      error
}

func (f *fakeGateableBackend) SetEnabledCategories(categories []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captured = append(f.captured, append([]string(nil), categories...))
	return f.err
}

func TestMakeCategoryGate_BackendImplementsGateable(t *testing.T) {
	b := &fakeGateableBackend{NoopBackend: NewNoopBackend()}
	gate := makeCategoryGate(b)
	if gate == nil {
		t.Fatal("gate must be non-nil for gateable backend")
		return
	}
	if err := gate([]string{"dns", "net"}); err != nil {
		t.Fatalf("gate: %v", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.captured) != 1 || !reflect.DeepEqual(b.captured[0], []string{"dns", "net"}) {
		t.Errorf("captured = %v, want [[dns net]]", b.captured)
	}
}

func TestMakeCategoryGate_BackendDoesNotImplementGateableReturnsNil(t *testing.T) {
	gate := makeCategoryGate(NewNoopBackend())
	if gate != nil {
		t.Error("gate should be nil for non-gateable backend")
	}
}

func TestMakeCategoryGate_NilBackendReturnsNil(t *testing.T) {
	if gate := makeCategoryGate(nil); gate != nil {
		t.Error("nil backend must produce nil gate")
	}
}

func samplePtrRT(v float64) *float64 { return &v }
