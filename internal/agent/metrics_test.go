package agent

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestMetrics_RefreshEmitsDeltaOnly(t *testing.T) {
	m := NewMetrics()
	router := NewRouter(nil)
	router.Publish([]CRRule{
		mkRule("ns", "pt", []uint64{1, 2}, []events.EventType{events.EventDNS}, &recExp{name: "x"}),
	})

	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `events_exported_total{cr_namespace="ns",cr_name="pt"}`); got != 0 {
		t.Fatalf("initial counter should be 0, got %d", got)
	}

	router.Stats().incr(CRKey{"ns", "pt"}, 10)
	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `events_exported_total{cr_namespace="ns",cr_name="pt"}`); got != 10 {
		t.Fatalf("after incr(10): counter=%d want 10", got)
	}

	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `events_exported_total{cr_namespace="ns",cr_name="pt"}`); got != 10 {
		t.Fatalf("idle refresh double-counted: %d", got)
	}

	router.Stats().incr(CRKey{"ns", "pt"}, 5)
	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `events_exported_total{cr_namespace="ns",cr_name="pt"}`); got != 15 {
		t.Fatalf("cumulative: %d want 15", got)
	}
}

func TestMetrics_RemovedCRDropsLabels(t *testing.T) {
	m := NewMetrics()
	router := NewRouter(nil)
	router.Publish([]CRRule{
		mkRule("ns", "goes", []uint64{1}, []events.EventType{events.EventDNS}, &recExp{name: "x"}),
	})
	key := CRKey{"ns", "goes"}
	router.Stats().incr(key, 7)
	router.Stats().incrDropped(key, 2)
	m.RefreshFromRouter(router)
	m.ObserveSpanBatched(key, 4)
	m.ObserveExportDelivery(key, 3, nil)
	m.ObserveExportDelivery(key, 1, errors.New("connection refused"))
	m.RecordThresholdTripped(key, "latency")

	for _, family := range []string{
		"events_exported_total", "events_dropped_total", "spans_batched_total",
		"spans_delivered_total", "export_delivery_dropped_total", "threshold_tripped_total",
	} {
		if scrapeMetric(t, m, family+`{cr_namespace="ns",cr_name="goes"}`) == 0 {
			t.Fatalf("pre-removal: %s has no cr_name=goes series", family)
		}
	}

	router.Publish(nil)
	m.RefreshFromRouter(router)

	body := scrape(t, m)
	if strings.Contains(body, `cr_name="goes"`) {
		t.Errorf("post-removal: series still carry cr_name=goes:\n%s", body)
	}

	m.ObserveExportDelivery(key, 5, nil)
	m.ObserveExportDelivery(key, 5, errors.New("connection refused"))
	m.ObserveSpanBatched(key, 5)
	m.RecordThresholdTripped(key, "latency")
	m.ObserveErrorRate(key, 10, true)
	if body = scrape(t, m); strings.Contains(body, `cr_name="goes"`) {
		t.Errorf("late observations resurrected a removed CR:\n%s", body)
	}

	router.Publish([]CRRule{
		mkRule("ns", "goes", []uint64{1}, []events.EventType{events.EventDNS}, &recExp{name: "x"}),
	})
	m.RefreshFromRouter(router)
	m.ObserveExportDelivery(key, 2, nil)
	m.ObserveSpanBatched(key, 2)
	if got := scrapeMetric(t, m, `spans_delivered_total{cr_namespace="ns",cr_name="goes"}`); got != 2 {
		t.Errorf("re-added CR spans_delivered_total = %d, want 2", got)
	}
	if got := scrapeMetric(t, m, `spans_batched_total{cr_namespace="ns",cr_name="goes"}`); got != 2 {
		t.Errorf("re-added CR spans_batched_total = %d, want 2", got)
	}
}

func TestMetrics_ActiveCRsTracksRouterSize(t *testing.T) {
	m := NewMetrics()
	router := NewRouter(nil)

	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `active_crs`); got != 0 {
		t.Errorf("no CRs → active_crs=%d want 0", got)
	}

	router.Publish([]CRRule{
		mkRule("ns", "a", []uint64{1}, []events.EventType{events.EventDNS}, &recExp{}),
		mkRule("ns", "b", []uint64{2}, []events.EventType{events.EventDNS}, &recExp{}),
	})
	m.RefreshFromRouter(router)
	if got := scrapeMetric(t, m, `active_crs`); got != 2 {
		t.Errorf("active_crs=%d want 2", got)
	}
}

func TestMetrics_BackendDegraded_NoSeriesByDefault(t *testing.T) {
	m := NewMetrics()
	body := scrape(t, m)
	if strings.Contains(body, "podtrace_agent_backend_degraded") {
		t.Errorf("untouched backend_degraded GaugeVec must emit no output; got:\n%s", body)
	}
}

func TestMetrics_BackendDegraded_SetByReason(t *testing.T) {
	m := NewMetrics()
	m.BackendDegraded.WithLabelValues("permission_denied").Set(1)

	got := scrapeMetric(t, m, `backend_degraded{reason="permission_denied"}`)
	if got != 1 {
		t.Errorf("backend_degraded{reason=permission_denied} = %d, want 1", got)
	}
}

func TestMetrics_ProgramAttachFailures_ByProgramAndReason(t *testing.T) {
	m := NewMetrics()

	if scrapeMetric(t, m, `program_attach_failures_total{program="kprobe_vfs_open",reason="permission_denied"}`) != 0 {
		t.Fatal("untouched program_attach_failures_total must emit no series")
	}

	m.RecordProgramAttachFailure("kprobe_vfs_open", "permission_denied")
	m.RecordProgramAttachFailure("kprobe_vfs_open", "permission_denied")
	m.RecordProgramAttachFailure("kprobe_do_futex", "kernel_too_old")

	if got := scrapeMetric(t, m, `program_attach_failures_total{program="kprobe_vfs_open",reason="permission_denied"}`); got != 2 {
		t.Errorf("vfs_open permission_denied = %d, want 2", got)
	}
	if got := scrapeMetric(t, m, `program_attach_failures_total{program="kprobe_do_futex",reason="kernel_too_old"}`); got != 1 {
		t.Errorf("do_futex kernel_too_old = %d, want 1", got)
	}
}

func TestMetrics_ProgramAttachFailures_EmptyReasonNormalized(t *testing.T) {
	m := NewMetrics()
	m.RecordProgramAttachFailure("kprobe_x", "")
	if got := scrapeMetric(t, m, `program_attach_failures_total{program="kprobe_x",reason="unknown"}`); got != 1 {
		t.Errorf("empty reason should normalize to unknown; got %d", got)
	}
}

func TestMetrics_ProgramAttachFailures_NilReceiverSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil receiver panicked: %v", r)
		}
	}()
	var m *Metrics
	m.RecordProgramAttachFailure("kprobe_x", "permission_denied")
}

func TestMetrics_ExporterInit_EdgeTriggered(t *testing.T) {
	m := NewMetrics()
	cr := CRKey{Namespace: "ns", Name: "broken"}
	bad := errors.New("unknown exporter type \"zipkin-direct\"")

	m.ObserveExporterInit(cr, bad)
	if got := scrapeMetric(t, m, `exporter_init_failures_total{cr_namespace="ns",cr_name="broken",reason="unsupported_type"}`); got != 1 {
		t.Fatalf("first failure: counter = %d, want 1", got)
	}

	m.ObserveExporterInit(cr, bad)
	m.ObserveExporterInit(cr, bad)
	if got := scrapeMetric(t, m, `exporter_init_failures_total{cr_namespace="ns",cr_name="broken",reason="unsupported_type"}`); got != 1 {
		t.Errorf("sustained failure inflated counter: %d, want 1", got)
	}

	m.ObserveExporterInit(cr, nil)
	if got := scrapeMetric(t, m, `exporter_init_failures_total{cr_namespace="ns",cr_name="broken",reason="unsupported_type"}`); got != 1 {
		t.Errorf("recovery should not change the counter; got %d", got)
	}

	m.ObserveExporterInit(cr, bad)
	if got := scrapeMetric(t, m, `exporter_init_failures_total{cr_namespace="ns",cr_name="broken",reason="unsupported_type"}`); got != 2 {
		t.Errorf("second edge: counter = %d, want 2", got)
	}
}

func TestMetrics_ExporterInit_ReasonClassification(t *testing.T) {
	m := NewMetrics()
	cases := []struct {
		cr     CRKey
		err    error
		reason string
	}{
		{CRKey{"ns", "a"}, errors.New("nil bundle payload"), "nil_payload"},
		{CRKey{"ns", "b"}, errors.New("missing endpoint for OTLP exporter"), "endpoint_missing"},
		{CRKey{"ns", "c"}, errors.New("tls handshake failed"), "tls_invalid"},
		{CRKey{"ns", "d"}, errors.New("missing api key"), "auth_missing"},
	}
	for _, tc := range cases {
		m.ObserveExporterInit(tc.cr, tc.err)
		sel := `exporter_init_failures_total{cr_namespace="` + tc.cr.Namespace + `",cr_name="` + tc.cr.Name + `",reason="` + tc.reason + `"}`
		if got := scrapeMetric(t, m, sel); got != 1 {
			t.Errorf("cr %s/%s expected reason=%q to register; got %d", tc.cr.Namespace, tc.cr.Name, tc.reason, got)
		}
	}
}

func TestMetrics_HandlerServesText(t *testing.T) {
	m := NewMetrics()
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL) //nolint:noctx // test-only
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "podtrace_agent_active_crs") {
		t.Error("expected podtrace_agent_active_crs in /metrics output")
	}
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL) //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func scrapeMetric(t *testing.T, m *Metrics, selector string) int {
	t.Helper()
	name, needles := parseSelector(selector)
	want := "podtrace_agent_" + name

	for _, line := range strings.Split(scrape(t, m), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !strings.HasPrefix(line, want) {
			continue
		}
		allNeedles := true
		for _, n := range needles {
			if !strings.Contains(line, n) {
				allNeedles = false
				break
			}
		}
		if !allNeedles {
			continue
		}
		idx := strings.LastIndex(line, " ")
		if idx < 0 {
			continue
		}
		var v int
		if _, err := sscan(line[idx+1:], &v); err == nil {
			return v
		}
	}
	return 0
}

func parseSelector(sel string) (string, []string) {
	open := strings.IndexByte(sel, '{')
	if open < 0 {
		return sel, nil
	}
	name := sel[:open]
	inner := strings.TrimSuffix(sel[open+1:], "}")
	if inner == "" {
		return name, nil
	}
	return name, strings.Split(inner, ",")
}

func sscan(s string, out *int) (int, error) {
	s = strings.TrimSpace(s)
	v := 0
	neg := false
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, errParse
		}
		v = v*10 + int(c-'0')
	}
	if neg {
		v = -v
	}
	*out = v
	return 1, nil
}

var errParse = &parseErr{}

type parseErr struct{}

func (*parseErr) Error() string { return "parse error" }

func TestMetrics_SpanBatchAndDeliveryCounters(t *testing.T) {
	m := NewMetrics()
	cr := CRKey{"ns", "pt"}

	m.ObserveSpanBatched(cr, 5)
	m.ObserveExportDelivery(cr, 3, nil)
	m.ObserveExportDelivery(cr, 2, errors.New("refused"))

	if got := scrapeMetric(t, m, `spans_batched_total{cr_namespace="ns",cr_name="pt"}`); got != 5 {
		t.Errorf("spans_batched_total=%d want 5", got)
	}
	if got := scrapeMetric(t, m, `spans_delivered_total{cr_namespace="ns",cr_name="pt"}`); got != 3 {
		t.Errorf("spans_delivered_total=%d want 3", got)
	}
	if got := scrapeMetric(t, m, `export_delivery_dropped_total{cr_namespace="ns",cr_name="pt"}`); got != 2 {
		t.Errorf("export_delivery_dropped_total=%d want 2", got)
	}
}
