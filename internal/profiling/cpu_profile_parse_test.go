package profiling

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"

	"github.com/gma1k/podtrace/internal/events"
)

func cpuProfileBytes(t *testing.T) []byte {
	t.Helper()
	hot := &profile.Function{ID: 1, Name: "main.hot"}
	evil := &profile.Function{ID: 2, Name: "main.\x1b[2Jevil"}
	cold := &profile.Function{ID: 3, Name: "main.cold"}
	locHot := &profile.Location{ID: 1, Address: 0x10, Line: []profile.Line{{Function: hot}}}
	locEvil := &profile.Location{ID: 2, Address: 0x20, Line: []profile.Line{{Function: evil}}}
	locCold := &profile.Location{ID: 3, Address: 0x30, Line: []profile.Line{{Function: cold}}}
	locBare := &profile.Location{ID: 4, Address: 0x40}
	p := &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "samples", Unit: "count"}, {Type: "cpu", Unit: "nanoseconds"}},
		PeriodType: &profile.ValueType{Type: "cpu", Unit: "nanoseconds"},
		Period:     10_000_000,
		Function:   []*profile.Function{hot, evil, cold},
		Location:   []*profile.Location{locHot, locEvil, locCold, locBare},
		Sample: []*profile.Sample{
			{Location: []*profile.Location{locHot, locCold}, Value: []int64{30, 300_000_000}},
			{Location: []*profile.Location{locHot}, Value: []int64{10, 100_000_000}},
			{Location: []*profile.Location{locEvil}, Value: []int64{5, 50_000_000}},
			{Location: []*profile.Location{locCold}, Value: []int64{2, 20_000_000}},
			{Location: []*profile.Location{locBare}, Value: []int64{1, 10_000_000}},
		},
		DurationNanos: int64(time.Second),
	}
	var buf bytes.Buffer
	if err := p.Write(&buf); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	return buf.Bytes()
}

func TestParseCPUProfileRanksFlatTime(t *testing.T) {
	top, err := parseCPUProfile(cpuProfileBytes(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(top) != 4 {
		t.Fatalf("expected 4 functions, got %v", top)
	}
	if top[0].Function != "main.hot" || top[0].CPUTime != 400*time.Millisecond || top[0].Samples != 40 {
		t.Errorf("unexpected leader %+v", top[0])
	}
	if top[2].Function != "main.cold" || top[2].CPUTime != 20*time.Millisecond {
		t.Errorf("cold must count flat time only, got %+v", top[2])
	}
	if top[3].Function != "0x40" {
		t.Errorf("unsymbolized location should fall back to its address, got %+v", top[3])
	}
	for _, f := range top {
		if strings.Contains(f.Function, "\x1b") {
			t.Errorf("function name not sanitized: %q", f.Function)
		}
	}
}

func TestParseCPUProfileRejectsGarbage(t *testing.T) {
	if _, err := parseCPUProfile([]byte("not a profile")); err == nil {
		t.Error("expected an error for a non-pprof body")
	}
}

func TestCPUProfileReachesReportAndResult(t *testing.T) {
	body := cpuProfileBytes(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	host, port := mustParseAddr(t, srv.Listener.Addr().String())
	h := NewHandler(host, []int{port})
	h.profiler.foundPort.Store(int64(port))

	h.doProfile(context.Background(), ProfileCPU, time.Second)

	res := h.GetResult()
	if res == nil || res.CPUProfile == nil || len(res.CPUProfile.TopCPUFunctions) == 0 {
		t.Fatalf("expected parsed CPU functions in the stored result, got %+v", res)
	}
	if res.CPUProfile.RawBytes != nil {
		t.Error("the raw CPU profile must not be retained")
	}

	section := h.GenerateSection([]*events.Event{}, time.Second)
	if !strings.Contains(section, "Top CPU functions") || !strings.Contains(section, "main.hot") {
		t.Errorf("report should list CPU functions:\n%s", section)
	}
	if strings.Contains(section, "\x1b") {
		t.Errorf("report contains an escape byte:\n%q", section)
	}

	m := h.resultMap()
	top, ok := m["top_cpu_functions"]
	if !ok {
		t.Fatal("result payload missing top_cpu_functions")
	}
	if !strings.Contains(fmt.Sprint(top), "main.hot") {
		t.Errorf("top_cpu_functions should include main.hot, got %v", top)
	}
}
