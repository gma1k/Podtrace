package profiling

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"
)

func writeProfile(t *testing.T, p *profile.Profile) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := p.Write(&buf); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	return buf.Bytes()
}

func TestParseCPUProfileRequiresCPUNanosecondsSampleType(t *testing.T) {
	fn := &profile.Function{ID: 1, Name: "main.alloc"}
	loc := &profile.Location{ID: 1, Line: []profile.Line{{Function: fn}}}
	raw := writeProfile(t, &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "alloc_space", Unit: "bytes"}},
		Function:   []*profile.Function{fn},
		Location:   []*profile.Location{loc},
		Sample:     []*profile.Sample{{Location: []*profile.Location{loc}, Value: []int64{1024}}},
	})
	_, err := parseCPUProfile(raw)
	if err == nil || !strings.Contains(err.Error(), "cpu/nanoseconds") {
		t.Fatalf("expected a missing cpu sample type error, got %v", err)
	}
}

func TestParseCPUProfileSkipsSamplesWithoutLocation(t *testing.T) {
	fn := &profile.Function{ID: 1, Name: "main.work"}
	loc := &profile.Location{ID: 1, Line: []profile.Line{{Function: fn}}}
	raw := writeProfile(t, &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}},
		Function:   []*profile.Function{fn},
		Location:   []*profile.Location{loc},
		Sample: []*profile.Sample{
			{Value: []int64{900_000_000}},
			{Location: []*profile.Location{loc}, Value: []int64{5_000_000}},
		},
	})
	top, err := parseCPUProfile(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(top) != 1 || top[0].Function != "main.work" || top[0].CPUTime != 5*time.Millisecond || top[0].Samples != 0 {
		t.Fatalf("unexpected result %+v", top)
	}
}

func TestParseCPUProfileBreaksTiesByNameAndCapsTheList(t *testing.T) {
	p := &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "samples", Unit: "count"}, {Type: "cpu", Unit: "nanoseconds"}},
	}
	total := maxTopFunctions + 5
	for i := 0; i < total; i++ {
		fn := &profile.Function{ID: uint64(i + 1), Name: fmt.Sprintf("main.f%02d", i)}
		loc := &profile.Location{ID: uint64(i + 1), Line: []profile.Line{{Function: fn}}}
		p.Function = append(p.Function, fn)
		p.Location = append(p.Location, loc)
		p.Sample = append(p.Sample, &profile.Sample{Location: []*profile.Location{loc}, Value: []int64{1, 10_000_000}})
	}
	top, err := parseCPUProfile(writeProfile(t, p))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(top) != maxTopFunctions {
		t.Fatalf("got %d functions, want %d", len(top), maxTopFunctions)
	}
	for i, f := range top {
		if want := fmt.Sprintf("main.f%02d", i); f.Function != want {
			t.Errorf("position %d = %q, want %q", i, f.Function, want)
		}
	}
}

func TestGenerateSectionListsAtMostEightCPUFunctions(t *testing.T) {
	var fns []CPUFunctionSample
	for i := 0; i < 12; i++ {
		fns = append(fns, CPUFunctionSample{Function: fmt.Sprintf("main.cpu%02d", i), CPUTime: time.Duration(12-i) * time.Millisecond, Samples: 1})
	}
	cr := &CorrelatedResult{
		PprofAvailable: true,
		CPUProfile:     &ProfileResult{Type: ProfileCPU, Available: true, Duration: 5 * time.Second, TopCPUFunctions: fns},
	}
	out := GenerateSection(cr, time.Second)
	if !strings.Contains(out, "Top CPU functions (from 5s pprof CPU profile") {
		t.Fatalf("missing CPU section header:\n%s", out)
	}
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("main.cpu%02d", i)
		if listed := strings.Contains(out, name); listed != (i < 8) {
			t.Errorf("%s listed=%v, want %v", name, listed, i < 8)
		}
	}
}
