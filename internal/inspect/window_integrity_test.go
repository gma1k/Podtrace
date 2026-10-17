package inspect

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func containerLabels(container string) []*dto.LabelPair {
	return []*dto.LabelPair{
		label("namespace", "shop"),
		label("workload", "checkout"),
		label("workload_kind", "Deployment"),
		label("container", container),
	}
}

func TestASeriesMissingFromAPartialGatherIsNotOneWindowsDelta(t *testing.T) {
	start := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	prev, err := Take(&fixedGatherer{
		families: []*dto.MetricFamily{counterFamily(familyL7Requests,
			counter(10, workloadLabels(label("outcome", "ok"), label("protocol", "http"))...))},
		err: errors.New("one collector failed"),
	}, start)
	if err == nil {
		t.Fatal("precondition: the gather should report its error")
	}
	cur, _ := Take(&fixedGatherer{families: []*dto.MetricFamily{counterFamily(familyL7Requests,
		counter(12, workloadLabels(label("outcome", "ok"), label("protocol", "http"))...),
		counter(90_000, workloadLabels(label("outcome", "error"), label("protocol", "http"))...),
	)}}, start.Add(time.Minute))

	deltas := Window{Prev: prev, Cur: cur}.Deltas(familyL7Requests)
	if len(deltas) != 1 || deltas[0].Value != 2 {
		t.Fatalf("deltas = %+v, want only the ok series with 2: the error series' lifetime "+
			"90000 is not a one-minute delta just because the last gather missed it", deltas)
	}
}

func TestASeriesNewSinceACompleteGatherStillCounts(t *testing.T) {
	start := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	prev, _ := Take(&fixedGatherer{families: []*dto.MetricFamily{counterFamily(familyL7Requests,
		counter(10, workloadLabels(label("outcome", "ok"))...))}}, start)
	cur, _ := Take(&fixedGatherer{families: []*dto.MetricFamily{counterFamily(familyL7Requests,
		counter(10, workloadLabels(label("outcome", "ok"))...),
		counter(3, workloadLabels(label("outcome", "error"))...),
	)}}, start.Add(time.Minute))

	if got := len(Window{Prev: prev, Cur: cur}.Deltas(familyL7Requests)); got != 2 {
		t.Errorf("got %d deltas, want 2", got)
	}
}

func TestSlowAcquisitionIsOneIssuePerWorkloadWhateverTheContainer(t *testing.T) {
	prev := []*dto.MetricFamily{histogramFamily(familyAcquire,
		histogram(10, 0.5, containerLabels("api")...),
		histogram(10, 0.5, containerLabels("worker")...))}
	cur := []*dto.MetricFamily{histogramFamily(familyAcquire,
		histogram(60, 15.5, containerLabels("api")...),
		histogram(60, 15.5, containerLabels("worker")...))}

	got := evalOnce(t, acquireLatencyRule(), prev, cur, time.Minute)
	if len(got) != 1 {
		t.Fatalf("got %d issues, want 1", len(got))
	}
	if got[0].Subject.Container != "" {
		t.Errorf("subject container = %q; the totals span both containers, and naming one "+
			"makes the issue key change with whichever series came first", got[0].Subject.Container)
	}
}

func TestActiveIssuesCountOnceAgainstTheBudget(t *testing.T) {
	h := &harness{
		gatherer: &fixedGatherer{},
		registry: prometheus.NewRegistry(),
		observer: &recorder{},
		clock:    time.Now(),
	}
	engine, err := New(Options{
		Gatherer:   h.gatherer,
		Registerer: h.registry,
		Rules:      []Rule{saturationRule()},
		Thresholds: DefaultThresholds(),
		Budget:     4,
		Now:        func() time.Time { return h.clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.engine = engine

	saturatedPods := func(pods ...string) *dto.MetricFamily {
		var metrics []*dto.Metric
		for _, pod := range pods {
			metrics = append(metrics, gauge(97, workloadLabels(label("resource", "cpu"), label("pod", pod))...))
		}
		return gaugeFamily(familyUtilization, metrics...)
	}

	h.serve(saturatedPods("a", "b"))
	h.evaluate(t)
	h.advance(2 * time.Minute)
	if got := len(h.evaluate(t)); got != 2 {
		t.Fatalf("precondition: activated %d, want 2", got)
	}

	h.serve(saturatedPods("a", "b", "c", "d"))
	h.evaluate(t)
	if got := h.counterValue(t, "podtrace_inspections_dropped_total", nil); got != 0 {
		t.Errorf("dropped = %v with 4 issues tracked at a budget of 4; active issues were "+
			"counted twice", got)
	}
}
