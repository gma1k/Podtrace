package diagnose

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/report"
	"github.com/gma1k/podtrace/internal/events"
)

func TestTheSummarySaysWhenTheBufferSampled(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 10
	d.sampleIntN = reject
	for i := range 30 {
		d.AddEvent(&events.Event{Type: events.EventRead, Timestamp: uint64(i + 1)})
	}
	d.Finish()

	got := report.GenerateSummarySection(d, time.Second)
	if !strings.Contains(got, "Events seen: 30") || !strings.Contains(got, "sampled out 20") {
		t.Errorf("summary does not say the counts are a sample:\n%s", got)
	}
	if summary := d.ExportJSON().Summary; summary["events_sampled_out"] != 20 {
		t.Errorf("export summary = %v, want events_sampled_out 20", summary)
	}
}

func TestFinishAndTheWindowReadDoNotRace(t *testing.T) {
	d := NewDiagnostician()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 200 {
			d.Finish()
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			_ = d.EndTime().Sub(d.StartTime())
		}
	}()
	wg.Wait()
}
