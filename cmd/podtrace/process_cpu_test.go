package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose"
	"github.com/gma1k/podtrace/internal/events"
)

type fakeProcessCPU struct {
	countErr error
	times    map[uint32]uint64
	drainErr error
	drains   int
}

func (f *fakeProcessCPU) CountProcessCPU() error { return f.countErr }

func (f *fakeProcessCPU) DrainProcessCPU() (map[uint32]uint64, error) {
	f.drains++
	return f.times, f.drainErr
}

func withNoProcessCPU(t *testing.T) {
	t.Helper()
	saved := processCPU
	t.Cleanup(func() { processCPU = saved })
	processCPU = nil
}

func podEvent(pid uint32, comm, pod string) *events.Event {
	return &events.Event{
		Type: events.EventTCPSend, PID: pid, ProcessName: comm, CgroupID: 7,
		K8s: &events.K8sMetadata{Namespace: "ns", PodName: pod},
	}
}

func TestADiagnoseRunDrainsTheKernelsProcessCPUOnce(t *testing.T) {
	withNoProcessCPU(t)
	withNoFastCounter(t)
	counter := &fakeProcessCPU{times: map[uint32]uint64{4194001: 4_000_000}}
	countProcessCPU(counter)

	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	d.AddEvent(podEvent(4194001, "wget", "busybox-test"))
	d.Finish()

	report := generateDiagnoseReport(d)
	if !strings.Contains(report, "PID 4194001 (wget):") || !strings.Contains(report, "4.0ms") {
		t.Errorf("report does not show the kernel's CPU time for an exited process:\n%s", report)
	}
	_ = generateDiagnoseReport(d)
	if counter.drains != 1 {
		t.Errorf("drained %d times; a second report would lose what the first drained", counter.drains)
	}
}

func TestEachPodsReportGetsTheKernelsProcessCPU(t *testing.T) {
	withNoProcessCPU(t)
	withNoFastCounter(t)
	countProcessCPU(&fakeProcessCPU{times: map[uint32]uint64{4194001: 4_000_000, 4194002: 9_000_000}})

	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	d.AddEvent(podEvent(4194001, "wget", "a"))
	d.AddEvent(podEvent(4194002, "curl", "b"))
	d.Finish()

	report := generateDiagnoseReport(d)
	for _, want := range []string{"PID 4194001 (wget):", "(4.0ms /", "PID 4194002 (curl):", "(9.0ms /"} {
		if !strings.Contains(report, want) {
			t.Errorf("a per-pod report lacks %q:\n%s", want, report)
		}
	}
}

func TestProcessCPUFallsBackWhenTheKernelCannotCount(t *testing.T) {
	withNoProcessCPU(t)
	countProcessCPU(&fakeProcessCPU{countErr: errors.New("no map")})
	if processCPU != nil {
		t.Fatal("a counter that could not start must not be drained")
	}

	withNoFastCounter(t)
	failing := &fakeProcessCPU{drainErr: errors.New("read failed")}
	countProcessCPU(failing)
	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	d.AddEvent(podEvent(4194001, "wget", "busybox-test"))
	d.Finish()
	report := generateDiagnoseReport(d)
	if !strings.Contains(report, "CPU time unavailable for the 1 traced process (it exited before sampling)") {
		t.Errorf("a failed drain must fall back to the honest line:\n%s", report)
	}
}

func TestCountProcessCPUIgnoresTracersWithoutIt(t *testing.T) {
	withNoProcessCPU(t)
	countProcessCPU(struct{}{})
	if processCPU != nil {
		t.Fatal("a tracer without process CPU counting must leave the drain unset")
	}
}
