package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
)

type drainSequence struct {
	cpu    []map[uint32]uint64
	fs     [][]kernelagg.Row
	cpuIdx int
	fsIdx  int
}

func (d *drainSequence) CountProcessCPU() error { return nil }

func (d *drainSequence) DrainProcessCPU() (map[uint32]uint64, error) {
	out := d.cpu[min(d.cpuIdx, len(d.cpu)-1)]
	d.cpuIdx++
	return out, nil
}

func (d *drainSequence) CountFastFilesystemOps() error { return nil }

func (d *drainSequence) DrainFastFilesystemOps() ([]kernelagg.Row, error) {
	out := d.fs[min(d.fsIdx, len(d.fs)-1)]
	d.fsIdx++
	return out, nil
}

func TestCPUCountedBeforeTheWindowOpensIsNotReported(t *testing.T) {
	withNoProcessCPU(t)
	withNoFastCounter(t)
	seq := &drainSequence{
		cpu: []map[uint32]uint64{{4194001: 2_000_000_000}, {4194001: 40_000_000}},
		fs:  [][]kernelagg.Row{nil, nil},
	}
	countProcessCPU(seq)
	countFastFilesystemOps(seq)

	d := diagnose.NewDiagnosticianWithThresholds(errorRateThreshold, rttSpikeThreshold, fsSlowThreshold)
	openKernelCountWindow()
	d.AddEvent(podEvent(4194001, "spin", "busy"))
	d.Finish()

	report := generateDiagnoseReport(d)
	if !strings.Contains(report, "(40.0ms /") {
		t.Errorf("want only the 40ms spent in the window:\n%s", report)
	}
	if seq.fsIdx != 2 {
		t.Errorf("filesystem counts drained %d times, want the setup drain and the report's", seq.fsIdx)
	}
}

func TestAFailedResetStillOpensTheWindow(t *testing.T) {
	withNoProcessCPU(t)
	withNoFastCounter(t)
	cpu := &fakeProcessCPU{drainErr: errors.New("map gone")}
	fs := &fakeFastCounter{drainErr: errors.New("map gone")}
	countProcessCPU(cpu)
	countFastFilesystemOps(fs)

	openKernelCountWindow()

	if cpu.drains != 1 || fs.drains != 1 {
		t.Errorf("drains = cpu %d, fs %d; want one reset attempt each", cpu.drains, fs.drains)
	}
	if processCPU == nil || fastFilesystemOps == nil {
		t.Error("a failed reset must leave the report's drain in place")
	}
}
