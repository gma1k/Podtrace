package v1alpha1_test

import (
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func on() *bool  { v := true; return &v }
func off() *bool { v := false; return &v }

type toggle struct {
	path    string
	read    func(spec *podtracev1alpha1.TracerConfigSpec) bool
	turnOff func(spec *podtracev1alpha1.TracerConfigSpec)
}

func metricsOf(spec *podtracev1alpha1.TracerConfigSpec) *podtracev1alpha1.AgentMetricsSpec {
	if spec.Agent.Metrics == nil {
		spec.Agent.Metrics = &podtracev1alpha1.AgentMetricsSpec{}
	}
	return spec.Agent.Metrics
}

func inspectionsOf(spec *podtracev1alpha1.TracerConfigSpec) *podtracev1alpha1.AgentInspectionsSpec {
	m := metricsOf(spec)
	if m.Inspections == nil {
		m.Inspections = &podtracev1alpha1.AgentInspectionsSpec{}
	}
	return m.Inspections
}

func toggles() []toggle {
	return []toggle{
		{"agent.dnsPacketCapture",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.DNSPacketCaptureEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { s.Agent.DNSPacketCapture = off() }},
		{"agent.dnsFullAnswers",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.DNSFullAnswersEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { s.Agent.DNSFullAnswers = off() }},
		{"agent.usdt",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.USDTEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { s.Agent.USDT = off() }},
		{"agent.uprobeMulti",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.UprobeMultiEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { s.Agent.UprobeMulti = off() }},
		{"agent.continuousProfiling",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.ContinuousProfilingEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { s.Agent.ContinuousProfiling = off() }},
		{"agent.sockOpsRTT",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.SockOpsRTTEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { s.Agent.SockOpsRTT = off() }},
		{"agent.metrics.enabled",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.Metrics.MetricsEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { metricsOf(s).Enabled = off() }},
		{"agent.metrics.nativeHistograms",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.Metrics.NativeHistogramsEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { metricsOf(s).NativeHistograms = off() }},
		{"agent.metrics.kernelAggregation",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.Metrics.KernelAggregationEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { metricsOf(s).KernelAggregation = off() }},
		{"agent.metrics.filesystem",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.Metrics.FilesystemEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { metricsOf(s).Filesystem = off() }},
		{"agent.metrics.inspections.enabled",
			func(s *podtracev1alpha1.TracerConfigSpec) bool { return s.Agent.Metrics.InspectionsEnabled() },
			func(s *podtracev1alpha1.TracerConfigSpec) { inspectionsOf(s).Enabled = off() }},
		{"agent.metrics.inspections.alerts",
			func(s *podtracev1alpha1.TracerConfigSpec) bool {
				return s.Agent.Metrics.InspectionsSpec().RaiseAlerts()
			},
			func(s *podtracev1alpha1.TracerConfigSpec) { inspectionsOf(s).Alerts = off() }},
	}
}

func TestEveryToggleIsOnWhenLeftOut(t *testing.T) {
	for _, tg := range toggles() {
		t.Run(tg.path, func(t *testing.T) {
			if !tg.read(&podtracev1alpha1.TracerConfigSpec{}) {
				t.Errorf("%s reads off on an empty spec; a TracerConfig written without the "+
					"chart, or created by the operator's bootstrap, would run without it", tg.path)
			}
		})
	}
}

func TestEveryToggleIsOnInAnEmptyBlock(t *testing.T) {
	spec := &podtracev1alpha1.TracerConfigSpec{}
	inspectionsOf(spec)
	for _, tg := range toggles() {
		if !tg.read(spec) {
			t.Errorf("%s reads off when its block is present but empty", tg.path)
		}
	}
}

func TestAnExplicitFalseIsKept(t *testing.T) {
	for _, tg := range toggles() {
		t.Run(tg.path, func(t *testing.T) {
			spec := &podtracev1alpha1.TracerConfigSpec{}
			tg.turnOff(spec)
			if tg.read(spec) {
				t.Errorf("%s reads on after being set to false; an opt-out would be ignored", tg.path)
			}
		})
	}
}

func TestAnExplicitTrueIsKept(t *testing.T) {
	spec := &podtracev1alpha1.TracerConfigSpec{}
	spec.Agent.ContinuousProfiling = on()
	metricsOf(spec).Enabled = on()
	inspectionsOf(spec).Enabled = on()
	if !spec.Agent.ContinuousProfilingEnabled() || !spec.Agent.Metrics.MetricsEnabled() ||
		!spec.Agent.Metrics.InspectionsEnabled() {
		t.Error("an explicit true was not read as on")
	}
}

func TestInspectionsAreOffWheneverThePlaneIs(t *testing.T) {
	spec := &podtracev1alpha1.TracerConfigSpec{}
	metricsOf(spec).Enabled = off()
	inspectionsOf(spec).Enabled = on()
	if spec.Agent.Metrics.InspectionsEnabled() {
		t.Error("inspections read on with the metrics plane off; every rule would evaluate " +
			"an empty surface and report healthy")
	}
}

func TestANilInspectionsBlockHasNoSpec(t *testing.T) {
	var m *podtracev1alpha1.AgentMetricsSpec
	if m.InspectionsSpec() != nil {
		t.Error("a nil metrics block returned an inspections block")
	}
	if (&podtracev1alpha1.AgentMetricsSpec{}).InspectionsSpec() != nil {
		t.Error("an empty metrics block returned an inspections block it does not have")
	}
}
