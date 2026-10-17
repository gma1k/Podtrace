package chart_test

import (
	"bytes"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/operator"
)

func renderedTracerConfig(t *testing.T, setFlags ...string) *podtracev1alpha1.TracerConfig {
	t.Helper()
	for _, doc := range bytes.Split(renderChart(t, setFlags...), []byte("\n---")) {
		var cm struct {
			Kind     string                `json:"kind"`
			Metadata struct{ Name string } `json:"metadata"`
			Data     map[string]string     `json:"data"`
		}
		if err := yaml.Unmarshal(doc, &cm); err != nil || cm.Kind != "ConfigMap" {
			continue
		}
		raw, ok := cm.Data["tracerconfig.yaml"]
		if !ok {
			continue
		}
		var tc podtracev1alpha1.TracerConfig
		if err := yaml.UnmarshalStrict([]byte(raw), &tc); err != nil {
			t.Fatalf("the chart's TracerConfig does not decode into the API type: %v\n%s", err, raw)
		}
		return &tc
	}
	t.Fatal("no TracerConfig in the rendered chart")
	return nil
}

type resolvedAgent struct {
	DNSPacketCapture, DNSFullAnswers, USDT, UprobeMulti, ContinuousProfiling, SockOpsRTT bool
	Metrics, NativeHistograms, KernelAggregation, Inspections, Alerts                    bool
	ExcludeNamespaces                                                                    []string
	Tolerations                                                                          []corev1.Toleration
}

func resolve(tc *podtracev1alpha1.TracerConfig) resolvedAgent {
	a := &tc.Spec.Agent
	r := resolvedAgent{
		DNSPacketCapture:    a.DNSPacketCaptureEnabled(),
		DNSFullAnswers:      a.DNSFullAnswersEnabled(),
		USDT:                a.USDTEnabled(),
		UprobeMulti:         a.UprobeMultiEnabled(),
		ContinuousProfiling: a.ContinuousProfilingEnabled(),
		SockOpsRTT:          a.SockOpsRTTEnabled(),
		Metrics:             a.Metrics.MetricsEnabled(),
		NativeHistograms:    a.Metrics.NativeHistogramsEnabled(),
		KernelAggregation:   a.Metrics.KernelAggregationEnabled(),
		Inspections:         a.Metrics.InspectionsEnabled(),
		Alerts:              a.Metrics.InspectionsSpec().RaiseAlerts(),
	}
	if a.Metrics != nil {
		r.ExcludeNamespaces = a.Metrics.ExcludeNamespaces
	}
	r.Tolerations = tc.Spec.Tolerations
	return r
}

func TestTheChartAndTheOperatorBootstrapRunTheSameAgent(t *testing.T) {
	chart := resolve(renderedTracerConfig(t))
	bootstrap := resolve(operator.NewBootstrapTracerConfig("default", "ghcr.io/gma1k/podtrace:test", "podtrace-system"))

	if !reflect.DeepEqual(chart, bootstrap) {
		t.Errorf("a chart install runs %+v\nbut an OLM or raw-manifest install runs %+v\n\n"+
			"Both are the default install of the same product; a default changed in "+
			"values.yaml has to change in the API defaults too, or the two drift.", chart, bootstrap)
	}
}

func TestTheChartDefaultIsTheFullPlane(t *testing.T) {
	got := resolve(renderedTracerConfig(t))
	v := reflect.ValueOf(got)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.Bool && !v.Field(i).Bool() {
			t.Errorf("%s is off in a default chart install", v.Type().Field(i).Name)
		}
	}
}

func TestTurningAPlaneOffInValuesWritesAnExplicitFalse(t *testing.T) {
	for _, tt := range []struct {
		set  string
		read func(*podtracev1alpha1.TracerConfig) *bool
	}{
		{"agent.metrics.enabled=false", func(tc *podtracev1alpha1.TracerConfig) *bool {
			if tc.Spec.Agent.Metrics == nil {
				return nil
			}
			return tc.Spec.Agent.Metrics.Enabled
		}},
		{"agent.metrics.inspections.enabled=false", func(tc *podtracev1alpha1.TracerConfig) *bool {
			if i := tc.Spec.Agent.Metrics.InspectionsSpec(); i != nil {
				return i.Enabled
			}
			return nil
		}},
		{"agent.metrics.kernelAggregation=false", func(tc *podtracev1alpha1.TracerConfig) *bool {
			if tc.Spec.Agent.Metrics == nil {
				return nil
			}
			return tc.Spec.Agent.Metrics.KernelAggregation
		}},
		{"agent.continuousProfiling=false", func(tc *podtracev1alpha1.TracerConfig) *bool {
			return tc.Spec.Agent.ContinuousProfiling
		}},
		{"agent.sockOpsRTT=false", func(tc *podtracev1alpha1.TracerConfig) *bool {
			return tc.Spec.Agent.SockOpsRTT
		}},
	} {
		t.Run(tt.set, func(t *testing.T) {
			got := tt.read(renderedTracerConfig(t, tt.set))
			if got == nil || *got {
				t.Errorf("--set %s rendered %v, want an explicit false; the CRD defaults a left-out "+
					"field to on, so leaving it out would switch it on", tt.set, got)
			}
		})
	}
}

func TestEveryInspectionThresholdInValuesReachesTheTracerConfig(t *testing.T) {
	tc := renderedTracerConfig(t,
		"agent.metrics.inspections.thresholds.cpuBlockedMean=250ms",
		"agent.metrics.inspections.thresholds.poolUtilizationPercent=70",
		"agent.metrics.inspections.thresholds.errorRatePercent=3",
	)
	th := tc.Spec.Agent.Metrics.InspectionsSpec().Thresholds
	if th == nil || th.CPUBlockedMean == nil || th.CPUBlockedMean.Duration.String() != "250ms" ||
		th.PoolUtilizationPercent == nil || *th.PoolUtilizationPercent != 70 ||
		th.ErrorRatePercent == nil || *th.ErrorRatePercent != 3 {
		t.Errorf("thresholds = %+v; a value set in values.yaml was dropped on the way to the "+
			"TracerConfig", th)
	}
}
