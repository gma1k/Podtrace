package agent

import (
	"testing"

	"github.com/gma1k/podtrace/internal/metricsexporter"
)

func TestAgentRegistryServesL7DecoderMetrics(t *testing.T) {
	metricsexporter.RecordL7DecoderRetainedBytes("agent_test", 1)
	metricsexporter.RecordL7DecoderDrops("agent_test", "agent_test", 1)
	families, err := NewMetrics().Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"podtrace_l7_decoder_drops_total":    false,
		"podtrace_l7_decoder_retained_bytes": false,
	}
	for _, f := range families {
		if _, ok := want[f.GetName()]; ok {
			want[f.GetName()] = true
		}
	}
	for name, served := range want {
		if !served {
			t.Errorf("%s is not served by the agent registry", name)
		}
	}
}

func TestTwoAgentRegistriesShareTheL7Collectors(t *testing.T) {
	NewMetrics()
	NewMetrics()
}
