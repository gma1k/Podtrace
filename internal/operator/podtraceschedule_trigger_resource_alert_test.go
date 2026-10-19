package operator

import (
	"testing"
	"time"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
)

func TestResourceAlertEventFiresResourceAlertTrigger(t *testing.T) {
	sources := []podtracev1alpha1.TriggerSource{{Kind: podtracev1alpha1.TriggerSourceResourceAlert}}

	for _, source := range []string{alerting.AlertSourceResourceMonitor, alerting.AlertSourceResourceMonitorBPF} {
		t.Run(source, func(t *testing.T) {
			ev := alerting.BuildAlertEvent(&alerting.Alert{
				Severity:  alerting.MapResourceAlertLevel(2),
				Title:     "Resource Limit critical: memory",
				Source:    source,
				PodName:   "web-0",
				Namespace: "shop",
				Context:   map[string]interface{}{"cgroup_path": "/sys/fs/cgroup/kubepods/pod-a"},
			}, time.Now())
			if ev == nil {
				t.Fatal("BuildAlertEvent returned nil for a resource alert on a known pod")
			}

			parsed, ok := parseAlertEvent(ev)
			if !ok {
				t.Fatalf("parseAlertEvent rejected the resource alert Event: %+v", ev)
			}
			if parsed.Kind != podtracev1alpha1.TriggerSourceResourceAlert {
				t.Errorf("kind = %q, want %q", parsed.Kind, podtracev1alpha1.TriggerSourceResourceAlert)
			}
			if parsed.Namespace != "shop" || parsed.PodName != "web-0" {
				t.Errorf("parsed target = %s/%s, want shop/web-0", parsed.Namespace, parsed.PodName)
			}
			if !matchesTriggerSources(parsed, sources) {
				t.Error("a critical resource alert did not match a ResourceAlert trigger at the default severity")
			}
		})
	}
}
