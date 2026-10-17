package agent

import (
	"testing"

	"go.opentelemetry.io/otel/attribute"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/events"
)

func errorRateExporter(threshold int32) *sdkEventExporter {
	return &sdkEventExporter{
		name:       "otlp",
		cr:         CRKey{Namespace: "obs", Name: "flight-recorder"},
		thresholds: &PolicyThresholds{ErrorRatePercent: &threshold},
		metrics:    &Metrics{detectors: map[CRKey]*errorRateDetector{}},
	}
}

func failingEvent() *events.Event {
	return &events.Event{
		Type:    events.EventHTTPResp,
		Error:   503,
		Details: "503",
		K8s: &events.K8sMetadata{
			Namespace: "prod",
			PodName:   "checkout-7f",
		},
	}
}

func hasBoolAttribute(attrs []attribute.KeyValue, key string) bool {
	for _, attr := range attrs {
		if string(attr.Key) == key && attr.Value.AsBool() {
			return true
		}
	}
	return false
}

func TestRaiseTriggerAlert_DeliversErrorRateAlert(t *testing.T) {
	sender := withCapturingGlobalManager(t)
	e := errorRateExporter(5)

	e.raiseTriggerAlert(failingEvent(), alerting.AlertSourceErrorRate, alerting.SeverityCritical, "error-rate threshold breached")

	alert := sender.await(t)
	if alert == nil {
		return
	}
	if alert.Source != alerting.AlertSourceErrorRate {
		t.Errorf("source = %q, want %q", alert.Source, alerting.AlertSourceErrorRate)
	}
	if alert.Severity != alerting.SeverityCritical {
		t.Errorf("severity = %q, want critical", alert.Severity)
	}
	if alert.Title != "error-rate threshold breached" {
		t.Errorf("title = %q", alert.Title)
	}
	if alert.PodName != "checkout-7f" || alert.Namespace != "prod" {
		t.Errorf("pod identity = %s/%s, want prod/checkout-7f", alert.Namespace, alert.PodName)
	}
}

func TestRaiseTriggerAlert_SkipsEventsWithoutPodIdentity(t *testing.T) {
	cases := map[string]*events.Event{
		"no pod metadata": {Type: events.EventTCPRecv, Error: 1},
		"empty pod name":  {Type: events.EventTCPRecv, Error: 1, K8s: &events.K8sMetadata{Namespace: "prod"}},
		"empty namespace": {Type: events.EventTCPRecv, Error: 1, K8s: &events.K8sMetadata{PodName: "checkout-7f"}},
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			sender := withCapturingGlobalManager(t)
			e := errorRateExporter(5)
			e.raiseTriggerAlert(ev, alerting.AlertSourceErrorRate, alerting.SeverityCritical, "error-rate threshold breached")
			sender.expectNoAlert(t)
		})
	}
}

func TestRaiseTriggerAlert_NoGlobalManagerIsSafe(t *testing.T) {
	withoutGlobalManager(t)
	e := errorRateExporter(5)
	e.raiseTriggerAlert(failingEvent(), alerting.AlertSourceErrorRate, alerting.SeverityCritical, "error-rate threshold breached")
}

func TestAppendThresholdAttributes_ErrorRateBreachRaisesTriggerAlert(t *testing.T) {
	sender := withCapturingGlobalManager(t)
	e := errorRateExporter(5)

	breachedAt := 0
	for i := 1; i <= errorRateMinSampleSize; i++ {
		attrs := e.appendThresholdAttributes(nil, failingEvent())
		if hasBoolAttribute(attrs, "podtrace.threshold.error_rate.breached") {
			breachedAt = i
			break
		}
	}
	if breachedAt != errorRateMinSampleSize {
		t.Fatalf("error rate should breach on observation %d, got %d", errorRateMinSampleSize, breachedAt)
		return
	}

	alert := sender.await(t)
	if alert == nil {
		return
	}
	if alert.Source != alerting.AlertSourceErrorRate {
		t.Errorf("source = %q, want %q", alert.Source, alerting.AlertSourceErrorRate)
	}
	if alert.Severity != alerting.SeverityCritical {
		t.Errorf("severity = %q, want critical", alert.Severity)
	}
	if alert.PodName != "checkout-7f" || alert.Namespace != "prod" {
		t.Errorf("alert must name the failing pod, got %s/%s", alert.Namespace, alert.PodName)
	}
}

func TestAppendThresholdAttributes_ErrorRateBelowSampleSizeRaisesNothing(t *testing.T) {
	sender := withCapturingGlobalManager(t)
	e := errorRateExporter(5)

	for i := 0; i < errorRateMinSampleSize-1; i++ {
		attrs := e.appendThresholdAttributes(nil, failingEvent())
		if hasBoolAttribute(attrs, "podtrace.threshold.error_rate.breached") {
			t.Fatalf("observation %d breached below the minimum sample size", i)
			return
		}
	}
	sender.expectNoAlert(t)
}
