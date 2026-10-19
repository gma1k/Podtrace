package operator

import (
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestFirstDegradedNodeReportsADeliveryFailureOnAReadyNode(t *testing.T) {
	node, msg, reason, ok := firstDegradedNode([]podtracev1alpha1.PodTraceNodeStatus{
		{Node: "node-a", Ready: true},
		{Node: "node-b", Ready: true, Reason: podtracev1alpha1.NodeStatusReasonExporterDeliveryFailed, Message: "otlp exporter is not delivering spans"},
	})
	if !ok || node != "node-b" || reason != podtracev1alpha1.NodeStatusReasonExporterDeliveryFailed || msg != "otlp exporter is not delivering spans" {
		t.Fatalf("got node=%q reason=%q msg=%q ok=%v", node, reason, msg, ok)
	}
}

func TestFirstDegradedNodePrefersAnUnreadyNodeOverADeliveryFailure(t *testing.T) {
	node, _, reason, ok := firstDegradedNode([]podtracev1alpha1.PodTraceNodeStatus{
		{Node: "node-a", Ready: true, Reason: podtracev1alpha1.NodeStatusReasonExporterDeliveryFailed, Message: "delivery"},
		{Node: "node-b", Ready: false, Reason: podtracev1alpha1.NodeStatusReasonBundleLoadFailed, Message: "load bundle: missing"},
	})
	if !ok || node != "node-b" || reason != podtracev1alpha1.NodeStatusReasonBundleLoadFailed {
		t.Fatalf("got node=%q reason=%q ok=%v, want the unready node first", node, reason, ok)
	}
}

func TestFirstDegradedNodeIgnoresHealthyReadyRows(t *testing.T) {
	if _, _, _, ok := firstDegradedNode([]podtracev1alpha1.PodTraceNodeStatus{
		{Node: "node-a", Ready: true},
		{Node: "node-b", Ready: true, Message: "informational"},
	}); ok {
		t.Fatal("healthy Ready rows must not degrade the PodTrace")
	}
}

func TestFirstDegradedNodePicksTheFirstDeliveryFailureByName(t *testing.T) {
	node, _, _, ok := firstDegradedNode([]podtracev1alpha1.PodTraceNodeStatus{
		{Node: "node-c", Ready: true, Reason: podtracev1alpha1.NodeStatusReasonExporterDeliveryFailed, Message: "c"},
		{Node: "node-a", Ready: true, Reason: podtracev1alpha1.NodeStatusReasonExporterDeliveryFailed, Message: "a"},
	})
	if !ok || node != "node-a" {
		t.Fatalf("node = %q, want node-a", node)
	}
}
