// Package operator implements the podtrace Kubernetes operator's control
// plane: three reconcilers that watch TracerConfig, PodTrace, and
// PodTraceSession CRs and drive the corresponding infrastructure.
package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Label keys. "podtrace.io/managed-by=podtrace-operator" is the single
// source of truth for "this object is owned by the operator", used for
// bulk cleanup and for informer filters.
const (
	LabelManagedBy      = "podtrace.io/managed-by"
	LabelComponent      = "podtrace.io/component"
	LabelTracerConfig   = "podtrace.io/tracer-config"
	LabelPodTraceName   = "podtrace.io/podtrace"
	LabelPodTraceNS     = "podtrace.io/podtrace-namespace"
	LabelSessionName    = "podtrace.io/session"
	LabelSessionNS      = "podtrace.io/session-namespace"
	LabelExporterConfig = "podtrace.io/exporter-config"
	LabelNodeName       = "podtrace.io/node"
	LabelSchedule       = "podtrace.io/schedule"

	ManagedByValue = "podtrace-operator"

	ComponentAgent   = "agent"
	ComponentSession = "session"
	ComponentBundle  = "exporter-bundle"
)

// Annotations a triggered session carries for the Job to read back.
const (
	AnnotationTriggeredBy     = "podtrace.io/triggered-by"
	AnnotationTriggerSeverity = "podtrace.io/trigger-severity"
	AnnotationTriggerPod      = "podtrace.io/trigger-pod"
	AnnotationTriggeredAt     = "podtrace.io/triggered-at"

	AnnotationTriggerReason = "podtrace.io/trigger-reason"
)

// Condition types reported on CR .status.conditions.
const (
	ConditionReady          = "Ready"
	ConditionReconciled     = "Reconciled"
	ConditionDegraded       = "Degraded"
	ConditionPaused         = "Paused"
	ConditionReportUploaded = "ReportUploaded"
	ConditionExported       = "Exported"
	ConditionReferenced     = "Referenced"
	ConditionConflict       = "Conflict"

	ConditionPolicyApplied = "PolicyApplied"
)

// agentObjectName derives the per-TracerConfig name for an agent-owned
// object from its base name.
func agentObjectName(base, tracerConfigName string) string {
	if tracerConfigName == DefaultTracerConfigName {
		return base
	}
	return base + "-" + tracerConfigName
}

// AgentDaemonSetName is the DaemonSet TracerConfigReconciler creates for
// the named config.
func AgentDaemonSetName(tracerConfigName string) string {
	return agentObjectName("podtrace-agent", tracerConfigName)
}

// AgentServiceAccountName is the ServiceAccount the agent DaemonSet runs as.
//
// Per-config rather than shared: it is the agent fleet's identity in audit
// logs, and it is what a future per-fleet RBAC restriction would attach to.
func AgentServiceAccountName(tracerConfigName string) string {
	return agentObjectName("podtrace-agent", tracerConfigName)
}

func SessionServiceAccountName(sessionUID types.UID) string {
	return "podtrace-session-" + shortUID(sessionUID)
}

func SessionReportRoleName(sessionUID types.UID) string {
	return "podtrace-session-report-" + shortUID(sessionUID)
}

func SessionReportRoleBindingName(sessionUID types.UID) string {
	return "podtrace-session-report-" + shortUID(sessionUID)
}

// SessionPodReadRoleName / SessionPodReadRoleBindingName name the per-namespace
// Role+RoleBinding granting the session SA pods/events read in each extra
// namespace a cross-namespace session targets (beyond its own).
func SessionPodReadRoleName(sessionUID types.UID) string {
	return "podtrace-session-podread-" + shortUID(sessionUID)
}

func SessionPodReadRoleBindingName(sessionUID types.UID) string {
	return "podtrace-session-podread-" + shortUID(sessionUID)
}

// AgentClusterRoleName is the ClusterRole granting the agent read access to
// PodTrace CRs cluster-wide and status-patch on the same.
func AgentClusterRoleName(tracerConfigName string) string {
	return agentObjectName("podtrace-agent", tracerConfigName)
}

// AgentClusterRoleBindingName binds AgentClusterRoleName to AgentServiceAccountName.
func AgentClusterRoleBindingName(tracerConfigName string) string {
	return agentObjectName("podtrace-agent", tracerConfigName)
}

func AgentBundleRoleName(tracerConfigName string) string {
	return agentObjectName("podtrace-agent-bundles", tracerConfigName)
}

func AgentBundleRoleBindingName(tracerConfigName string) string {
	return agentObjectName("podtrace-agent-bundles", tracerConfigName)
}

func OperatorWebhookServiceName() string { return "podtrace-webhook" }

// SessionJobName returns a per-(session,node) Job name that fits the
// 63-character DNS limit AND is unique per node.
func SessionJobName(sessionUID types.UID, nodeName string) string {
	prefix := "pts-" + shortUID(sessionUID) + "-"
	sum := sha256.Sum256([]byte(nodeName))
	suffix := hex.EncodeToString(sum[:])[:8]

	budget := 63 - len(prefix) - 1 - len(suffix)
	if budget < 0 {
		budget = 0
	}
	node := sanitiseDNS(nodeName)
	if len(node) > budget {
		node = node[:budget]
	}
	node = strings.TrimRight(node, "-.")

	if node == "" {
		return strings.TrimRight(prefix+suffix, "-.")
	}
	return strings.TrimRight(prefix+node+"-"+suffix, "-.")
}

func ExporterBundleName(exporterUID types.UID) string {
	return "pt-bundle-" + shortUID(exporterUID)
}

const BundleAnnotationSourceRef = "podtrace.io/exporterconfig-ref"

func ManagedObjectMeta(name, namespace, component string, extraLabels map[string]string) metav1.ObjectMeta {
	labels := map[string]string{
		LabelManagedBy: ManagedByValue,
		LabelComponent: component,
	}
	for k, v := range extraLabels {
		labels[k] = v
	}
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
	}
}

// shortUID returns the first 12 characters of a UID string — enough to
// stay collision-resistant within a cluster while keeping derived names
// inside Kubernetes' 63-character limit.
func shortUID(uid types.UID) string {
	s := string(uid)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func sanitiseDNS(in string) string {
	b := make([]byte, 0, len(in))
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z':
			b = append(b, byte(r))
		case r >= '0' && r <= '9':
			b = append(b, byte(r))
		case r == '-':
			b = append(b, '-')
		case r >= 'A' && r <= 'Z':
			b = append(b, byte(r+('a'-'A')))
		default:
			b = append(b, '-')
		}
	}
	// Trim leading/trailing '-', DNS-1123 forbids them at label ends.
	start, end := 0, len(b)
	for start < end && b[start] == '-' {
		start++
	}
	for end > start && b[end-1] == '-' {
		end--
	}
	if start == end {
		return "node"
	}
	return string(b[start:end])
}
