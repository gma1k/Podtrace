package operator

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/reportsink/objectstore"
)

const reportUploaderContainerName = "report-uploader"

// reportUploadObservation is the operator's view of one session's
// objectStore uploader sidecar across all of its node Jobs.
type reportUploadObservation struct {
	ResolvedURI string

	Terminated bool

	Succeeded bool

	Attempts int32

	UploaderDisabled bool
}

func harvestReportLocation(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, systemNS string) (reportUploadObservation, error) {
	if s == nil || s.Spec.ReportRef == nil || s.Spec.ReportRef.ObjectStore == nil {
		return reportUploadObservation{}, nil
	}

	var pods corev1.PodList
	if err := c.List(ctx, &pods,
		client.InNamespace(systemNS),
		client.MatchingLabels{
			LabelSessionName: s.Name,
			LabelSessionNS:   s.Namespace,
		},
	); err != nil {
		return reportUploadObservation{}, fmt.Errorf("list session pods: %w", err)
	}

	var obs reportUploadObservation
	hasUploader := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, c := range pod.Spec.InitContainers {
			if c.Name == reportUploaderContainerName {
				hasUploader = true
			}
		}
		for _, cs := range pod.Status.InitContainerStatuses {
			if cs.Name != reportUploaderContainerName {
				continue
			}
			hasUploader = true
			if cs.RestartCount > obs.Attempts {
				obs.Attempts = cs.RestartCount
			}
			if cs.State.Terminated == nil {
				continue
			}
			msg := bestTerminationMessage(cs)
			obs.Terminated = true
			if cs.State.Terminated.ExitCode == 0 && msg != "" {
				obs.ResolvedURI = msg
				obs.Succeeded = true
				return obs, nil
			}
			obs.ResolvedURI = msg
			return obs, nil
		}
	}
	obs.UploaderDisabled = len(pods.Items) > 0 && !hasUploader
	return obs, nil
}

func applyReportUploadStatus(s *podtracev1alpha1.PodTraceSession, obs reportUploadObservation) {
	if s == nil || s.Spec.ReportRef == nil || s.Spec.ReportRef.ObjectStore == nil {
		return
	}
	now := metav1.Now()
	s.Status.ReportAttempts = obs.Attempts

	switch {
	case obs.UploaderDisabled:
		s.Status.ReportFailureReason = ""
		s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
			Type:               ConditionReportUploaded,
			Status:             metav1.ConditionFalse,
			Reason:             "UploaderDisabled",
			Message:            "the session pods have no report-uploader sidecar because TracerConfig spec.session.sidecarUploader is off; the report is not uploaded to object storage",
			LastTransitionTime: now,
			ObservedGeneration: s.Generation,
		})
	case !obs.Terminated:
		s.Status.ReportFailureReason = ""
		s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
			Type:               ConditionReportUploaded,
			Status:             metav1.ConditionUnknown,
			Reason:             "UploadPending",
			Message:            "sidecar has not terminated yet",
			LastTransitionTime: now,
			ObservedGeneration: s.Generation,
		})
	case obs.Succeeded:
		s.Status.ReportLocation = obs.ResolvedURI
		s.Status.ReportFailureReason = ""
		s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
			Type:               ConditionReportUploaded,
			Status:             metav1.ConditionTrue,
			Reason:             "ObjectStoreUploadSucceeded",
			Message:            obs.ResolvedURI,
			LastTransitionTime: now,
			ObservedGeneration: s.Generation,
		})
	default:
		s.Status.ReportFailureReason = classifyUploadFailure(obs.ResolvedURI)
		s.Status.Conditions = upsertCondition(s.Status.Conditions, metav1.Condition{
			Type:               ConditionReportUploaded,
			Status:             metav1.ConditionFalse,
			Reason:             "ObjectStoreUploadFailed",
			Message:            obs.ResolvedURI,
			LastTransitionTime: now,
			ObservedGeneration: s.Generation,
		})
	}
}

// classifyUploadFailure maps a sidecar's stderr / termination message
// into a stable reason enum. The mapping is intentionally pattern-based
// rather than typed-error-based because the message arrives as a string
// from another process (the sidecar) — there is no in-process error
// chain to .Is() / .As() against.
func classifyUploadFailure(message string) podtracev1alpha1.ReportFailureReason {
	if message == "" {
		return podtracev1alpha1.ReportFailureReasonUnknown
	}
	m := strings.ToLower(message)

	switch {
	case strings.Contains(m, "no such bucket"),
		strings.Contains(m, "nosuchbucket"),
		strings.Contains(m, "404"),
		strings.Contains(m, "storage: bucket doesn't exist"),
		strings.Contains(m, "containernotfound"):
		return podtracev1alpha1.ReportFailureReasonBucketNotFound
	case strings.Contains(m, "access denied"),
		strings.Contains(m, "accessdenied"),
		strings.Contains(m, "forbidden"),
		strings.Contains(m, "403"),
		strings.Contains(m, "authorizationfailed"),
		strings.Contains(m, "signaturedoesnotmatch"):
		return podtracev1alpha1.ReportFailureReasonAccessDenied
	case strings.Contains(m, "credential"),
		strings.Contains(m, "unauthorized"),
		strings.Contains(m, "401"),
		strings.Contains(m, "no credentials"),
		strings.Contains(m, "missing"+"credentials"),
		strings.Contains(m, "default credentials"):
		return podtracev1alpha1.ReportFailureReasonCredentialMissing
	case strings.Contains(m, "timeout"),
		strings.Contains(m, "deadline exceeded"),
		strings.Contains(m, "i/o timeout"),
		strings.Contains(m, "connection refused"),
		strings.Contains(m, "no such host"),
		strings.Contains(m, "tls handshake"):
		return podtracev1alpha1.ReportFailureReasonNetworkTimeout
	case isInvalidURIMessage(m):
		return podtracev1alpha1.ReportFailureReasonInvalidURI
	default:
		return podtracev1alpha1.ReportFailureReasonUnknown
	}
}

func isInvalidURIMessage(lowered string) bool {
	return strings.Contains(lowered, "unsupported uri scheme") ||
		strings.Contains(lowered, "must include scheme and host") ||
		strings.Contains(lowered, "must include a container") ||
		strings.Contains(lowered, "parse uri") ||
		strings.Contains(lowered, "object key is empty")
}

var _ = objectstore.SchemeS3

// bestTerminationMessage picks the most informative termination
// message between the container's current and previous terminated
// states.
func bestTerminationMessage(cs corev1.ContainerStatus) string {
	current := ""
	if cs.State.Terminated != nil {
		current = strings.TrimSpace(cs.State.Terminated.Message)
	}
	previous := ""
	if cs.LastTerminationState.Terminated != nil {
		previous = strings.TrimSpace(cs.LastTerminationState.Terminated.Message)
	}

	if current != "" && !isKubeletShutdownMessage(current) {
		return current
	}
	if previous != "" {
		return previous
	}
	return current
}

// isKubeletShutdownMessage reports whether a message looks like the
// generic placeholder kubelet writes when it SIGKILLs a sidecar
// during pod shutdown rather than wording produced by our uploader.
func isKubeletShutdownMessage(msg string) bool {
	lc := strings.ToLower(msg)
	return strings.Contains(lc, "container could not be located when the pod was terminated") ||
		strings.Contains(lc, "the node was lost") ||
		strings.Contains(lc, "containerstatusunknown")
}
