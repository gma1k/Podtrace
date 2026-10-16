package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose"
	"github.com/gma1k/podtrace/internal/hostfs"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/redactor"
	"go.uber.org/zap"
)

func finalizeDiagnoseOutputs(ctx context.Context, report string, d *diagnose.Diagnostician) {
	if summaryFile == "" && terminationMessagePath == "" && reportTo == "" {
		return
	}
	finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalizeGracePeriod)
	defer cancel()
	node := os.Getenv("NODE_NAME")
	summary := computeSessionSummary(d, node)
	if err := emitSessionArtifacts(finalizeCtx, summary, report); err != nil {
		logger.Warn("emit session artifacts", zap.Error(err))
	}
}

// finalizeGracePeriod bounds report/summary delivery after shutdown began so
// a hung sink cannot exceed the pod's termination grace period.
const finalizeGracePeriod = 30 * time.Second

// SessionSummary is the compact, machine-readable summary the CLI emits
// at the end of --diagnose.
type SessionSummary struct {
	TotalEvents    int64  `json:"totalEvents"`
	DNSEvents      int64  `json:"dnsEvents,omitempty"`
	NetEvents      int64  `json:"netEvents,omitempty"`
	FSEvents       int64  `json:"fsEvents,omitempty"`
	CPUEvents      int64  `json:"cpuEvents,omitempty"`
	ProcEvents     int64  `json:"procEvents,omitempty"`
	ErrorsDetected int32  `json:"errorsDetected,omitempty"`
	DurationMS     int64  `json:"durationMs,omitempty"`
	Node           string `json:"node,omitempty"`
}

// computeSessionSummary rolls up a Diagnostician's observed events into
// the small struct Kubernetes surfaces in pod status.
func computeSessionSummary(d *diagnose.Diagnostician, node string) SessionSummary {
	events := d.GetEvents()
	summary := SessionSummary{
		TotalEvents: int64(len(events)),
		DurationMS:  d.EndTime().Sub(d.StartTime()).Milliseconds(),
		Node:        node,
	}
	for _, ev := range events {
		if ev == nil {
			continue
		}
		switch categoryForEventType(ev.TypeString()) {
		case "dns":
			summary.DNSEvents++
		case "net":
			summary.NetEvents++
		case "fs":
			summary.FSEvents++
		case "cpu":
			summary.CPUEvents++
		case "proc":
			summary.ProcEvents++
		}
		if ev.IsError() {
			summary.ErrorsDetected++
		}
	}
	return summary
}

// categoryForEventType maps the internal events.Event.TypeString() value
// (uppercase category names like DNS/NET/FS/CPU/PROC) into the five
// top-level buckets the PodTrace CRD exposes.
func categoryForEventType(typeStr string) string {
	switch strings.ToLower(typeStr) {
	case "dns":
		return "dns"
	case "net":
		return "net"
	case "fs":
		return "fs"
	case "cpu":
		return "cpu"
	case "proc":
		return "proc"
	}
	return ""
}

// emitSessionArtifacts writes the three session artifacts that the
// operator expects when a diagnose session completes:
//
//   - summaryFile: full-fat JSON including per-category breakdown.
//   - terminationMessagePath: compact JSON (<=4KB) surfaced in pod status
//     via Kubernetes' terminationMessagePath contract.
//   - reportTo: patches a ConfigMap or Secret with the human-readable
//     report text (the "full artifact" per spec.reportRef).
func emitSessionArtifacts(ctx context.Context, summary SessionSummary, reportText string) error {
	var errs []string

	if summaryFile != "" {
		if err := writeSummaryFile(summaryFile, summary); err != nil {
			errs = append(errs, fmt.Sprintf("summary-file: %v", err))
		}
	}
	if terminationMessagePath != "" {
		if err := writeTerminationMessage(terminationMessagePath, summary); err != nil {
			errs = append(errs, fmt.Sprintf("termination-message: %v", err))
		}
	}
	if reportTo != "" {
		if err := uploadReport(ctx, reportTo, reportText); err != nil {
			errs = append(errs, fmt.Sprintf("report-to: %v", err))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("session artifact emission: %s", strings.Join(errs, "; "))
}

// k8sTerminationLog is the fixed kubelet termination-message path, the one
// artifact target that legitimately lives outside the session run directory.
const k8sTerminationLog = "/dev/termination-log"

// writeArtifactFile writes a session artifact, confining it to
// config.ArtifactBaseDir() when the operator has set one (the privileged Job
// context).
func writeArtifactFile(path string, data []byte, perm os.FileMode) error {
	base := config.ArtifactBaseDir()
	if base == "" || path == k8sTerminationLog {
		return hostfs.WriteFile(path, data, perm)
	}
	return hostfs.WriteFileWithin(base, path, data, perm)
}

// writeSummaryFile writes the JSON summary to the given path. Used by
// the sidecar uploader (reads this file) as the source of truth for
// summary content when the CLI succeeds.
func writeSummaryFile(path string, summary SessionSummary) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return writeArtifactFile(path, data, 0o600)
}

// writeTerminationMessage writes a compact JSON encoding of the summary
// so the apiserver surfaces it in Pod.Status.ContainerStatuses[].
// State.Terminated.Message.
func writeTerminationMessage(path string, summary SessionSummary) error {
	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	const maxTerminationBytes = 4096
	if len(data) > maxTerminationBytes {
		return fmt.Errorf("summary JSON %d bytes exceeds 4KB termination message limit", len(data))
	}
	return writeArtifactFile(path, data, 0o600)
}

var objectStoreReportFile = "/var/run/podtrace/report.txt"

// redactReportText scrubs the rendered report before it is persisted to any
// sink.
func redactReportText(reportText string) string {
	red, err := redactor.DefaultWithCustomRules(config.RedactCustomRules)
	if err != nil {
		logger.Warn("custom redaction rules invalid; redacting report with defaults only", zap.Error(err))
	}
	return red.RedactText(reportText)
}

func uploadReport(ctx context.Context, spec, reportText string) error {
	reportText = redactReportText(reportText)
	if strings.Contains(spec, "://") {

		if err := hostfs.WriteFileAtomic(objectStoreReportFile, []byte(reportText), 0o644); err != nil {
			return fmt.Errorf("write report file for sidecar: %w", err)
		}
		return nil
	}
	kind, namespace, name, err := parseReportToSpec(spec)
	if err != nil {
		return err
	}

	client, err := buildInClusterClient()
	if err != nil {
		return fmt.Errorf("build kubernetes client: %w", err)
	}

	writeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	key := reportDataKey()
	switch kind {
	case "configmap":
		return upsertReportConfigMap(writeCtx, client, namespace, name, key, reportText)
	case "secret":
		return upsertReportSecret(writeCtx, client, namespace, name, key, reportText)
	default:
		return fmt.Errorf("unsupported report-to kind %q (want configmap|secret)", kind)
	}
}

// parseReportToSpec breaks a string of the form "kind/namespace/name"
// into its three components.
func parseReportToSpec(spec string) (kind, namespace, name string, err error) {
	parts := strings.Split(spec, "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("report-to must be kind/namespace/name, got %q", spec)
	}
	for i, p := range parts {
		if strings.TrimSpace(p) == "" {
			return "", "", "", fmt.Errorf("report-to part %d is empty: %q", i, spec)
		}
	}
	return strings.ToLower(parts[0]), parts[1], parts[2], nil
}

// reportDataKey returns the ConfigMap/Secret data key the session report is
// written under.
func reportDataKey() string {
	node := os.Getenv("NODE_NAME")
	if node == "" {
		return "report.txt"
	}
	return "report-" + sanitizeReportKeySegment(node) + ".txt"
}

// sanitizeReportKeySegment maps a node name onto the characters a ConfigMap /
// Secret data key allows ([-._a-zA-Z0-9]).
func sanitizeReportKeySegment(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !isReportKeyByte(c) {
			b[i] = '-'
		}
	}
	return string(b)
}

// isReportKeyByte reports whether c is valid in a ConfigMap/Secret data key
// ([-._a-zA-Z0-9]).
func isReportKeyByte(c byte) bool {
	return c == '-' || c == '.' || c == '_' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

var reportSinkLabels = map[string]string{
	"podtrace.io/managed-by": "podtrace-cli",
	"podtrace.io/kind":       "session-report",
}

// upsertReportConfigMap writes reportText under the given per-node data key,
// creating the ConfigMap if absent.
func upsertReportConfigMap(ctx context.Context, client kubernetes.Interface, namespace, name, key, reportText string) error {
	cms := client.CoreV1().ConfigMaps(namespace)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing, err := cms.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: reportSinkLabels},
				Data:       map[string]string{key: reportText},
			}
			_, cerr := cms.Create(ctx, cm, metav1.CreateOptions{})
			if cerr == nil || !apierrors.IsAlreadyExists(cerr) {
				return cerr
			}
			existing, err = cms.Get(ctx, name, metav1.GetOptions{})
		}
		if err != nil {
			return err
		}
		if existing.Data == nil {
			existing.Data = map[string]string{}
		}
		existing.Data[key] = reportText
		_, uerr := cms.Update(ctx, existing, metav1.UpdateOptions{})
		return uerr
	})
	if err != nil {
		return fmt.Errorf("upsert report ConfigMap: %w", err)
	}
	return nil
}

// upsertReportSecret mirrors upsertReportConfigMap for Secret sinks.
func upsertReportSecret(ctx context.Context, client kubernetes.Interface, namespace, name, key, reportText string) error {
	secrets := client.CoreV1().Secrets(namespace)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing, err := secrets.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			sec := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: reportSinkLabels},
				Type:       corev1.SecretTypeOpaque,
				Data:       map[string][]byte{key: []byte(reportText)},
			}
			_, cerr := secrets.Create(ctx, sec, metav1.CreateOptions{})
			if cerr == nil || !apierrors.IsAlreadyExists(cerr) {
				return cerr
			}
			existing, err = secrets.Get(ctx, name, metav1.GetOptions{})
		}
		if err != nil {
			return err
		}
		if existing.Data == nil {
			existing.Data = map[string][]byte{}
		}
		existing.Data[key] = []byte(reportText)
		_, uerr := secrets.Update(ctx, existing, metav1.UpdateOptions{})
		if apierrors.IsForbidden(uerr) {
			return replaceReportSecret(ctx, secrets, existing)
		}
		return uerr
	})
	if err != nil {
		return fmt.Errorf("upsert report Secret: %w", err)
	}
	return nil
}

// replaceReportSecret writes a Secret the session ServiceAccount may get,
// delete and create but not update: the operator can only grant the verbs it
// holds itself, and it holds secrets update in no namespace but its own. The
// delete is pinned to the UID that was read, and the replacement keeps the
// labels and annotations the operator put on the staging Secret.
func replaceReportSecret(ctx context.Context, secrets typedcorev1.SecretInterface, existing *corev1.Secret) error {
	uid := existing.UID
	if err := secrets.Delete(ctx, existing.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	replacement := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        existing.Name,
			Namespace:   existing.Namespace,
			Labels:      existing.Labels,
			Annotations: existing.Annotations,
		},
		Type: existing.Type,
		Data: existing.Data,
	}
	_, err := secrets.Create(ctx, replacement, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return apierrors.NewConflict(corev1.Resource("secrets"), existing.Name, err)
	}
	return err
}

// buildInClusterClient constructs a kubernetes.Interface from the Job
// pod's ServiceAccount.
func buildInClusterClient() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			return nil, fmt.Errorf("in-cluster config: %w", err)
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig: %w", err)
		}
	}
	return kubernetes.NewForConfig(cfg)
}
