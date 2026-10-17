package operator

import (
	"sort"
	"strconv"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
)

const defaultSessionDeadlineOffset = 90 * time.Second

// sessionClock is the operator's clock, replaceable in tests.
var sessionClock = time.Now

func buildSessionJobSpec(s *podtracev1alpha1.PodTraceSession, tc *podtracev1alpha1.TracerConfig, node string, targets sessionTargets) batchv1.JobSpec {
	completions := int32(1)
	parallelism := int32(1)

	backoffLimit := int32(0)
	ttlSeconds := int32(300)
	deadlineOffset := int64(defaultSessionDeadlineOffset / time.Second)
	sidecarUploader := false
	if tc != nil {
		if tc.Spec.Session.BackoffLimit != nil {
			backoffLimit = *tc.Spec.Session.BackoffLimit
		}
		if tc.Spec.Session.TTLSecondsAfterFinished != nil {
			ttlSeconds = *tc.Spec.Session.TTLSecondsAfterFinished
		}
		if o := tc.Spec.Session.ActiveDeadlineOffset; o != nil && o.Duration > 0 {
			deadlineOffset = int64(o.Seconds())
		}
		sidecarUploader = tc.Spec.Session.SidecarUploader
	}

	effectiveDuration := effectiveSessionDuration(s, tc)
	activeDeadline := int64(effectiveDuration.Seconds()) + deadlineOffset
	killAt := sessionClock().Add(time.Duration(activeDeadline) * time.Second)

	imagePullPolicy := corev1.PullIfNotPresent
	image := ""
	var pullSecrets []corev1.LocalObjectReference
	var resources corev1.ResourceRequirements
	if tc != nil {
		image = tc.Spec.Image
		if tc.Spec.ImagePullPolicy != "" {
			imagePullPolicy = tc.Spec.ImagePullPolicy
		}
		pullSecrets = tc.Spec.ImagePullSecrets
		resources = tc.Spec.Session.Resources
	}

	priv := false
	runAsRoot := int64(0)

	args := buildDiagnoseArgs(s, targets, effectiveDuration)
	reportTo := reportToSpecFromReportRef(s)
	if reportSinkIsSecret(s) {
		reportTo = "secret/$(POD_NAMESPACE)/" + SessionReportStagingName(s.UID, node)
	}

	volumes := []corev1.Volume{
		{Name: "bpf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf"}}},
		{Name: "btf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/btf"}}},
		{Name: "proc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
		{Name: "cgroup", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/cgroup"}}},
		{Name: "debugfs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/debug"}}},
		{Name: "tracefs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/tracing"}}},
		{
			Name: "exporter",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: SessionBundleName(s.UID)},
					Optional:             pointerBool(true),
				},
			},
		},
		{
			Name: "exporter-credential",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: SessionBundleName(s.UID),
					Optional:   pointerBool(true),
				},
			},
		},
		{
			Name:         "rundir",
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		},
	}

	mainVolumeMounts := []corev1.VolumeMount{
		{Name: "bpf", MountPath: "/sys/fs/bpf", MountPropagation: mountPropagationHostToContainer()},
		{Name: "btf", MountPath: "/sys/kernel/btf", ReadOnly: true},
		{Name: "proc", MountPath: "/host/proc", ReadOnly: true},
		{Name: "cgroup", MountPath: "/sys/fs/cgroup", ReadOnly: true},
		{Name: "debugfs", MountPath: "/sys/kernel/debug", ReadOnly: true},
		{Name: "tracefs", MountPath: "/sys/kernel/tracing", ReadOnly: true},
		{Name: "exporter", MountPath: "/etc/podtrace/exporter", ReadOnly: true},
		{Name: "exporter-credential", MountPath: "/etc/podtrace/exporter-credential", ReadOnly: true},
		{Name: "rundir", MountPath: "/var/run/podtrace"},
	}

	sessionArgs := append([]string{}, args...)
	if s.Spec.ExporterRef.Name != "" {
		sessionArgs = append(sessionArgs,
			"--tracing",
			"--exporter-from-file", "/etc/podtrace/exporter/bundle.yaml",
		)
	}
	sessionArgs = append(sessionArgs,
		"--summary-file", "/var/run/podtrace/summary.json",
		"--termination-message-path", "/dev/termination-log",
		"--session-deadline", killAt.UTC().Format(time.RFC3339),
	)
	if reportTo != "" {
		sessionArgs = append(sessionArgs, "--report-to", reportTo)
	}
	sessionArgs = append(sessionArgs, triggerIssueArgs(s.Annotations)...)

	mainEnv := []corev1.EnvVar{
		{
			Name: "NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{
			Name:  "PODTRACE_EXPORTER_CREDENTIAL_FILE",
			Value: "/etc/podtrace/exporter-credential/credential",
		},
		{Name: "PODTRACE_OTLP_INSECURE", Value: "1"},
		{Name: config.EnvArtifactBaseDir, Value: "/var/run/podtrace"},
		podNamespaceEnv(),
	}
	if tc != nil {
		mainEnv = append(mainEnv, redactionEnv(tc.Spec.Redaction)...)
		mainEnv = append(mainEnv, captureEnv(tc.Spec.Capture)...)
		usdtEnabled := true
		if u := tc.Spec.Agent.USDT; u != nil {
			usdtEnabled = *u
		}
		mainEnv = append(mainEnv, corev1.EnvVar{Name: "PODTRACE_USDT_ENABLED", Value: strconv.FormatBool(usdtEnabled)})
		mainEnv = append(mainEnv, corev1.EnvVar{Name: "PODTRACE_UPROBE_MULTI", Value: strconv.FormatBool(tc.Spec.Agent.UprobeMultiEnabled())})
		dnsFull := true
		if d := tc.Spec.Agent.DNSFullAnswers; d != nil {
			dnsFull = *d
		}
		mainEnv = append(mainEnv, corev1.EnvVar{Name: "PODTRACE_DNS_PAYLOAD_ENABLED", Value: strconv.FormatBool(dnsFull)})
		if lvl := tc.Spec.Agent.LogLevel; lvl != "" {
			mainEnv = append(mainEnv, corev1.EnvVar{Name: "PODTRACE_LOG_LEVEL", Value: lvl})
		}

		btfEnv, btfVolume, btfMount := btfFileWiring(tc)
		mainEnv = append(mainEnv, btfEnv...)
		volumes = append(volumes, btfVolume...)
		mainVolumeMounts = append(mainVolumeMounts, btfMount...)
	}

	mainContainer := corev1.Container{
		Name:                     "podtrace",
		Image:                    image,
		ImagePullPolicy:          imagePullPolicy,
		Args:                     sessionArgs,
		Env:                      mainEnv,
		Resources:                resources,
		TerminationMessagePath:   "/dev/termination-log",
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		SecurityContext: &corev1.SecurityContext{
			Privileged:               &priv,
			RunAsUser:                &runAsRoot,
			AllowPrivilegeEscalation: boolPtr(false),
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"BPF", "SYS_ADMIN", "PERFMON", "SYS_RESOURCE", "NET_ADMIN", "SYS_PTRACE"},
			},
		},
		VolumeMounts: mainVolumeMounts,
	}

	initContainers := buildSessionSidecar(sidecarUploader, reportTo, image, imagePullPolicy, s)

	if vol, ok := objectStoreCredentialsVolume(s); ok {
		volumes = append(volumes, vol)
	}

	return batchv1.JobSpec{
		Completions:             &completions,
		Parallelism:             &parallelism,
		BackoffLimit:            &backoffLimit,
		TTLSecondsAfterFinished: &ttlSeconds,
		ActiveDeadlineSeconds:   &activeDeadline,
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					LabelManagedBy:   ManagedByValue,
					LabelComponent:   ComponentSession,
					LabelSessionName: s.Name,
					LabelSessionNS:   s.Namespace,
					LabelNodeName:    node,
				},
			},
			Spec: corev1.PodSpec{
				RestartPolicy:      corev1.RestartPolicyNever,
				ServiceAccountName: SessionServiceAccountName(s.UID),
				NodeSelector: map[string]string{
					"kubernetes.io/hostname": node,
				},
				HostPID:           true,
				ImagePullSecrets:  pullSecrets,
				Tolerations:       tolerationsFrom(tc),
				PriorityClassName: priorityClassNameFrom(tc),
				InitContainers:    initContainers,
				Containers:        []corev1.Container{mainContainer},
				Volumes:           volumes,
			},
		},
	}
}

// buildSessionSidecar returns the native sidecar (init container with
// restartPolicy=Always) that re-uploads the session report when the
// operator's TracerConfig.spec.session.sidecarUploader flag is set.
func buildSessionSidecar(enabled bool, reportTo, image string, pullPolicy corev1.PullPolicy, s *podtracev1alpha1.PodTraceSession) []corev1.Container {
	if !enabled || reportTo == "" {
		return nil
	}
	always := corev1.ContainerRestartPolicyAlways

	mounts := []corev1.VolumeMount{
		{Name: "rundir", MountPath: "/var/run/podtrace"},
	}
	env := []corev1.EnvVar{podNamespaceEnv()}
	if _, ok := objectStoreCredentialsVolume(s); ok {
		const credsMount = "/etc/podtrace/objectstore-credentials" // #nosec G101 -- mount path, not a credential value; documented in docs/object-store-reports.md
		mounts = append(mounts, corev1.VolumeMount{
			Name:      objectStoreCredentialsVolumeName,
			MountPath: credsMount,
			ReadOnly:  true,
		})
		env = append(env, corev1.EnvVar{
			Name:  "PODTRACE_OBJECTSTORE_CREDENTIALS_DIR",
			Value: credsMount,
		})
	}

	return []corev1.Container{{
		Name:            "report-uploader",
		Image:           image,
		ImagePullPolicy: pullPolicy,
		RestartPolicy:   &always,
		Args: []string{
			"report-uploader",
			"--report-file", "/var/run/podtrace/report.txt",
			"--summary-file", "/var/run/podtrace/summary.json",
			"--report-to", reportTo,
		},
		Env:                      env,
		TerminationMessagePath:   "/dev/termination-log",
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		VolumeMounts:             mounts,
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot:             boolPtr(true),
			RunAsUser:                ptrInt64(65532),
			AllowPrivilegeEscalation: boolPtr(false),
			ReadOnlyRootFilesystem:   boolPtr(true),
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	}}
}

// podNamespaceEnv exposes the Job's namespace for $(POD_NAMESPACE) in args.
func podNamespaceEnv() corev1.EnvVar {
	return corev1.EnvVar{
		Name: "POD_NAMESPACE",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
		},
	}
}

const objectStoreCredentialsVolumeName = "objectstore-credentials"

func objectStoreCredentialsVolume(s *podtracev1alpha1.PodTraceSession) (corev1.Volume, bool) {
	if s == nil || s.Spec.ReportRef == nil || s.Spec.ReportRef.ObjectStore == nil {
		return corev1.Volume{}, false
	}
	ref := s.Spec.ReportRef.ObjectStore.CredentialsSecretRef
	if ref == nil || ref.Name == "" {
		return corev1.Volume{}, false
	}
	return corev1.Volume{
		Name: objectStoreCredentialsVolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: SessionObjectStoreCredsName(s.UID),
				Optional:   pointerBool(false),
			},
		},
	}, true
}

// pointerBool is a trivial helper for struct-literal initialization of
// *bool fields that Kubernetes API types require.
func pointerBool(b bool) *bool {
	return &b
}

// triggerIssueArgs tells the session which issue started it, so its report
// opens with that issue. It returns nothing for a session no issue started.
func triggerIssueArgs(annotations map[string]string) []string {
	id := knownIssueID(annotations[alerting.AnnotationIssueID])
	if id == "" {
		return nil
	}
	args := []string{"--trigger-issue", id}
	for _, f := range []struct{ flag, annotation string }{
		{"--trigger-severity", AnnotationTriggerSeverity},
		{"--trigger-pod", AnnotationTriggerPod},
		{"--trigger-at", AnnotationTriggeredAt},
		{"--trigger-reason", AnnotationTriggerReason},
	} {
		if v := annotations[f.annotation]; v != "" {
			args = append(args, f.flag, truncateReason(v))
		}
	}
	return args
}

// buildDiagnoseArgs produces the `podtrace` CLI args that a session Job
// executes.
func effectiveSessionDuration(s *podtracev1alpha1.PodTraceSession, tc *podtracev1alpha1.TracerConfig) time.Duration {
	d := s.Spec.Duration.Duration
	if tc != nil && tc.Spec.Session.MaxDuration != nil {
		if cap := tc.Spec.Session.MaxDuration.Duration; cap > 0 && cap < d {
			return cap
		}
	}
	return d
}

// buildDiagnoseArgs renders the in-Job CLI arguments from the session's
// grant-authorized targets.
func buildDiagnoseArgs(s *podtracev1alpha1.PodTraceSession, targets sessionTargets, duration time.Duration) []string {
	args := []string{
		"--diagnose", duration.String(),
	}
	if s.Spec.ContainerName != "" {
		args = append(args, "--container", s.Spec.ContainerName)
	}
	if len(s.Spec.Filters) > 0 {
		vals := make([]string, 0, len(s.Spec.Filters))
		for _, f := range s.Spec.Filters {
			vals = append(vals, string(f))
		}
		args = append(args, "--filter", strings.Join(vals, ","))
	}
	if s.Spec.SamplePercent != nil {
		args = append(args, "--tracing-sample-rate", strconv.FormatFloat(float64(*s.Spec.SamplePercent)/100.0, 'f', 2, 64))
	}

	if s.Spec.Selector != nil {
		args = append(args, "--pod-selector", labelSelectorToFlag(s.Spec.Selector))
		args = append(args, "--all-in-namespace")
		if len(targets.Namespaces) > 0 {
			args = append(args, "--namespaces", strings.Join(targets.Namespaces, ","))
		} else {
			args = append(args, "--namespace", s.Namespace)
		}
	}
	if len(targets.PodRefs) > 0 {
		refs := make([]string, 0, len(targets.PodRefs))
		for _, r := range targets.PodRefs {
			if r.Namespace != "" {
				refs = append(refs, r.Namespace+"/"+r.Name)
			} else {
				refs = append(refs, s.Namespace+"/"+r.Name)
			}
		}
		args = append(args, "--pods", strings.Join(refs, ","))
	}
	return args
}

// labelSelectorToFlag serializes the FULL selector, matchLabels and
// matchExpressions, into the string form the in-Job CLI passes to the API
// server.
func labelSelectorToFlag(s *metav1.LabelSelector) string {
	sel, err := metav1.LabelSelectorAsSelector(s)
	if err != nil {
		return ""
	}
	return sel.String()
}

func tolerationsFrom(tc *podtracev1alpha1.TracerConfig) []corev1.Toleration {
	if tc == nil {
		return nil
	}
	return tc.Spec.Tolerations
}

func priorityClassNameFrom(tc *podtracev1alpha1.TracerConfig) string {
	if tc == nil {
		return ""
	}
	return tc.Spec.Agent.PriorityClassName
}

// makeSessionJobRefs rolls up a list of child Jobs into the slim status
// representation carried on PodTraceSession.
const sessionJobFailedMessage = "Job failed"

func makeSessionJobRefs(jobs []batchv1.Job) []podtracev1alpha1.SessionJobRef {
	refs := make([]podtracev1alpha1.SessionJobRef, 0, len(jobs))
	for _, j := range jobs {
		node := j.Labels[LabelNodeName]
		ref := podtracev1alpha1.SessionJobRef{
			Node:      node,
			Name:      j.Name,
			Completed: jobSucceeded(&j) || jobFailed(&j),
		}
		if j.Status.StartTime != nil {
			ref.StartTime = j.Status.StartTime
		}
		if j.Status.CompletionTime != nil {
			ref.CompletionTime = j.Status.CompletionTime
		}
		if jobFailed(&j) && !jobSucceeded(&j) {
			ref.Message = sessionJobFailedMessage
		}
		refs = append(refs, ref)
	}
	return refs
}

// mergeSessionJobRefs unions the live Job list with the previously recorded
// per-node refs, carrying forward any node whose Job already completed but
// has since been TTL-garbage-collected.
func mergeSessionJobRefs(live []batchv1.Job, prior []podtracev1alpha1.SessionJobRef) []podtracev1alpha1.SessionJobRef {
	refs := makeSessionJobRefs(live)
	seen := make(map[string]struct{}, len(refs))
	for i := range refs {
		seen[refs[i].Node] = struct{}{}
	}
	for i := range prior {
		p := prior[i]
		if p.Completed && p.Node != "" {
			if _, ok := seen[p.Node]; !ok {
				refs = append(refs, p)
				seen[p.Node] = struct{}{}
			}
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Node < refs[j].Node })
	return refs
}

// fannedOutNodes returns the sorted nodes the session has already created
// Jobs on.
func fannedOutNodes(refs []podtracev1alpha1.SessionJobRef) []string {
	seen := make(map[string]struct{}, len(refs))
	out := make([]string, 0, len(refs))
	for i := range refs {
		node := refs[i].Node
		if node == "" {
			continue
		}
		if _, dup := seen[node]; dup {
			continue
		}
		seen[node] = struct{}{}
		out = append(out, node)
	}
	sort.Strings(out)
	return out
}

// completedSessionNodes returns the set of nodes with a recorded terminal
// Job outcome, so the reconciler never recreates a Job for a node that has
// already finished this session.
func completedSessionNodes(refs []podtracev1alpha1.SessionJobRef) map[string]struct{} {
	done := make(map[string]struct{})
	for i := range refs {
		if refs[i].Completed && refs[i].Node != "" {
			done[refs[i].Node] = struct{}{}
		}
	}
	return done
}

func jobBackoffLimit(j *batchv1.Job) int32 {
	if j.Spec.BackoffLimit != nil {
		return *j.Spec.BackoffLimit
	}
	return 6
}

// jobConditionTrue reports whether the Job carries condition t with status
// True.
func jobConditionTrue(j *batchv1.Job, t batchv1.JobConditionType) bool {
	for i := range j.Status.Conditions {
		c := &j.Status.Conditions[i]
		if c.Type == t && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// jobSucceeded / jobFailed classify a Job terminally via its conditions.
func jobSucceeded(j *batchv1.Job) bool {
	return jobConditionTrue(j, batchv1.JobComplete) || j.Status.Succeeded > 0
}

func jobFailed(j *batchv1.Job) bool {
	return jobConditionTrue(j, batchv1.JobFailed) || j.Status.Failed > jobBackoffLimit(j)
}

// computeSessionState maps Job statuses to a SessionState.
//
//   - All succeeded         → Completed
//   - Any failed past limit → Failed
//   - Any running           → Running
//   - Otherwise             → Pending
func computeSessionState(refs []podtracev1alpha1.SessionJobRef, liveJobs []batchv1.Job, expectedNodes int) podtracev1alpha1.SessionState {
	if len(refs) == 0 || expectedNodes == 0 {
		return podtracev1alpha1.SessionStatePending
	}
	completed := 0
	anyFailed := false
	for i := range refs {
		if !refs[i].Completed {
			continue
		}
		completed++
		if refs[i].Message == sessionJobFailedMessage {
			anyFailed = true
		}
	}
	switch {
	case anyFailed:
		return podtracev1alpha1.SessionStateFailed
	case completed >= expectedNodes:
		return podtracev1alpha1.SessionStateCompleted
	}
	for i := range liveJobs {
		if liveJobs[i].Status.Active > 0 {
			return podtracev1alpha1.SessionStateRunning
		}
	}
	return podtracev1alpha1.SessionStatePending
}

func isTerminal(p podtracev1alpha1.SessionState) bool {
	return p == podtracev1alpha1.SessionStateCompleted || p == podtracev1alpha1.SessionStateFailed
}

func anyJobStarted(jobs []batchv1.Job) bool {
	for _, j := range jobs {
		if j.Status.StartTime != nil || j.Status.Active > 0 || j.Status.Succeeded > 0 || j.Status.Failed > 0 {
			return true
		}
	}
	return false
}
