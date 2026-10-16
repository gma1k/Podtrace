package operator

import (
	"path/filepath"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

// buildAgentDaemonSetSpec renders the DaemonSet.Spec for the agent
// derived from a TracerConfig.
const agentTerminationGracePeriodSeconds = 120

func buildAgentDaemonSetSpec(tc *podtracev1alpha1.TracerConfig, systemNS string) appsv1.DaemonSetSpec {
	selector := &metav1.LabelSelector{
		MatchLabels: map[string]string{
			LabelManagedBy:    ManagedByValue,
			LabelComponent:    ComponentAgent,
			LabelTracerConfig: tc.Name,
		},
	}

	podLabels := agentPodTemplateLabels(selector.MatchLabels)

	hostPathType := corev1.HostPathDirectory
	priv := false
	runAsRoot := int64(0)

	imagePullPolicy := tc.Spec.ImagePullPolicy
	if imagePullPolicy == "" {
		imagePullPolicy = corev1.PullIfNotPresent
	}

	priorityClassName := tc.Spec.Agent.PriorityClassName
	if priorityClassName == "" {
		priorityClassName = "system-node-critical"
	}

	env := []corev1.EnvVar{
		{
			Name: "NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
			},
		},
		{
			Name: "POD_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			},
		},
		{Name: "PODTRACE_PROC_BASE", Value: "/host/proc"},
	}

	if lvl := tc.Spec.Agent.LogLevel; lvl != "" {
		env = append(env, corev1.EnvVar{Name: "PODTRACE_LOG_LEVEL", Value: lvl})
	}
	if n := tc.Spec.Agent.EventBufferSize; n > 0 {
		env = append(env, corev1.EnvVar{
			Name:  "PODTRACE_EVENT_BUFFER_SIZE",
			Value: itoa(int(n)),
		})
	}
	agent := &tc.Spec.Agent
	env = append(env,
		boolEnv("PODTRACE_DNS_PACKET_CAPTURE", agent.DNSPacketCaptureEnabled()),
		boolEnv("PODTRACE_USDT_ENABLED", agent.USDTEnabled()),
		boolEnv("PODTRACE_DNS_PAYLOAD_ENABLED", agent.DNSFullAnswersEnabled()),
		boolEnv("PODTRACE_CONTINUOUS_PROFILING_ENABLED", agent.ContinuousProfilingEnabled()),
		boolEnv("PODTRACE_SOCKOPS_RTT_ENABLED", agent.SockOpsRTTEnabled()),
	)
	if a := tc.Spec.Agent.Alerting; a != nil && a.Enabled {
		env = append(env, corev1.EnvVar{Name: "PODTRACE_ALERTING_ENABLED", Value: "true"})
		switch {
		case a.WebhookURLSecretRef != nil && a.WebhookURLSecretRef.Name != "":
			env = append(env, corev1.EnvVar{
				Name: "PODTRACE_ALERT_WEBHOOK_URL",
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: a.WebhookURLSecretRef.Name},
					Key:                  a.WebhookURLSecretRef.Key,
					Optional:             pointerBool(true),
				}},
			})
		case a.WebhookURL != "":
			env = append(env, corev1.EnvVar{Name: "PODTRACE_ALERT_WEBHOOK_URL", Value: a.WebhookURL})
		}
		if a.AllowInsecureWebhook {
			env = append(env, corev1.EnvVar{Name: "PODTRACE_ALERT_WEBHOOK_ALLOW_HTTP", Value: "true"})
		}
	}
	env = append(env, redactionEnv(tc.Spec.Redaction)...)
	env = append(env, captureEnv(tc.Spec.Capture)...)
	env = append(env, metricsEnv(tc.Spec.Agent.Metrics)...)

	btfEnv, btfVolume, btfMount := btfFileWiring(tc)
	env = append(env, btfEnv...)

	args := []string{
		"agent",
		"--system-namespace", systemNS,
		"--tracer-config", tc.Name,
	}
	if tc.Spec.Agent.StatusReportInterval != nil {
		args = append(args, "--status-report-interval", tc.Spec.Agent.StatusReportInterval.Duration.String())
	}

	return appsv1.DaemonSetSpec{
		Selector:       selector,
		UpdateStrategy: agentUpdateStrategy(tc),
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels:      podLabels,
				Annotations: agentScrapeAnnotations(),
			},
			Spec: corev1.PodSpec{
				ServiceAccountName:            AgentServiceAccountName(tc.Name),
				PriorityClassName:             priorityClassName,
				HostPID:                       true,
				NodeSelector:                  tc.Spec.NodeSelector,
				Tolerations:                   tc.Spec.Tolerations,
				Affinity:                      tc.Spec.Affinity,
				ImagePullSecrets:              tc.Spec.ImagePullSecrets,
				TerminationGracePeriodSeconds: ptrInt64(agentTerminationGracePeriodSeconds),
				Containers: []corev1.Container{{
					Name:            "agent",
					Image:           tc.Spec.Image,
					ImagePullPolicy: imagePullPolicy,
					Args:            args,
					Env:             env,
					Resources:       tc.Spec.Agent.Resources,
					SecurityContext: &corev1.SecurityContext{
						Privileged:               &priv,
						RunAsUser:                &runAsRoot,
						AllowPrivilegeEscalation: boolPtr(false),
						SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{
								"BPF", "SYS_ADMIN", "PERFMON", "SYS_RESOURCE", "NET_ADMIN", "SYS_PTRACE",
							},
						},
					},
					Ports: []corev1.ContainerPort{
						{Name: "metrics", ContainerPort: 9090, Protocol: corev1.ProtocolTCP},
						{Name: "health", ContainerPort: 9091, Protocol: corev1.ProtocolTCP},
					},
					StartupProbe:   agentStartupProbe(),
					LivenessProbe:  agentLivenessProbe(),
					ReadinessProbe: agentReadinessProbe(),
					VolumeMounts: append([]corev1.VolumeMount{
						{Name: "bpf", MountPath: "/sys/fs/bpf", MountPropagation: mountPropagationHostToContainer()},
						{Name: "btf", MountPath: "/sys/kernel/btf", ReadOnly: true},
						{Name: "proc", MountPath: "/host/proc", ReadOnly: true},
						{Name: "cgroup", MountPath: "/sys/fs/cgroup", ReadOnly: true},
						{Name: "debugfs", MountPath: "/sys/kernel/debug", ReadOnly: true},
						{Name: "tracefs", MountPath: "/sys/kernel/tracing", ReadOnly: true},
					}, btfMount...),
				}},
				Volumes: append([]corev1.Volume{
					{Name: "bpf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: &hostPathType}}},
					{Name: "btf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/btf", Type: &hostPathType}}},
					{Name: "proc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc", Type: &hostPathType}}},
					{Name: "cgroup", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/cgroup", Type: &hostPathType}}},
					{Name: "debugfs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/debug", Type: &hostPathType}}},
					{Name: "tracefs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/tracing", Type: &hostPathType}}},
				}, btfVolume...),
			},
		},
	}
}

// mountPropagationHostToContainer returns a pointer to
// corev1.MountPropagationHostToContainer, required for the BPF
// filesystem: without it, bpffs pins created by the agent would not be
// visible to other processes on the host.
func mountPropagationHostToContainer() *corev1.MountPropagationMode {
	mp := corev1.MountPropagationHostToContainer
	return &mp
}

func ptrInt64(v int64) *int64 { return &v }

func boolPtr(b bool) *bool { return &b }
func itoa(n int) string    { return strconv.Itoa(n) }

// intstrFromString returns an IntOrString whose StrVal names a port by
// name.
func intstrFromString(name string) intstr.IntOrString {
	return intstr.FromString(name)
}

// agentPodTemplateLabels returns the selector labels plus the
// app.kubernetes.io/* convention, as a new map so the caller's selector is
// left untouched.
func agentPodTemplateLabels(selector map[string]string) map[string]string {
	labels := make(map[string]string, len(selector)+4)
	for k, v := range selector {
		labels[k] = v
	}
	labels["app.kubernetes.io/name"] = "podtrace"
	labels["app.kubernetes.io/component"] = ComponentAgent
	labels["app.kubernetes.io/part-of"] = "podtrace"
	labels["app.kubernetes.io/managed-by"] = ManagedByValue
	return labels
}

// agentUpdateStrategy decides how many agents may be down at once during a
// rollout.
func agentUpdateStrategy(tc *podtracev1alpha1.TracerConfig) appsv1.DaemonSetUpdateStrategy {
	strategy := appsv1.DaemonSetUpdateStrategy{
		Type: appsv1.RollingUpdateDaemonSetStrategyType,
	}
	if tc == nil || tc.Spec.Agent.RolloutMaxUnavailable == nil {
		return strategy
	}
	strategy.RollingUpdate = &appsv1.RollingUpdateDaemonSet{
		MaxUnavailable: tc.Spec.Agent.RolloutMaxUnavailable,
	}
	return strategy
}

// btfFileMountDir is where a supplied BTF blob is mounted in the agent.
const btfFileMountDir = "/etc/podtrace/btf"

// btfFileWiring translates btfMode "file" into the mount and the environment
// variable the tracer already consumes.
func btfFileWiring(tc *podtracev1alpha1.TracerConfig) ([]corev1.EnvVar, []corev1.Volume, []corev1.VolumeMount) {
	if tc == nil || tc.Spec.BTFMode != podtracev1alpha1.BTFModeFile || tc.Spec.BTFSource == nil {
		return nil, nil, nil
	}
	src := tc.Spec.BTFSource

	var filePath, mountPath string
	var volumeSource corev1.VolumeSource

	switch {
	case src.ConfigMap != nil && src.ConfigMap.Name != "":
		key := src.ConfigMap.Key
		if key == "" {
			key = podtracev1alpha1.DefaultBTFConfigMapKey
		}
		filePath = filepath.Join(btfFileMountDir, key)
		mountPath = btfFileMountDir
		volumeSource = corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: src.ConfigMap.Name},
				Items:                []corev1.KeyToPath{{Key: key, Path: key}},
			},
		}

	case src.HostPath != "":
		fileType := corev1.HostPathFile
		filePath = filepath.Join(btfFileMountDir, filepath.Base(src.HostPath))
		mountPath = filePath
		volumeSource = corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: src.HostPath, Type: &fileType},
		}

	default:
		return nil, nil, nil
	}

	env := []corev1.EnvVar{{Name: "PODTRACE_BTF_FILE", Value: filePath}}
	volumes := []corev1.Volume{{Name: "btf-file", VolumeSource: volumeSource}}
	mounts := []corev1.VolumeMount{{Name: "btf-file", MountPath: mountPath, ReadOnly: true}}
	return env, volumes, mounts
}

// agentMetricsPort is the agent container's "metrics" port.
const agentMetricsPort = "9090"

// agentScrapeAnnotations advertises the agent's metrics endpoint to
// annotation-based scrapers: the community Prometheus chart, the OpenTelemetry
// Collector's Kubernetes discovery, and Datadog all read these.
func agentScrapeAnnotations() map[string]string {
	return map[string]string{
		"prometheus.io/scrape": "true",
		"prometheus.io/port":   agentMetricsPort,
		"prometheus.io/path":   "/metrics",
	}
}

// The agent's health endpoints are served only once the eBPF backend has
// loaded, which on a busy node, attaching hundreds of probes.
const (
	agentStartupPeriodSeconds    = 10
	agentStartupFailureThreshold = 30
	agentProbeTimeoutSeconds     = 5
)

func agentHealthGet(path string) corev1.ProbeHandler {
	return corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: path, Port: intstrFromString("health")}}
}

func agentStartupProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:     agentHealthGet("/healthz"),
		PeriodSeconds:    agentStartupPeriodSeconds,
		FailureThreshold: agentStartupFailureThreshold,
		TimeoutSeconds:   agentProbeTimeoutSeconds,
	}
}

func agentLivenessProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:     agentHealthGet("/healthz"),
		PeriodSeconds:    20,
		FailureThreshold: 3,
		TimeoutSeconds:   agentProbeTimeoutSeconds,
	}
}

func agentReadinessProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:     agentHealthGet("/readyz"),
		PeriodSeconds:    10,
		FailureThreshold: 3,
		TimeoutSeconds:   agentProbeTimeoutSeconds,
	}
}
