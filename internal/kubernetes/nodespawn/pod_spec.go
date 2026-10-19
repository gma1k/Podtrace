package nodespawn

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Labels stamped on every spawned pod. Used by the reaper to find pods left
// behind by a crashed CLI.
const (
	LabelManagedBy   = "app.kubernetes.io/managed-by"
	LabelComponent   = "app.kubernetes.io/component"
	LabelNode        = "podtrace.io/node"
	LabelOwnerHost   = "podtrace.io/owner-host"
	LabelOwnerPID    = "podtrace.io/owner-pid"
	LabelOwnerBootID = "podtrace.io/owner-boot-id"
	LabelOwnerPIDNS  = "podtrace.io/owner-pid-ns"
	LabelCreatedAt   = "podtrace.io/created-at"
	ManagedByValue   = "podtrace-cli"
	ComponentValue   = "cli-spawn"

	EnvNodeLocalSentinel = "PODTRACE_NODE_LOCAL"

	SplunkSecretKey = "token"

	ReaperMaxAge = 2 * time.Hour
)

// SpawnSecretName names the Secret carrying a spawn pod's credentials: the
// Splunk token and any credential-bearing endpoints.
func SpawnSecretName(podName string) string {
	return podName + "-credentials"
}

// btfFileMountDir is where a supplied BTF blob is mounted in the spawned pod.
const btfFileMountDir = "/etc/podtrace/btf"

// PodSpecOptions configures BuildPodSpec.
type PodSpecOptions struct {
	ExtraEnv []corev1.EnvVar

	SplunkToken string

	SecretEnv map[string]string

	BTFFile string

	NodeName              string
	Namespace             string
	Image                 string
	ImagePullPolicy       corev1.PullPolicy
	ImagePullSecrets      []corev1.LocalObjectReference
	Args                  []string
	ActiveDeadlineSeconds int64
	Tolerations           []corev1.Toleration
	ServiceAccountName    string
	OwnerHost             string
	OwnerPID              int
}

// BuildPodSpec returns a pod with privileged + hostPID set, mounting the host
// root under /host/* and pointing the podtrace binary at those paths via env
// vars.
func BuildPodSpec(opts PodSpecOptions) (*corev1.Pod, error) {
	if opts.NodeName == "" {
		return nil, fmt.Errorf("nodespawn: NodeName is required")
	}
	if opts.Namespace == "" {
		return nil, fmt.Errorf("nodespawn: Namespace is required")
	}
	if opts.Image == "" {
		return nil, fmt.Errorf("nodespawn: Image is required")
	}

	priv := false
	runAsRoot := int64(0)

	suffix, err := randomSuffix()
	if err != nil {
		return nil, err
	}
	name := podName(opts.NodeName, suffix)

	createdAt := fmt.Sprintf("%d", time.Now().UTC().Unix())

	hpDir := corev1.HostPathDirectoryOrCreate
	hpRequiredDir := corev1.HostPathDirectory
	volumes := []corev1.Volume{
		{Name: "bpf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf"}}},
		{Name: "btf", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/btf"}}},
		{Name: "proc", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
		{Name: "cgroup", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/cgroup"}}},
		{Name: "containerd-sock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/containerd"}}},
		{Name: "debug", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/debug", Type: &hpDir}}},
		{Name: "tracing", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/tracing", Type: &hpDir}}},
		{Name: "securityfs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/security", Type: &hpRequiredDir}}},
	}

	mounts := []corev1.VolumeMount{
		{Name: "bpf", MountPath: "/sys/fs/bpf"},
		{Name: "btf", MountPath: "/sys/kernel/btf", ReadOnly: true},
		{Name: "proc", MountPath: "/host/proc", ReadOnly: true},
		{Name: "cgroup", MountPath: "/sys/fs/cgroup", ReadOnly: true},
		{Name: "cgroup", MountPath: "/host/sys/fs/cgroup", ReadOnly: true},
		{Name: "containerd-sock", MountPath: "/run/containerd", ReadOnly: true},
		{Name: "debug", MountPath: "/sys/kernel/debug"},
		{Name: "tracing", MountPath: "/sys/kernel/tracing"},
		{Name: "securityfs", MountPath: "/host/sys/kernel/security", ReadOnly: true},
	}

	env := []corev1.EnvVar{
		{Name: EnvNodeLocalSentinel, Value: "1"},
		{Name: "PODTRACE_PROC_BASE", Value: "/host/proc"},
		{Name: "PODTRACE_CGROUP_BASE", Value: "/host/sys/fs/cgroup"},
		{
			Name: "NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
	}
	passthrough := []string{
		"PODTRACE_BPF_LOG_LEVEL",
		"PODTRACE_BPF_LOG_SIZE",
		"PODTRACE_OTLP_INSECURE",
		"PODTRACE_ALERT_WARN_PCT",
		"PODTRACE_ALERT_CRIT_PCT",
		"PODTRACE_ALERT_EMERG_PCT",
		"PODTRACE_MANAGEMENT_PORT",
		"PODTRACE_PROFILING_PPROF_PORTS",
	}
	for _, name := range passthrough {
		if v := os.Getenv(name); v != "" {
			env = append(env, corev1.EnvVar{Name: name, Value: v})
		}
	}
	env = append(env, opts.ExtraEnv...)

	if opts.BTFFile != "" {
		mountPath := filepath.Join(btfFileMountDir, filepath.Base(opts.BTFFile))
		fileType := corev1.HostPathFile
		env = append(env, corev1.EnvVar{Name: "PODTRACE_BTF_FILE", Value: mountPath})
		volumes = append(volumes, corev1.Volume{
			Name: "btf-file",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: opts.BTFFile, Type: &fileType},
			},
		})
		// Mounted as the file itself rather than its directory: the blob may
		// sit beside unrelated files and this pod is privileged already.
		mounts = append(mounts, corev1.VolumeMount{
			Name: "btf-file", MountPath: mountPath, ReadOnly: true,
		})
	}

	if opts.SplunkToken != "" {
		env = append(env, corev1.EnvVar{
			Name: "PODTRACE_SPLUNK_TOKEN", // contract read by internal/config.SplunkToken
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: SpawnSecretName(name)},
					Key:                  SplunkSecretKey,
				},
			},
		})
	}

	secretEnvNames := make([]string, 0, len(opts.SecretEnv))
	for envName := range opts.SecretEnv {
		secretEnvNames = append(secretEnvNames, envName)
	}
	sort.Strings(secretEnvNames)
	for _, envName := range secretEnvNames {
		env = append(env, corev1.EnvVar{
			Name: envName,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: SpawnSecretName(name)},
					Key:                  envName,
				},
			},
		})
	}

	container := corev1.Container{
		Name:                     "podtrace",
		Image:                    opts.Image,
		ImagePullPolicy:          opts.ImagePullPolicy,
		Args:                     append([]string(nil), opts.Args...),
		Env:                      env,
		Stdin:                    true,
		StdinOnce:                true,
		TTY:                      false,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		SecurityContext: &corev1.SecurityContext{
			Privileged:               &priv,
			RunAsUser:                &runAsRoot,
			AllowPrivilegeEscalation: ptrBool(false),
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"BPF", "SYS_ADMIN", "PERFMON", "SYS_RESOURCE", "NET_ADMIN", "SYS_PTRACE"},
			},
		},
		VolumeMounts: mounts,
	}

	labels := map[string]string{
		LabelManagedBy: ManagedByValue,
		LabelComponent: ComponentValue,
		LabelNode:      opts.NodeName,
		LabelCreatedAt: createdAt,
	}
	if opts.OwnerHost != "" {
		labels[LabelOwnerHost] = sanitizeLabelValue(opts.OwnerHost)
	}
	if opts.OwnerPID > 0 {
		labels[LabelOwnerPID] = fmt.Sprintf("%d", opts.OwnerPID)
	}
	if bootID := MachineBootID(); bootID != "" {
		labels[LabelOwnerBootID] = sanitizeLabelValue(bootID)
	}
	if pidNS := MachinePIDNamespace(); pidNS != "" {
		labels[LabelOwnerPIDNS] = sanitizeLabelValue(pidNS)
	}

	spec := corev1.PodSpec{
		RestartPolicy:      corev1.RestartPolicyNever,
		HostPID:            true,
		NodeSelector:       map[string]string{"kubernetes.io/hostname": opts.NodeName},
		Tolerations:        opts.Tolerations,
		ServiceAccountName: opts.ServiceAccountName,
		ImagePullSecrets:   opts.ImagePullSecrets,
		Containers:         []corev1.Container{container},
		Volumes:            volumes,
	}
	if opts.ActiveDeadlineSeconds > 0 {
		spec.ActiveDeadlineSeconds = &opts.ActiveDeadlineSeconds
	}

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: opts.Namespace,
			Labels:    labels,
		},
		Spec: spec,
	}, nil
}

func podName(nodeName, suffix string) string {
	prefix := "podtrace-cli-"
	maxNode := 63 - len(prefix) - 1 - len(suffix)
	node := sanitizeName(nodeName)
	if len(node) > maxNode {
		node = node[:maxNode]
	}
	return prefix + node + "-" + suffix
}

func sanitizeName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	last := byte('-')
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			c = '-'
		}
		if c == '-' && last == '-' {
			continue
		}
		b.WriteByte(c)
		last = c
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "node"
	}
	return out
}

func sanitizeLabelValue(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 63; i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			c = '_'
		}
		b.WriteByte(c)
	}
	out := strings.Trim(b.String(), "-_.")
	if out == "" {
		return "unknown"
	}
	return out
}

// randomSuffix is a var so tests can force its (otherwise unreachable)
// crypto/rand error path.
var randomSuffix = func() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("nodespawn: random suffix: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func Hostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}
