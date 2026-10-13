package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// BTFMode controls how the agent resolves BTF for CO-RE.
//
// "auto" and "host" both read /sys/kernel/btf/vmlinux. "file" loads a BTF blob
// the operator supplies through btfSource, for a node whose kernel was built
// without CONFIG_DEBUG_INFO_BTF; see docs/crd-tracerconfig.md for how to
// produce one.
//
// "embedded" is DEPRECATED and does nothing: no BTF is shipped in the image, so
// the agent behaves as for "auto" and the admission webhook warns. Use "file".
// It stays in the enum because removing a value from a published API is a
// breaking change; it will go at the next stored-version cutover.
// +kubebuilder:validation:Enum=auto;host;file;embedded
type BTFMode string

const (
	BTFModeAuto BTFMode = "auto"
	BTFModeHost BTFMode = "host"

	// BTFModeFile loads BTF from the blob named by TracerConfigSpec.BTFSource.
	BTFModeFile BTFMode = "file"

	// BTFModeEmbedded is deprecated and inert. Use BTFModeFile.
	BTFModeEmbedded BTFMode = "embedded"
)

// BTFSource locates the BTF blob the agent loads when btfMode is "file".
// Exactly one of its fields may be set.
//
// The blob may be a raw BTF file -- what "bpftool gen min_core_btf" and the
// BTFHub archive produce -- or an ELF carrying a .BTF section, such as a
// vmlinux built with CONFIG_DEBUG_INFO_BTF. A minimised blob is tens of
// kilobytes and fits a ConfigMap; a whole vmlinux does not.
type BTFSource struct {
	// ConfigMap names a ConfigMap in the system namespace whose binaryData
	// holds the blob. Preferred: it survives node replacement and needs no
	// access to the node's filesystem. A ConfigMap caps at 1MiB, so the blob
	// must be minimised.
	// +optional
	ConfigMap *BTFConfigMapSource `json:"configMap,omitempty"`

	// HostPath reads the blob from an absolute path present on every node the
	// agent runs on. For a blob too large for a ConfigMap, or one already
	// staged on the node by other tooling.
	// +kubebuilder:validation:Pattern=`^/.*`
	// +optional
	HostPath string `json:"hostPath,omitempty"`
}

// BTFConfigMapSource names the ConfigMap and key holding a BTF blob.
type BTFConfigMapSource struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Key defaults to "vmlinux.btf".
	// +optional
	Key string `json:"key,omitempty"`
}

// DefaultBTFConfigMapKey is the ConfigMap key used when BTFConfigMapSource
// leaves Key empty.
const DefaultBTFConfigMapKey = "vmlinux.btf"

// AgentSpec tunes the per-node tracer DaemonSet.
type AgentSpec struct {
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// +kubebuilder:validation:Enum=debug;info;warn;error
	// +optional
	LogLevel string `json:"logLevel,omitempty"`

	// +kubebuilder:validation:Minimum=128
	// +optional
	EventBufferSize int32 `json:"eventBufferSize,omitempty"`

	// +optional
	StatusReportInterval *metav1.Duration `json:"statusReportInterval,omitempty"`

	// +optional
	// +kubebuilder:default=true
	DNSPacketCapture *bool `json:"dnsPacketCapture,omitempty"`

	// +optional
	// +kubebuilder:default=true
	DNSFullAnswers *bool `json:"dnsFullAnswers,omitempty"`

	// +optional
	// +kubebuilder:default=true
	USDT *bool `json:"usdt,omitempty"`

	// ContinuousProfiling builds an always-on per-workload CPU profile from
	// the user stacks already captured on every sched_switch, served as JSON
	// on the agent's /profile. It needs nothing exposed by the workload and
	// works for any language, unlike the session profiler which needs a Go
	// pprof endpoint.
	// +optional
	// +kubebuilder:default=true
	ContinuousProfiling *bool `json:"continuousProfiling,omitempty"`

	// SockOpsRTT attaches a sock_ops program that reads the kernel's own
	// smoothed round-trip time, which no kprobe, uprobe, tracepoint or
	// cgroup_skb hook can reach. It makes net.rtt_spike_rate measure the
	// wire rather than syscall duration. Observation only: no sockmap, no
	// redirect, no payload access. Needs kernel 5.10 or newer and cgroup v2;
	// where it cannot attach the rule falls back to syscall latency.
	// +optional
	// +kubebuilder:default=true
	SockOpsRTT *bool `json:"sockOpsRTT,omitempty"`

	// +optional
	Alerting *AgentAlertingSpec `json:"alerting,omitempty"`

	// Metrics configures the continuous metrics plane, which runs unless
	// metrics.enabled is set to false.
	// +optional
	// +kubebuilder:default={}
	Metrics *AgentMetricsSpec `json:"metrics,omitempty"`

	// RolloutMaxUnavailable is how many agents may be updated at once when
	// the DaemonSet's pod template changes, as a count or a percentage.
	// +optional
	RolloutMaxUnavailable *intstr.IntOrString `json:"rolloutMaxUnavailable,omitempty"`
}

// AgentMetricsSpec configures the continuous metrics plane.
type AgentMetricsSpec struct {
	// Enabled runs the continuous metrics plane. On unless set to false.
	// +optional
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`

	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`

	// +optional
	Labels *AgentMetricsLabelsSpec `json:"labels,omitempty"`

	// +optional
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=2000000
	SeriesBudget *int32 `json:"seriesBudget,omitempty"`

	// +optional
	// +kubebuilder:default=true
	NativeHistograms *bool `json:"nativeHistograms,omitempty"`

	// +optional
	SemanticConventions bool `json:"semanticConventions,omitempty"`

	// KernelAggregation folds observations in a BPF map instead of shipping
	// one event per observation, so the plane costs O(series) rather than
	// O(events).
	// +optional
	// +kubebuilder:default=true
	KernelAggregation *bool `json:"kernelAggregation,omitempty"`

	// Filesystem adds regular-file reads, writes, fsyncs, opens and closes to
	// the plane. It needs kernelAggregation, which counts every operation in
	// the kernel; only operations of 1ms or more become events. Each traced
	// read or write costs the workload about 0.3µs where the kernel has
	// fentry (5.11+ with BTF) and about 0.9µs with kprobes. Set false to
	// leave filesystem latency to diagnose sessions.
	// +optional
	// +kubebuilder:default=true
	Filesystem *bool `json:"filesystem,omitempty"`

	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000
	AttributeCardinality *int32 `json:"attributeCardinality,omitempty"`

	// Inspections evaluate rules over this plane's own metrics and raise a
	// typed issue when one holds.
	// +optional
	// +kubebuilder:default={}
	Inspections *AgentInspectionsSpec `json:"inspections,omitempty"`
}

// AgentInspectionsSpec configures continuous inspections: the half of the
// plane that decides something is wrong, rather than only recording it.
type AgentInspectionsSpec struct {
	// Enabled runs the inspections. On unless set to false; they read the
	// metrics plane, so they are also off whenever it is.
	// +optional
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`

	// Interval is how often rules are evaluated. It doubles as the rate
	// window, so it has to be long enough for a counter delta to mean
	// something and short enough for an issue to be noticed.
	// +optional
	Interval *metav1.Duration `json:"interval,omitempty"`

	// Alerts controls whether an activated issue is raised as an alert,
	// which is what lets a PodTraceSchedule with an Issue trigger start a
	// session from it. With this off, inspections only expose
	// podtrace_issue_active.
	// +optional
	// +kubebuilder:default=true
	Alerts *bool `json:"alerts,omitempty"`

	// Budget bounds how many distinct issue instances an agent tracks.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100000
	Budget *int32 `json:"budget,omitempty"`

	// HoldTime replaces every rule's own hold duration, the time a condition
	// must hold before its issue activates. Leave unset to keep the built-in
	// per-rule defaults, which suit their signals; set it shorter for a test
	// run or longer for a workload whose bursts are expected.
	// +optional
	HoldTime *metav1.Duration `json:"holdTime,omitempty"`

	// Thresholds tune when the built-in rules fire.
	// +optional
	Thresholds *AgentInspectionThresholdsSpec `json:"thresholds,omitempty"`
}

// AgentInspectionThresholdsSpec tunes the built-in rules. Rule shapes are not
// configurable — that is what keeps the issue vocabulary meaningful — but the
// numbers they compare against are workload-specific.
type AgentInspectionThresholdsSpec struct {
	// ErrorRatePercent is the application-layer error ratio above which
	// l7.error_rate fires.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	ErrorRatePercent *int32 `json:"errorRatePercent,omitempty"`

	// MinRequestsPerMinute is the traffic floor below which the error-rate
	// rule stays quiet, so one failed request in an idle interval does not
	// read as a 100% error rate. Expressed per minute rather than per second
	// because the useful values are fractions of a request per second.
	// +optional
	// +kubebuilder:validation:Minimum=0
	MinRequestsPerMinute *int32 `json:"minRequestsPerMinute,omitempty"`

	// MeanLatency is the mean request duration above which
	// l7.latency_degraded fires.
	// +optional
	MeanLatency *metav1.Duration `json:"meanLatency,omitempty"`

	// AcquireMean is the mean time callers spend queued for a free database
	// connection above which db.connection_acquire_slow fires. Go database/sql only.
	// +optional
	AcquireMean *metav1.Duration `json:"acquireMean,omitempty"`

	// CPUBlockedMean is the mean time a workload spends off-CPU waiting to
	// be scheduled above which cpu.contention fires.
	// +optional
	CPUBlockedMean *metav1.Duration `json:"cpuBlockedMean,omitempty"`

	// PoolUtilizationPercent is the share of SetMaxOpenConns at which
	// db.pool_saturated fires as a warning; it escalates to critical ten
	// points higher. This fires before db.connection_acquire_slow, which
	// only notices once callers are already queueing.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	PoolUtilizationPercent *int32 `json:"poolUtilizationPercent,omitempty"`

	// DNSSlowLookupPercent is the share of a workload's DNS lookups slower
	// than 100ms above which dns.slow_lookup_rate fires.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	DNSSlowLookupPercent *int32 `json:"dnsSlowLookupPercent,omitempty"`

	// FSSlowOperationsPercent is the share of a workload's regular-file
	// reads, writes and fsyncs slower than 50ms above which
	// fs.slow_operations fires.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	FSSlowOperationsPercent *int32 `json:"fsSlowOperationsPercent,omitempty"`

	// DNSFailurePercent is the share of a workload's DNS lookups that fail
	// (SERVFAIL, REFUSED, another error rcode, or no answer) above which
	// dns.failure_rate fires. NXDOMAIN is an answer and never counts.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	DNSFailurePercent *int32 `json:"dnsFailurePercent,omitempty"`

	// TLSHandshakeFailurePercent is the share of a workload's TLS handshakes
	// that fail above which tls.handshake_failure_rate fires. Only
	// handshakes through Go's crypto/tls, OpenSSL, LibreSSL, BoringSSL,
	// GnuTLS and mbedTLS are seen.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	TLSHandshakeFailurePercent *int32 `json:"tlsHandshakeFailurePercent,omitempty"`
}

// AgentMetricsLabelsSpec opts into labels that are deliberately absent by
// default because each one multiplies series count.
type AgentMetricsLabelsSpec struct {
	// +optional
	Pod bool `json:"pod,omitempty"`

	// +optional
	Process bool `json:"process,omitempty"`
}

// AgentAlertingSpec configures agent-side resource-limit alert delivery.
type AgentAlertingSpec struct {
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// +optional
	WebhookURL string `json:"webhookURL,omitempty"`

	// +optional
	AllowInsecureWebhook bool `json:"allowInsecureWebhook,omitempty"`
}

// RedactionSpec configures PII redaction applied to event Target and Details
// fields in the tracer, before any exporter or report sink receives them.
type RedactionSpec struct {
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// +optional
	RedactDNSNames bool `json:"redactDNSNames,omitempty"`

	// +optional
	// +listType=map
	// +listMapKey=name
	CustomRules []RedactionRule `json:"customRules,omitempty"`
}

// CaptureSpec selects additional L7 request/response data to capture.
type CaptureSpec struct {
	// +optional
	// +kubebuilder:validation:MaxItems=4
	// +kubebuilder:validation:items:MaxLength=32
	// +kubebuilder:validation:items:Pattern=`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`
	Headers []string `json:"headers,omitempty"`
}

// RedactionRule is a single user-supplied redaction pattern.
type RedactionRule struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Pattern string `json:"pattern"`

	// +optional
	Replace string `json:"replace,omitempty"`
}

// SessionRuntimeSpec tunes the per-session Job pods the operator creates.
type SessionRuntimeSpec struct {
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	TTLSecondsAfterFinished *int32 `json:"ttlSecondsAfterFinished,omitempty"`

	// +optional
	ActiveDeadlineOffset *metav1.Duration `json:"activeDeadlineOffset,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	BackoffLimit *int32 `json:"backoffLimit,omitempty"`

	// +optional
	MaxDuration *metav1.Duration `json:"maxDuration,omitempty"`

	SidecarUploader bool `json:"sidecarUploader,omitempty"`
}

// MaxTracerConfigNameLength bounds a TracerConfig's metadata.name.
const MaxTracerConfigNameLength = 63

type TracerConfigSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:XValidation:rule="self.contains('/') && (self.split('/')[0].contains('.') || self.split('/')[0].contains(':') || self.split('/')[0] == 'localhost')",message="spec.image must be a fully-qualified image reference that includes a registry host, e.g. ghcr.io/org/app:tag"
	Image string `json:"image"`

	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// +optional
	// +kubebuilder:default={}
	Agent AgentSpec `json:"agent,omitempty"`

	// +optional
	Session SessionRuntimeSpec `json:"session,omitempty"`

	// +optional
	Redaction *RedactionSpec `json:"redaction,omitempty"`

	// +optional
	Capture *CaptureSpec `json:"capture,omitempty"`

	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// +optional
	BTFMode BTFMode `json:"btfMode,omitempty"`

	// BTFSource supplies the blob for btfMode "file". Ignored in every other
	// mode.
	// +optional
	BTFSource *BTFSource `json:"btfSource,omitempty"`

	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxConcurrentSessionsPerNode int32 `json:"maxConcurrentSessionsPerNode,omitempty"`

	// +optional
	SystemNamespace string `json:"systemNamespace,omitempty"`

	// +optional
	FleetPriority int32 `json:"fleetPriority,omitempty"`
}

// TracerConfigStatus reflects the observed state of a TracerConfig.
type TracerConfigStatus struct {
	DesiredAgents int32 `json:"desiredAgents,omitempty"`

	ReadyAgents int32 `json:"readyAgents,omitempty"`

	ActiveSessions int32 `json:"activeSessions,omitempty"`

	MatchedNodes int32 `json:"matchedNodes,omitempty"`

	ContestedNodes int32 `json:"contestedNodes,omitempty"`

	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=tc,categories=podtrace-all
// +kubebuilder:printcolumn:name="Desired",type=integer,JSONPath=`.status.desiredAgents`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.readyAgents`
// +kubebuilder:printcolumn:name="Sessions",type=integer,JSONPath=`.status.activeSessions`
// +kubebuilder:printcolumn:name="Contested",type=integer,priority=1,JSONPath=`.status.contestedNodes`
// +kubebuilder:printcolumn:name="Image",type=string,priority=1,JSONPath=`.spec.image`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TracerConfig is the infrastructure configuration for one podtrace agent
// fleet.
type TracerConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TracerConfigSpec   `json:"spec,omitempty"`
	Status TracerConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TracerConfigList contains a list of TracerConfig.
type TracerConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TracerConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(addKnownTypes(&TracerConfig{}, &TracerConfigList{}))
}
