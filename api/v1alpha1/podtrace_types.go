package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodTraceSpec defines a continuous, realtime tracing intent over a set of pods.
// PodTrace is the continuous-observability counterpart of PodTraceSession: it
// has no bounded duration and remains active until the resource is deleted or
// paused.
// +kubebuilder:validation:XValidation:rule="[has(self.selector), has(self.podRefs), has(self.appSelector)].filter(x, x).size() == 1",message="exactly one of spec.selector, spec.podRefs, or spec.appSelector must be set"
type PodTraceSpec struct {
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// +optional
	PodRefs []PodRef `json:"podRefs,omitempty"`

	// +optional
	AppSelector *AppSelector `json:"appSelector,omitempty"`

	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// ContainerName narrows tracing to one named container of each matched
	// pod. Empty means every running container (including restartable-init
	// sidecars and ephemeral containers) is traced.
	// +optional
	ContainerName string `json:"containerName,omitempty"`

	// +optional
	Filters []EventFilter `json:"filters,omitempty"`

	// +kubebuilder:validation:Required
	ExporterRef corev1.LocalObjectReference `json:"exporterRef"`

	// +optional
	Thresholds *Thresholds `json:"thresholds,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	SamplePercent *int32 `json:"samplePercent,omitempty"`

	// +optional
	Paused bool `json:"paused,omitempty"`
}

// NodeStatusReason is the stable enum the agent stamps onto
// status.nodeStatus[].reason when a node reports unready or a CR rule
// fails.
// +kubebuilder:validation:Enum=AgentUnready;BackendUnavailable;BundleLoadFailed;ExporterBuildFailed;ProgramAttachFailed;PolicyParseError;PodMatchFailed;CgroupResolutionFailed;Unknown
type NodeStatusReason string

var (
	NodeStatusReasonAgentUnready           = NodeStatusReason("AgentUnready")
	NodeStatusReasonBackendUnavailable     = NodeStatusReason("BackendUnavailable")
	NodeStatusReasonBundleLoadFailed       = NodeStatusReason("BundleLoadFailed")
	NodeStatusReasonExporterBuildFailed    = NodeStatusReason("ExporterBuildFailed")
	NodeStatusReasonProgramAttachFailed    = NodeStatusReason("ProgramAttachFailed")
	NodeStatusReasonPolicyParseError       = NodeStatusReason("PolicyParseError")
	NodeStatusReasonPodMatchFailed         = NodeStatusReason("PodMatchFailed")
	NodeStatusReasonCgroupResolutionFailed = NodeStatusReason("CgroupResolutionFailed")
	NodeStatusReasonUnknown                = NodeStatusReason("Unknown")
)

// PodTraceNodeStatus reports one agent's view of this PodTrace.
type PodTraceNodeStatus struct {
	// +kubebuilder:validation:Required
	Node string `json:"node"`

	// Ready is a plain bool rather than a Condition on purpose: this is a
	// per-node entry inside an array, and Conditions cannot be expressed per
	// array element. It is the only readiness signal available here, so it
	// duplicates nothing. Object-level readiness is a Condition, as usual.
	Ready bool `json:"ready"`

	// +optional
	MatchedPods int32 `json:"matchedPods,omitempty"`

	ActiveCgroups int32 `json:"activeCgroups"`

	TotalEvents int64 `json:"totalEvents"`

	DroppedEvents int64 `json:"droppedEvents"`

	LastHeartbeat metav1.Time `json:"lastHeartbeat"`

	// +optional
	Message string `json:"message,omitempty"`

	// +optional
	Reason NodeStatusReason `json:"reason,omitempty"`

	PolicyHash string `json:"policyHash,omitempty"`
}

// PolicyStatus is the operator-side view of the effective policy a
// PodTrace imposes on the bundle.
type PolicyStatus struct {
	// +optional
	EffectiveSampleRate *int32 `json:"effectiveSampleRate,omitempty"`

	// +optional
	Filters []EventFilter `json:"filters,omitempty"`

	// +optional
	Thresholds *Thresholds `json:"thresholds,omitempty"`

	// +optional
	Hash string `json:"hash,omitempty"`

	// +optional
	Generation int64 `json:"generation,omitempty"`
}

// PodTraceStatus reflects the observed state of a PodTrace.
type PodTraceStatus struct {
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// +optional
	// +patchMergeKey=node
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=node
	NodeStatus []PodTraceNodeStatus `json:"nodeStatus,omitempty" patchStrategy:"merge" patchMergeKey:"node"`

	MatchedPods int32 `json:"matchedPods,omitempty"`

	TargetNamespaces []string `json:"targetNamespaces,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +optional
	Policy *PolicyStatus `json:"policy,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pt,categories=podtrace-all
// +kubebuilder:printcolumn:name="Matched",type=integer,JSONPath=`.status.matchedPods`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Exporter",type=string,JSONPath=`.spec.exporterRef.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PodTrace is a continuous realtime eBPF trace over a dynamic set of pods.
type PodTrace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PodTraceSpec   `json:"spec,omitempty"`
	Status PodTraceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PodTraceList contains a list of PodTrace.
type PodTraceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodTrace `json:"items"`
}

func init() {
	SchemeBuilder.Register(addKnownTypes(&PodTrace{}, &PodTraceList{}))
}
