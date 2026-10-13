package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ApplicationTraceSpec declares continuous tracing for a whole application:
// the set of workloads its AppSelector matches, optionally across namespaces.
type ApplicationTraceSpec struct {
	// +kubebuilder:validation:Required
	AppSelector AppSelector `json:"appSelector"`

	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// +kubebuilder:validation:Required
	ExporterRef corev1.LocalObjectReference `json:"exporterRef"`

	// +optional
	Filters []EventFilter `json:"filters,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	SamplePercent *int32 `json:"samplePercent,omitempty"`

	// +optional
	Thresholds *Thresholds `json:"thresholds,omitempty"`

	// +optional
	Paused bool `json:"paused,omitempty"`
}

// ApplicationTraceStatus reflects the observed state of an ApplicationTrace,
// aggregated from its generated PodTrace.
type ApplicationTraceStatus struct {
	// +optional
	PodTraceRef *corev1.LocalObjectReference `json:"podTraceRef,omitempty"`

	// +optional
	MatchedPods int32 `json:"matchedPods,omitempty"`

	// +optional
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`

	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=appt,categories=podtrace-all
// +kubebuilder:printcolumn:name="Matched",type=integer,JSONPath=`.status.matchedPods`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Exporter",type=string,JSONPath=`.spec.exporterRef.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ApplicationTrace is the user-facing "application" object: it owns and keeps
// in sync a single PodTrace that traces all of the application's workloads.
type ApplicationTrace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ApplicationTraceSpec   `json:"spec,omitempty"`
	Status ApplicationTraceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ApplicationTraceList contains a list of ApplicationTrace.
type ApplicationTraceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApplicationTrace `json:"items"`
}

func init() {
	SchemeBuilder.Register(addKnownTypes(&ApplicationTrace{}, &ApplicationTraceList{}))
}
