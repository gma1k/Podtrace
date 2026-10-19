package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodRef references a specific pod by namespace/name.
type PodRef struct {
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// SecretKeySelector selects a key from a Secret in the same namespace.
type SecretKeySelector struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// AppSelector matches pods that satisfy ANY of its label selectors, so
// an application composed of several workloads with distinct labels
// can be traced as one.
type AppSelector struct {
	// +kubebuilder:validation:MinItems=1
	MatchSelectors []metav1.LabelSelector `json:"matchSelectors"`
}

// EventFilter enumerates the event categories podtrace can capture.
// +kubebuilder:validation:Enum=dns;net;fs;cpu;proc;crypto;usdt
type EventFilter string

const (
	FilterDNS    EventFilter = "dns"
	FilterNet    EventFilter = "net"
	FilterFS     EventFilter = "fs"
	FilterCPU    EventFilter = "cpu"
	FilterProc   EventFilter = "proc"
	FilterCrypto EventFilter = "crypto"
	FilterUSDT   EventFilter = "usdt"
)

// Thresholds control anomaly detection on the agent side.
type Thresholds struct {
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	ErrorRatePercent *int32 `json:"errorRatePercent,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	RTTSpikeMs *int32 `json:"rttSpikeMs,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	FilesystemLatencyMs *int32 `json:"filesystemLatencyMs,omitempty"`
}

// ReportReference describes where a session's diagnose report is persisted.
// Exactly one sink should be set.
type ReportReference struct {
	// +optional
	ConfigMap *corev1.LocalObjectReference `json:"configMap,omitempty"`

	// +optional
	Secret *corev1.LocalObjectReference `json:"secret,omitempty"`

	// +optional
	ObjectStore *ObjectStoreReference `json:"objectStore,omitempty"`
}

// ObjectStoreReference names a cloud-storage destination for a session
// report. When CredentialsSecretRef is unset, the uploader uses the
// cloud SDK's default credential chain (IRSA / Workload Identity /
// Managed Identity). That ambient fallback is allowed for sessions in
// the operator's own namespace; sessions in other namespaces need the
// operator's cross-namespace ambient-credentials opt-in or a Secret with
// static credentials. A custom endpoint is honoured only alongside
// static credentials or when the operator's endpoint allowlist names it.
//
// Per-backend Secret key schema (all optional — missing keys defer to
// the SDK default chain, subject to the rules above):
//
//	S3:     access_key_id, secret_access_key, session_token,
//	        region, endpoint, force_path_style
//	GCS:    service_account_json, endpoint
//	Azure:  tenant_id, client_id, client_secret,
//	        account_key, endpoint
type ObjectStoreReference struct {
	// URI of the destination. Three schemes:
	//
	//   s3://bucket/key-or-prefix
	//   gs://bucket/key-or-prefix
	//   azblob://account/container/key-or-prefix
	//
	// A trailing slash means "prefix mode" — the uploader appends a
	// per-session filename (<pod-name>-<rfc3339>.txt) and an additional
	// <key>.summary.json object. Without a trailing slash, the URI's
	// path is used verbatim as the object key.
	// +kubebuilder:validation:Required
	URI string `json:"uri"`

	// +optional
	CredentialsSecretRef *corev1.LocalObjectReference `json:"credentialsSecretRef,omitempty"`
}
