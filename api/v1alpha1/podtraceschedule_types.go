package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConcurrencyPolicy describes how the schedule reconciles overlapping
// scheduled runs. It mirrors the semantics of batch/v1.CronJob.
// +kubebuilder:validation:Enum=Allow;Forbid;Replace
type ConcurrencyPolicy string

const (
	AllowConcurrent ConcurrencyPolicy = "Allow"

	ForbidConcurrent ConcurrencyPolicy = "Forbid"

	ReplaceConcurrent ConcurrencyPolicy = "Replace"
)

// PodTraceSessionTemplateSpec describes the desired state of the
// PodTraceSession resources the schedule will produce.
type PodTraceSessionTemplateSpec struct {
	// +optional
	Metadata PodTraceSessionTemplateMetadata `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec PodTraceSessionSpec `json:"spec"`
}

// PodTraceSessionTemplateMetadata is the subset of ObjectMeta the
// schedule controller propagates to child sessions.
type PodTraceSessionTemplateMetadata struct {
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PodTraceScheduleSpec describes a PodTraceSession source. Exactly one of
// Schedule (recurring, cron-driven) or Trigger (event-driven, fired by an
// agent-detected alert) must be set; the validating webhook enforces this.
type PodTraceScheduleSpec struct {
	// Schedule is the cron expression that triggers session creation.
	// Accepts the standard 5-field form ("*/5 * * * *") and the 6-field
	// form with leading seconds ("0 */5 * * * *"). Descriptors such as
	// "@hourly", "@daily" and "@every 5m" are also accepted.
	//
	// Mutually exclusive with Trigger; exactly one of the two must be set.
	// +optional
	Schedule string `json:"schedule,omitempty"`

	// Trigger fires a session in response to an agent-detected alert
	// (resource-limit breach, OOM kill, error-rate spike) rather than on a
	// clock — the "flight recorder" mode. Mutually exclusive with Schedule.
	// +optional
	Trigger *TriggerSpec `json:"trigger,omitempty"`

	// TimeZone is an IANA time-zone name (e.g. "Europe/Amsterdam") used
	// to interpret Schedule.
	// +optional
	TimeZone *string `json:"timeZone,omitempty"`

	// +kubebuilder:default=Allow
	// +optional
	ConcurrencyPolicy ConcurrencyPolicy `json:"concurrencyPolicy,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	StartingDeadlineSeconds *int64 `json:"startingDeadlineSeconds,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=3
	// +optional
	SuccessfulSessionsHistoryLimit *int32 `json:"successfulSessionsHistoryLimit,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=1
	// +optional
	FailedSessionsHistoryLimit *int32 `json:"failedSessionsHistoryLimit,omitempty"`

	// +optional
	Suspend *bool `json:"suspend,omitempty"`

	// +kubebuilder:validation:Minimum=0
	// +optional
	MaxActiveSessions *int32 `json:"maxActiveSessions,omitempty"`

	// +kubebuilder:validation:Required
	SessionTemplate PodTraceSessionTemplateSpec `json:"sessionTemplate"`
}

// +kubebuilder:validation:Enum=ResourceAlert;OOMKill;ErrorRate;Issue
type TriggerSourceKind string

const (
	TriggerSourceResourceAlert TriggerSourceKind = "ResourceAlert"

	TriggerSourceOOMKill TriggerSourceKind = "OOMKill"

	TriggerSourceErrorRate TriggerSourceKind = "ErrorRate"

	// TriggerSourceIssue fires on any detected issue. Select a specific one
	// with TriggerSource.IssueID.
	TriggerSourceIssue TriggerSourceKind = "Issue"
)

// TriggerSource selects one alert category and the minimum severity that
// arms the trigger.
// +kubebuilder:validation:XValidation:rule="!has(self.issueID) || self.kind == 'Issue'",message="issueID applies only to kind Issue"
type TriggerSource struct {
	// TriggerSourceKind names an agent-detected alert category that can fire a
	// triggered session.
	// +kubebuilder:validation:Required
	Kind TriggerSourceKind `json:"kind"`

	// MinSeverity is the minimum alert severity that fires, ordered
	// warning < critical < fatal. Defaults to critical so noisy warnings
	// do not spawn privileged Jobs unless explicitly opted into.
	// +kubebuilder:validation:Enum=warning;critical;fatal
	// +optional
	MinSeverity string `json:"minSeverity,omitempty"`

	// IssueID narrows an Issue source to one issue, such as l7.error_rate.
	// Leave it unset to fire on every issue. The ids are listed in
	// docs/continuous-inspections.md.
	// +kubebuilder:validation:Enum=net.connection_failure_rate;net.rtt_spike_rate;resource.saturation;l7.error_rate;l7.latency_degraded;db.connection_acquire_slow;db.pool_saturated;cpu.contention;dns.slow_lookup_rate;fs.slow_operations;dns.failure_rate;tls.handshake_failure_rate
	// +optional
	IssueID string `json:"issueID,omitempty"`
}

// TriggerSpec configures event-driven ("flight recorder") session creation.
type TriggerSpec struct {
	// Sources are the alert categories that fire a session. A session fires
	// when an observed alert matches ANY listed source (its Kind and at
	// least its MinSeverity).
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Sources []TriggerSource `json:"sources"`

	// Selector narrows which pods' alerts arm the trigger. An empty
	// selector matches every pod in scope (subject to NamespaceSelector).
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// NamespaceSelector widens matching across namespaces, subject to the
	// same target-namespace consent model as PodTrace.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// Cooldown is the minimum time after a session fires for a given pod
	// before another session may fire for that same pod.
	// +optional
	Cooldown *metav1.Duration `json:"cooldown,omitempty"`

	// MaxSessionsPerHour caps how many triggered sessions this schedule may
	// create per rolling hour across all pods, a fleet-wide backstop against
	// a broad alert storm.
	// +kubebuilder:validation:Minimum=1
	// +optional
	MaxSessionsPerHour *int32 `json:"maxSessionsPerHour,omitempty"`

	// ConcurrencyPolicy governs overlap with already-active triggered
	// sessions. Defaults to Forbid, the safe default for the privileged
	// Jobs a session runs.
	// +kubebuilder:default=Forbid
	// +optional
	ConcurrencyPolicy ConcurrencyPolicy `json:"concurrencyPolicy,omitempty"`
}

// TriggerFiring records a single triggered-session creation, used to enforce
// per-pod cooldown and the rolling-hour rate cap idempotently across
// reconciles.
type TriggerFiring struct {
	// +kubebuilder:validation:Required
	PodName string `json:"podName"`

	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`

	// +kubebuilder:validation:Required
	Time metav1.Time `json:"time"`

	// +optional
	SessionName string `json:"sessionName,omitempty"`
}

// TriggerStatus records trigger firing history. Present only for
// trigger-mode schedules.
type TriggerStatus struct {
	// RecentFirings is a bounded, time-ordered log (oldest first) of the
	// sessions this trigger created. The controller prunes entries older
	// than the cooldown and the rate window so it cannot grow unbounded.
	// +optional
	// +listType=atomic
	RecentFirings []TriggerFiring `json:"recentFirings,omitempty"`
}

// PodTraceScheduleStatus reflects the observed state of a
// PodTraceSchedule.
type PodTraceScheduleStatus struct {
	// +optional
	Trigger *TriggerStatus `json:"trigger,omitempty"`

	// +optional
	Active []corev1.ObjectReference `json:"active,omitempty"`

	// +optional
	LastScheduleTime *metav1.Time `json:"lastScheduleTime,omitempty"`

	// +optional
	LastSuccessfulTime *metav1.Time `json:"lastSuccessfulTime,omitempty"`

	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ptsch,categories=podtrace-all
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule`
// +kubebuilder:printcolumn:name="Suspend",type=boolean,JSONPath=`.spec.suspend`
// +kubebuilder:printcolumn:name="Active",type=string,JSONPath=`.status.active[*].name`,priority=1
// +kubebuilder:printcolumn:name="Last Schedule",type=date,JSONPath=`.status.lastScheduleTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PodTraceSchedule describes a recurring PodTraceSession. The schedule
// controller creates a new session on each cron tick, subject to the
// ConcurrencyPolicy.
type PodTraceSchedule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PodTraceScheduleSpec   `json:"spec,omitempty"`
	Status PodTraceScheduleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type PodTraceScheduleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodTraceSchedule `json:"items"`
}

func init() {
	SchemeBuilder.Register(addKnownTypes(&PodTraceSchedule{}, &PodTraceScheduleList{}))
}
