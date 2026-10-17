package v1alpha1

// Defaults for the agent's on/off toggles.
//
// A toggle that defaults to on is a *bool, so "left out" and "set to false"
// stay distinguishable, and carries a +kubebuilder:default marker, so the API
// server fills it in and `kubectl get -o yaml` shows the value in effect.
// These constants are what the operator assumes when a field is still nil,
// which happens when an object was written before the schema had the
// default, or when the CRD installed in the cluster is older than the
// operator. Tests hold the schema markers, these constants and the chart's
// values.yaml to one another.
const (
	DefaultDNSPacketCapture       = true
	DefaultDNSFullAnswers         = true
	DefaultUSDT                   = true
	DefaultUprobeMulti            = true
	DefaultContinuousProfiling    = true
	DefaultSockOpsRTT             = true
	DefaultMetricsEnabled         = true
	DefaultNativeHistograms       = true
	DefaultKernelAggregation      = true
	DefaultFilesystemMetrics      = true
	DefaultInspectionsEnabled     = true
	DefaultInspectionsRaiseAlerts = true
)

func boolOr(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

// DNSPacketCaptureEnabled reports whether DNS is captured from packets.
func (a *AgentSpec) DNSPacketCaptureEnabled() bool {
	return boolOr(a.DNSPacketCapture, DefaultDNSPacketCapture)
}

// DNSFullAnswersEnabled reports whether every answer record is decoded.
func (a *AgentSpec) DNSFullAnswersEnabled() bool {
	return boolOr(a.DNSFullAnswers, DefaultDNSFullAnswers)
}

// USDTEnabled reports whether USDT probes are attached.
func (a *AgentSpec) USDTEnabled() bool {
	return boolOr(a.USDT, DefaultUSDT)
}

// UprobeMultiEnabled reports whether uprobes may be attached as uprobe_multi
// links.
func (a *AgentSpec) UprobeMultiEnabled() bool {
	return boolOr(a.UprobeMulti, DefaultUprobeMulti)
}

// ContinuousProfilingEnabled reports whether the agent serves /profile.
func (a *AgentSpec) ContinuousProfilingEnabled() bool {
	return boolOr(a.ContinuousProfiling, DefaultContinuousProfiling)
}

// SockOpsRTTEnabled reports whether the sock_ops RTT program is attached.
func (a *AgentSpec) SockOpsRTTEnabled() bool {
	return boolOr(a.SockOpsRTT, DefaultSockOpsRTT)
}

// MetricsEnabled reports whether the continuous metrics plane runs. A nil
// spec is the plane with every default, so it is on.
func (m *AgentMetricsSpec) MetricsEnabled() bool {
	if m == nil {
		return DefaultMetricsEnabled
	}
	return boolOr(m.Enabled, DefaultMetricsEnabled)
}

// NativeHistogramsEnabled reports whether histograms are exposed as native
// histograms.
func (m *AgentMetricsSpec) NativeHistogramsEnabled() bool {
	if m == nil {
		return DefaultNativeHistograms
	}
	return boolOr(m.NativeHistograms, DefaultNativeHistograms)
}

// KernelAggregationEnabled reports whether observations are folded in a BPF
// map rather than shipped one event at a time.
func (m *AgentMetricsSpec) KernelAggregationEnabled() bool {
	if m == nil {
		return DefaultKernelAggregation
	}
	return boolOr(m.KernelAggregation, DefaultKernelAggregation)
}

// FilesystemEnabled reports whether the plane covers regular-file
// operations.
func (m *AgentMetricsSpec) FilesystemEnabled() bool {
	if m == nil {
		return DefaultFilesystemMetrics
	}
	return boolOr(m.Filesystem, DefaultFilesystemMetrics)
}

// InspectionsSpec returns the inspections block, nil when there is none.
func (m *AgentMetricsSpec) InspectionsSpec() *AgentInspectionsSpec {
	if m == nil {
		return nil
	}
	return m.Inspections
}

// InspectionsEnabled reports whether inspections run. They read the metrics
// plane, so they are off whenever the plane is.
func (m *AgentMetricsSpec) InspectionsEnabled() bool {
	return m.MetricsEnabled() && m.InspectionsSpec().IsEnabled()
}

// IsEnabled reports whether this inspections block is switched on. A nil
// block is every default, so it is on.
func (i *AgentInspectionsSpec) IsEnabled() bool {
	if i == nil {
		return DefaultInspectionsEnabled
	}
	return boolOr(i.Enabled, DefaultInspectionsEnabled)
}

// RaiseAlerts reports whether an activated issue is raised as an alert.
func (i *AgentInspectionsSpec) RaiseAlerts() bool {
	if i == nil {
		return DefaultInspectionsRaiseAlerts
	}
	return boolOr(i.Alerts, DefaultInspectionsRaiseAlerts)
}
