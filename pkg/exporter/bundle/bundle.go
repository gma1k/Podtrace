// Package bundle defines the wire format for exporter configuration that
// travels between the podtrace operator, agent, and CLI.
//
// One shared schema means all three consume exporter config identically:
//
//   - operator renders an ExporterConfig CR into ConfigMap.data
//     (key/value strings) plus an optional companion Secret.
//   - agent reads that ConfigMap and constructs its in-process exporter.
//   - CLI reads a YAML file mounted from the same ConfigMap (via
//     --exporter-from-file) and sets the equivalent config globals.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CredentialKey is the fixed key under which the operator stores the
// resolved credential material in the companion Secret.
const CredentialKey = "credential"

// SecretHeaderKeyPrefix prefixes bundle-Secret keys that carry one
// Secret-backed header each (OTLP headersFromSecret): "header.<name>" maps
// to header <name>. Kept in the Secret — never the ConfigMap — because the
// values are credential material.
const SecretHeaderKeyPrefix = "header."

const CurrentVersion = "v2"

type Type string

const (
	TypeOTLP    Type = "otlp"
	TypeJaeger  Type = "jaeger"
	TypeZipkin  Type = "zipkin"
	TypeSplunk  Type = "splunk"
	TypeDataDog Type = "datadog"
)

// FilterCategory enumerates the event categories an operator may push into
// the bundle.
type FilterCategory string

const (
	FilterDNS  FilterCategory = "dns"
	FilterNet  FilterCategory = "net"
	FilterFS   FilterCategory = "fs"
	FilterCPU  FilterCategory = "cpu"
	FilterProc FilterCategory = "proc"
)

// Thresholds carries the anomaly-detection rules an agent applies to
// every event it forwards on behalf of a CR.
type Thresholds struct {
	ErrorRatePercent    *int32 `yaml:"errorRatePercent,omitempty"`
	RTTSpikeMs          *int32 `yaml:"rttSpikeMs,omitempty"`
	FilesystemLatencyMs *int32 `yaml:"fsSlowMs,omitempty"`
}

// IsZero reports whether the thresholds carry any configured value.
func (t *Thresholds) IsZero() bool {
	return t == nil || (t.ErrorRatePercent == nil && t.RTTSpikeMs == nil && t.FilesystemLatencyMs == nil)
}

type Payload struct {
	Version string `yaml:"version,omitempty"`

	Type Type `yaml:"type"`

	Endpoint string `yaml:"endpoint,omitempty"`

	Protocol string `yaml:"protocol,omitempty"`

	Insecure bool `yaml:"insecure,omitempty"`

	Site string `yaml:"site,omitempty"`

	Sample *float64 `yaml:"sample,omitempty"`

	SynthesizeSpans bool `yaml:"synthesizeSpans,omitempty"`

	Metrics bool `yaml:"metrics,omitempty"`

	MetricsInterval time.Duration `yaml:"metricsInterval,omitempty"`

	Headers map[string]string `yaml:"headers,omitempty"`

	HeaderName string `yaml:"headerName,omitempty"`

	// TargetNamespaces is the resolved allowlist of namespace names a
	// PodTrace's spec.namespaceSelector matched at bundle-render time.
	// The semantics are tri-state and the wire format preserves all
	// three (see ConfigMapHasTargetNamespacesKey for the on-wire
	// representation):
	//
	//	nil         — spec.namespaceSelector is nil on the CR; agents
	//	              fall back to own-namespace matching (legacy).
	//	[]string{}  — spec.namespaceSelector is set but matched no
	//	              namespaces; agents match nothing for this CR.
	//	["a", "b"]  — spec.namespaceSelector matched these namespaces.
	TargetNamespaces []string `yaml:"targetNamespaces,omitempty"`

	Filters []FilterCategory `yaml:"filters,omitempty"`

	Thresholds *Thresholds `yaml:"thresholds,omitempty"`

	PolicyGeneration int64 `yaml:"policyGeneration,omitempty"`

	Credential []byte `yaml:"-"`

	SecretHeaders map[string]string `yaml:"-"`

	ResourceVer string `yaml:"-"`

	SamplingKey string `yaml:"-"`
}

// FromConfigMapData parses the flat ConfigMap data written by the
// operator into a structured Payload. Unknown keys are ignored.
func FromConfigMapData(data map[string]string) (*Payload, error) {
	if data == nil {
		return nil, fmt.Errorf("bundle: nil ConfigMap data")
	}
	if v := data["version"]; v != "" && v != CurrentVersion {
		return nil, fmt.Errorf("bundle: unsupported version %q (this build understands %q)", v, CurrentVersion)
	}
	p := &Payload{
		Version:    data["version"],
		Type:       Type(data["type"]),
		Endpoint:   data["endpoint"],
		Protocol:   data["protocol"],
		Site:       data["site"],
		HeaderName: data["header_secret_name"],
	}
	if v := data["insecure"]; v != "" {
		p.Insecure = v == "true"
	}
	if v := data["synthesize_spans"]; v != "" {
		p.SynthesizeSpans = v == "true"
	}
	if v := data["metrics"]; v != "" {
		p.Metrics = v == "true"
	}
	if v := data["metrics_interval_seconds"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("bundle: metrics_interval_seconds %q not an integer: %w", v, err)
		}
		if n < 0 {
			return nil, fmt.Errorf("bundle: metrics_interval_seconds %d must be non-negative", n)
		}
		p.MetricsInterval = time.Duration(n) * time.Second
	}
	if v, ok := data["sample_percent"]; ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("bundle: sample_percent %q not an integer: %w", v, err)
		}
		if n < 0 || n > 100 {
			return nil, fmt.Errorf("bundle: sample_percent %d out of range 0-100", n)
		}
		sample := float64(n) / 100.0
		p.Sample = &sample
	}
	for k, v := range data {
		if rest, ok := strings.CutPrefix(k, "headers."); ok {
			if p.Headers == nil {
				p.Headers = map[string]string{}
			}
			p.Headers[rest] = v
		}
	}
	if raw, ok := data["filters"]; ok && raw != "" {
		parts := strings.Split(raw, ",")
		filters := make([]FilterCategory, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			filters = append(filters, FilterCategory(part))
		}
		if len(filters) > 0 {
			p.Filters = filters
		}
	}
	thresholds, err := readThresholds(data)
	if err != nil {
		return nil, err
	}
	p.Thresholds = thresholds
	if raw, ok := data["policy_generation"]; ok && raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bundle: policy_generation %q not an integer: %w", raw, err)
		}
		p.PolicyGeneration = n
	}
	if raw, ok := data["target_namespaces"]; ok {
		if raw == "" {
			p.TargetNamespaces = []string{}
		} else {
			p.TargetNamespaces = strings.Split(raw, ",")
		}
	}
	if err := validatePayload(p); err != nil {
		return nil, err
	}
	return p, nil
}

// readThresholds reconstructs the Thresholds struct from the flat
// ConfigMap data, preserving key-presence semantics so "unset" round-trips
// distinctly from "0".
func readThresholds(data map[string]string) (*Thresholds, error) {
	var t Thresholds
	var anyPresent bool
	for _, spec := range thresholdFields() {
		raw, ok := data[spec.key]
		if !ok || raw == "" {
			continue
		}
		parsed, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bundle: %s %q not a 32-bit integer: %w", spec.key, raw, err)
		}
		if parsed < 0 {
			return nil, fmt.Errorf("bundle: %s %d must be non-negative", spec.key, parsed)
		}
		if spec.max > 0 && parsed > int64(spec.max) {
			return nil, fmt.Errorf("bundle: %s %d out of range 0-%d", spec.key, parsed, spec.max)
		}
		val := int32(parsed)
		spec.set(&t, &val)
		anyPresent = true
	}
	if !anyPresent {
		return nil, nil
	}
	return &t, nil
}

type thresholdField struct {
	key string
	max int
	get func(*Thresholds) *int32
	set func(*Thresholds, *int32)
}

func thresholdFields() []thresholdField {
	return []thresholdField{
		{
			key: "threshold_error_rate_percent",
			max: 100,
			get: func(t *Thresholds) *int32 { return t.ErrorRatePercent },
			set: func(t *Thresholds, v *int32) { t.ErrorRatePercent = v },
		},
		{
			key: "threshold_rtt_spike_ms",
			get: func(t *Thresholds) *int32 { return t.RTTSpikeMs },
			set: func(t *Thresholds, v *int32) { t.RTTSpikeMs = v },
		},
		{
			key: "threshold_fs_slow_ms",
			get: func(t *Thresholds) *int32 { return t.FilesystemLatencyMs },
			set: func(t *Thresholds, v *int32) { t.FilesystemLatencyMs = v },
		},
	}
}

// ToConfigMapData renders a Payload back into the flat ConfigMap schema.
// Inverse of FromConfigMapData for all fields operator-side bundle
// reconcilers care about.
func ToConfigMapData(p *Payload) map[string]string {
	if p == nil {
		return nil
	}
	out := map[string]string{
		"version": CurrentVersion,
		"type":    string(p.Type),
	}
	if p.Endpoint != "" {
		out["endpoint"] = p.Endpoint
	}
	if p.Protocol != "" {
		out["protocol"] = p.Protocol
	}
	if p.Site != "" {
		out["site"] = p.Site
	}
	if p.HeaderName != "" {
		out["header_secret_name"] = p.HeaderName
	}
	if p.Insecure {
		out["insecure"] = "true"
	} else if p.Type == TypeOTLP {
		out["insecure"] = "false"
	}
	if p.Sample != nil {
		percent := int(*p.Sample*100 + 0.5)
		out["sample_percent"] = strconv.Itoa(percent)
	}
	if p.SynthesizeSpans {
		out["synthesize_spans"] = "true"
	}
	if p.Metrics {
		out["metrics"] = "true"
	}
	if p.MetricsInterval > 0 {
		out["metrics_interval_seconds"] = strconv.Itoa(int(p.MetricsInterval / time.Second))
	}
	keys := make([]string, 0, len(p.Headers))
	for k := range p.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out["headers."+k] = p.Headers[k]
	}
	if p.TargetNamespaces != nil {
		sorted := make([]string, len(p.TargetNamespaces))
		copy(sorted, p.TargetNamespaces)
		sort.Strings(sorted)
		out["target_namespaces"] = strings.Join(sorted, ",")
	}
	if len(p.Filters) > 0 {
		filters := make([]string, 0, len(p.Filters))
		for _, f := range p.Filters {
			if f == "" {
				continue
			}
			filters = append(filters, string(f))
		}
		sort.Strings(filters)
		filters = dedupeSortedStrings(filters)
		out["filters"] = strings.Join(filters, ",")
	}
	if !p.Thresholds.IsZero() {
		for _, spec := range thresholdFields() {
			if v := spec.get(p.Thresholds); v != nil {
				out[spec.key] = strconv.FormatInt(int64(*v), 10)
			}
		}
	}
	if p.PolicyGeneration > 0 {
		out["policy_generation"] = strconv.FormatInt(p.PolicyGeneration, 10)
	}
	out["policy_hash"] = PolicyHash(p)
	return out
}

// dedupeSortedStrings removes adjacent duplicates from a sorted slice.
func dedupeSortedStrings(in []string) []string {
	if len(in) <= 1 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// PolicyHash returns a stable hex sha256 over the policy-bearing fields
// of a Payload.
func PolicyHash(p *Payload) string {
	if p == nil {
		return ""
	}
	h := sha256.New()
	if len(p.Filters) > 0 {
		filters := make([]string, len(p.Filters))
		for i, f := range p.Filters {
			filters[i] = string(f)
		}
		sort.Strings(filters)
		filters = dedupeSortedStrings(filters)
		_, _ = fmt.Fprintf(h, "filters=%s\n", strings.Join(filters, ","))
	}
	if p.Sample != nil {
		_, _ = fmt.Fprintf(h, "sample_percent=%d\n", int(*p.Sample*100+0.5))
	}
	if !p.Thresholds.IsZero() {
		for _, spec := range thresholdFields() {
			if v := spec.get(p.Thresholds); v != nil {
				_, _ = fmt.Fprintf(h, "%s=%d\n", spec.key, *v)
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// validatePayload enforces the semantic constraints every Payload wire format
// shares
func validatePayload(p *Payload) error {
	if p.Version != "" && p.Version != CurrentVersion {
		return fmt.Errorf("bundle: unsupported version %q (this build understands %q)", p.Version, CurrentVersion)
	}
	if p.Type == "" {
		return fmt.Errorf("bundle: missing required field 'type'")
	}
	if p.Sample != nil && (*p.Sample < 0 || *p.Sample > 1) {
		return fmt.Errorf("bundle: sample %v out of range 0-1", *p.Sample)
	}
	if p.Metrics && p.Type != TypeOTLP {
		return fmt.Errorf("bundle: metrics export requires type %q, got %q", TypeOTLP, p.Type)
	}
	if p.MetricsInterval < 0 {
		return fmt.Errorf("bundle: metricsInterval %v must be non-negative", p.MetricsInterval)
	}
	if p.Thresholds != nil {
		for _, spec := range thresholdFields() {
			v := spec.get(p.Thresholds)
			if v == nil {
				continue
			}
			if *v < 0 {
				return fmt.Errorf("bundle: %s %d must be non-negative", spec.key, *v)
			}
			if spec.max > 0 && int(*v) > spec.max {
				return fmt.Errorf("bundle: %s %d out of range 0-%d", spec.key, *v, spec.max)
			}
		}
	}
	return nil
}

// FromYAML parses a Payload from its YAML serialization.
func FromYAML(raw []byte) (*Payload, error) {
	var p Payload
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("bundle: parse YAML: %w", err)
	}
	if err := validatePayload(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ToYAML renders a Payload as YAML. The operator writes this shape into
// the Job's mounted ConfigMap so the CLI sees identical fields to what
// the agent sees via FromConfigMapData.
func ToYAML(p *Payload) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("bundle: nil payload")
	}
	out := *p
	out.Version = CurrentVersion
	raw, err := yaml.Marshal(&out)
	if err != nil {
		return nil, err
	}
	// targetNamespaces is tri-state (nil / empty / populated), but
	// omitempty drops BOTH nil and []string{} — an empty allowlist
	// ("match nothing") round-tripped to nil ("legacy own-namespace
	// fallback") and the session traced pods it was told to exclude.
	// Re-add the key explicitly for the empty-but-set case; FromYAML's
	// unmarshal already distinguishes a present empty list from absence.
	if p.TargetNamespaces != nil && len(p.TargetNamespaces) == 0 {
		raw = append(raw, []byte("targetNamespaces: []\n")...)
	}
	return raw, nil
}
