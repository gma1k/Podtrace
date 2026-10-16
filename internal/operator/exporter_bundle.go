package operator

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

// renderBundlePayload converts an ExporterConfig's typed spec — plus the
// policy carried by the referent PodTrace (filters, sample, thresholds) —
// into the flat ConfigMap data plus an optional credential-Secret reference
// the operator will copy into systemNS.
//
// Bundle schema (ConfigMap.data):
//
//	version                       = bundle protocol version (always stamped)
//	type                          = otlp | jaeger | zipkin | splunk | datadog
//	endpoint                      = full URL or host:port (exporter-specific)
//	protocol                      = http | grpc (OTLP only)
//	insecure                      = "true" | "false" (OTLP only)
//	metrics                       = "true" when the continuous workload
//	                                metrics should be pushed to the same
//	                                endpoint as the spans (OTLP only)
//	metrics_interval_seconds      = push period in whole seconds
//	                                (optional; absent means the agent
//	                                 default)
//	site                          = datadoghq.com | datadoghq.eu (DataDog only)
//	sample_percent                = effective decimal string in [0, 100]
//	                                (operator-computed min of CR + EC; absent
//	                                 when both are unset, meaning 100%)
//	headers.<name>                = literal value (OTLP only)
//	header_secret_name            = name of the OTLP header sourced from
//	                                the companion Secret (OTLP only)
//	filters                       = comma-joined sorted event categories
//	                                (absent / empty means "no restriction")
//	threshold_error_rate_percent  = int 0-100 (optional, key absent when unset)
//	threshold_rtt_spike_ms        = int >=0  (optional, key absent when unset)
//	threshold_fs_slow_ms          = int >=0  (optional, key absent when unset)
//	target_namespaces             = sorted CSV (tri-state via key presence)
//	policy_generation             = PodTrace.metadata.generation at render time
//	policy_hash                   = sha256 over the policy fields (stable
//	                                across same-policy CRs, used by agents
//	                                to assert propagation)
//
// renderBundlePayload accepts a nil bundlePolicyInputs so unit tests that
// exercise exporter-variant rendering in isolation keep working; in that
// mode only EC-side sampling is considered and no per-CR policy keys
// (filters, thresholds, generation) are written. Production callers
// (continuous PodTrace + bounded PodTraceSession) always pass a
// populated bundlePolicyInputs.
func renderBundlePayload(policy *bundlePolicyInputs, ec *podtracev1alpha1.ExporterConfig, targetNamespaces []string) (map[string]string, *podtracev1alpha1.SecretKeySelector, *corev1.LocalObjectReference, error) {
	data := map[string]string{
		"version": bundle.CurrentVersion,
		"type":    string(ec.Spec.Type),
	}
	if pct := effectiveSamplePercentFromPolicy(policy, ec); pct != nil {
		data["sample_percent"] = itoa(int(*pct))
	}
	if ec.Spec.SynthesizeSpans {
		data["synthesize_spans"] = "true"
	}
	if targetNamespaces != nil {
		sorted := make([]string, len(targetNamespaces))
		copy(sorted, targetNamespaces)
		sort.Strings(sorted)
		data["target_namespaces"] = strings.Join(sorted, ",")
	}
	applyPolicyKeys(data, policy)

	switch ec.Spec.Type {
	case podtracev1alpha1.ExporterTypeOTLP:
		if ec.Spec.OTLP == nil {
			return nil, nil, nil, fmt.Errorf("spec.otlp is required when type=otlp")
		}
		data["endpoint"] = ec.Spec.OTLP.Endpoint
		if ec.Spec.OTLP.Protocol != "" {
			data["protocol"] = string(ec.Spec.OTLP.Protocol)
		} else {
			data["protocol"] = string(podtracev1alpha1.OTLPProtocolHTTP)
		}
		data["insecure"] = boolString(ec.Spec.OTLP.Insecure)
		if m := ec.Spec.OTLP.Metrics; m != nil && m.Enabled {
			data["metrics"] = "true"
			if m.Interval != nil && m.Interval.Duration > 0 {
				data["metrics_interval_seconds"] = itoa(int(m.Interval.Duration / time.Second))
			}
		}
		var credRef *podtracev1alpha1.SecretKeySelector
		for _, h := range ec.Spec.OTLP.Headers {
			if errs := validation.IsConfigMapKey(h.Name); len(errs) > 0 {
				return nil, nil, nil, fmt.Errorf("spec.otlp.headers[].name %q: %s", h.Name, strings.Join(errs, "; "))
			}
			if h.ValueFrom != nil {
				if credRef != nil {
					return nil, nil, nil, fmt.Errorf(
						"at most one headers[].valueFrom is supported (the bundle carries a single credential); move additional secret-backed headers into headersFromSecret")
				}
				data["header_secret_name"] = h.Name
				credRef = h.ValueFrom.DeepCopy()
				continue
			}
			data["headers."+h.Name] = h.Value
		}
		var headersFrom *corev1.LocalObjectReference
		if ec.Spec.OTLP.HeadersFromSecret != nil && ec.Spec.OTLP.HeadersFromSecret.Name != "" {
			headersFrom = ec.Spec.OTLP.HeadersFromSecret.DeepCopy()
		}
		return data, credRef, headersFrom, nil

	case podtracev1alpha1.ExporterTypeJaeger:
		if ec.Spec.Jaeger == nil {
			return nil, nil, nil, fmt.Errorf("spec.jaeger is required when type=jaeger")
		}
		data["endpoint"] = ec.Spec.Jaeger.Endpoint
		return data, nil, nil, nil

	case podtracev1alpha1.ExporterTypeZipkin:
		if ec.Spec.Zipkin == nil {
			return nil, nil, nil, fmt.Errorf("spec.zipkin is required when type=zipkin")
		}
		data["endpoint"] = ec.Spec.Zipkin.Endpoint
		return data, nil, nil, nil

	case podtracev1alpha1.ExporterTypeSplunk:
		if ec.Spec.Splunk == nil {
			return nil, nil, nil, fmt.Errorf("spec.splunk is required when type=splunk")
		}
		data["endpoint"] = ec.Spec.Splunk.Endpoint
		data["header_secret_name"] = "X-SF-TOKEN"
		ref := ec.Spec.Splunk.TokenSecretRef
		return data, &ref, nil, nil

	case podtracev1alpha1.ExporterTypeDataDog:
		if ec.Spec.DataDog == nil {
			return nil, nil, nil, fmt.Errorf("spec.datadog is required when type=datadog")
		}
		site := ec.Spec.DataDog.Site
		if site == "" {
			site = "datadoghq.com"
		}
		data["site"] = site
		if ec.Spec.DataDog.Endpoint != "" {
			data["endpoint"] = ec.Spec.DataDog.Endpoint
		} else {
			data["endpoint"] = "datadog-agent.datadog:4318"
		}
		data["header_secret_name"] = "DD-API-KEY"
		ref := ec.Spec.DataDog.APIKeySecretRef
		return data, &ref, nil, nil

	default:
		return nil, nil, nil, fmt.Errorf("unsupported exporter type %q", ec.Spec.Type)
	}
}

// buildBundleSecretData materializes the bundle Secret contents: the single
// credential (bundle.CredentialKey) when credRef is set, plus one
// "header.<name>" entry per key of the headersFromSecret Secret.
func buildBundleSecretData(ctx context.Context, reader client.Reader, ecNamespace string, credRef *podtracev1alpha1.SecretKeySelector, headersFrom *corev1.LocalObjectReference) (map[string][]byte, error) {
	out := map[string][]byte{}
	if credRef != nil {
		var src corev1.Secret
		if err := reader.Get(ctx, types.NamespacedName{Namespace: ecNamespace, Name: credRef.Name}, &src); err != nil {
			return nil, fmt.Errorf("get credential Secret %s/%s: %w", ecNamespace, credRef.Name, err)
		}
		val, ok := src.Data[credRef.Key]
		if !ok {
			return nil, fmt.Errorf("secret %s/%s has no key %q", ecNamespace, credRef.Name, credRef.Key)
		}
		out[bundle.CredentialKey] = val
	}
	if headersFrom != nil {
		var src corev1.Secret
		if err := reader.Get(ctx, types.NamespacedName{Namespace: ecNamespace, Name: headersFrom.Name}, &src); err != nil {
			return nil, fmt.Errorf("get headersFromSecret Secret %s/%s: %w", ecNamespace, headersFrom.Name, err)
		}
		for k, v := range src.Data {
			out[bundle.SecretHeaderKeyPrefix+k] = v
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// bundlePolicyInputs is the operator-side view of the policy a CR
// imposes on the bundle.
type bundlePolicyInputs struct {
	Filters       []podtracev1alpha1.EventFilter
	SamplePercent *int32
	Thresholds    *podtracev1alpha1.Thresholds
	Generation    int64
}

// policyFromPodTrace lifts the policy fields off a PodTrace.
func policyFromPodTrace(pt *podtracev1alpha1.PodTrace) *bundlePolicyInputs {
	if pt == nil {
		return nil
	}
	return &bundlePolicyInputs{
		Filters:       pt.Spec.Filters,
		SamplePercent: pt.Spec.SamplePercent,
		Thresholds:    pt.Spec.Thresholds,
		Generation:    pt.Generation,
	}
}

// policyFromSession lifts the policy fields off a PodTraceSession.
func policyFromSession(s *podtracev1alpha1.PodTraceSession) *bundlePolicyInputs {
	if s == nil {
		return nil
	}
	return &bundlePolicyInputs{
		Filters:       s.Spec.Filters,
		SamplePercent: s.Spec.SamplePercent,
		Thresholds:    s.Spec.Thresholds,
		Generation:    s.Generation,
	}
}

// effectiveSamplePercentFromPolicy returns the operator-side resolution
// of the "minimum applies" sampling contract between the CR-owner intent
// (PodTrace/Session.spec.samplePercent) and the platform-owner cap
// (ExporterConfig.spec.samplePercent).
func effectiveSamplePercentFromPolicy(p *bundlePolicyInputs, ec *podtracev1alpha1.ExporterConfig) *int32 {
	var crVal *int32
	if p != nil {
		crVal = p.SamplePercent
	}
	var ecVal *int32
	if ec != nil {
		ecVal = ec.Spec.SamplePercent
	}
	if crVal == nil && ecVal == nil {
		return nil
	}
	const fullRate int32 = 100
	cr := fullRate
	if crVal != nil {
		cr = *crVal
	}
	ecPct := fullRate
	if ecVal != nil {
		ecPct = *ecVal
	}
	min := cr
	if ecPct < min {
		min = ecPct
	}
	return &min
}

// applyPolicyKeys writes the CR's filters, thresholds, generation,
// and computed policy_hash onto the bundle's flat ConfigMap data.
func applyPolicyKeys(data map[string]string, policy *bundlePolicyInputs) {
	if policy == nil {
		data["policy_hash"] = bundle.PolicyHash(bundleViewFromData(data))
		return
	}

	if filters := normalizeFilters(policy.Filters); len(filters) > 0 {
		data["filters"] = strings.Join(filters, ",")
	}

	if t := policy.Thresholds; t != nil {
		if t.ErrorRatePercent != nil {
			data["threshold_error_rate_percent"] = strconv.FormatInt(int64(*t.ErrorRatePercent), 10)
		}
		if t.RTTSpikeMs != nil {
			data["threshold_rtt_spike_ms"] = strconv.FormatInt(int64(*t.RTTSpikeMs), 10)
		}
		if t.FilesystemLatencyMs != nil {
			data["threshold_fs_slow_ms"] = strconv.FormatInt(int64(*t.FilesystemLatencyMs), 10)
		}
	}

	if policy.Generation > 0 {
		data["policy_generation"] = strconv.FormatInt(policy.Generation, 10)
	}

	data["policy_hash"] = bundle.PolicyHash(bundleViewFromData(data))
}

// normalizeFilters dedupes and sorts the CRD's filter list so the
// bundle's "filters" key is byte-stable across reconciles.
func normalizeFilters(in []podtracev1alpha1.EventFilter) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, f := range in {
		s := strings.TrimSpace(string(f))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// bundleViewFromData parses the bundle data we have just produced so
// PolicyHash can hash the typed view of the policy fields.
func bundleViewFromData(data map[string]string) *bundle.Payload {
	p, err := bundle.FromConfigMapData(data)
	if err != nil {
		return nil
	}
	return p
}

// resolvePolicyStatus produces the status.Policy view for a CR.
func resolvePolicyStatus(policy *bundlePolicyInputs, ec *podtracev1alpha1.ExporterConfig) *podtracev1alpha1.PolicyStatus {
	if policy == nil && ec == nil {
		return nil
	}
	out := &podtracev1alpha1.PolicyStatus{}
	if pct := effectiveSamplePercentFromPolicy(policy, ec); pct != nil {
		val := *pct
		out.EffectiveSampleRate = &val
	}
	if policy != nil {
		if filters := normalizeFilters(policy.Filters); len(filters) > 0 {
			typed := make([]podtracev1alpha1.EventFilter, len(filters))
			for i, f := range filters {
				typed[i] = podtracev1alpha1.EventFilter(f)
			}
			out.Filters = typed
		}
		if policy.Thresholds != nil {
			thresholds := *policy.Thresholds
			if thresholds.ErrorRatePercent != nil ||
				thresholds.RTTSpikeMs != nil ||
				thresholds.FilesystemLatencyMs != nil {
				out.Thresholds = thresholds.DeepCopy()
			}
		}
		out.Generation = policy.Generation
	}
	out.Hash = bundle.PolicyHash(synthBundleForHash(out))
	return out
}

// synthBundleForHash builds a transient bundle.Payload view from a
// PolicyStatus so bundle.PolicyHash can be reused as the single source
// of hash semantics.
func synthBundleForHash(p *podtracev1alpha1.PolicyStatus) *bundle.Payload {
	if p == nil {
		return nil
	}
	b := &bundle.Payload{}
	if p.EffectiveSampleRate != nil {
		sample := float64(*p.EffectiveSampleRate) / 100.0
		b.Sample = &sample
	}
	if len(p.Filters) > 0 {
		filters := make([]bundle.FilterCategory, len(p.Filters))
		for i, f := range p.Filters {
			filters[i] = bundle.FilterCategory(f)
		}
		b.Filters = filters
	}
	if p.Thresholds != nil {
		b.Thresholds = &bundle.Thresholds{
			ErrorRatePercent:    p.Thresholds.ErrorRatePercent,
			RTTSpikeMs:          p.Thresholds.RTTSpikeMs,
			FilesystemLatencyMs: p.Thresholds.FilesystemLatencyMs,
		}
	}
	return b
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
