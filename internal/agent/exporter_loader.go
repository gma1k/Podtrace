package agent

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gma1k/podtrace/internal/operator"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
	"github.com/gma1k/podtrace/pkg/tracer"
)

// BundlePayload is an alias for bundle.Payload so existing agent callers
// keep their familiar type name.
type BundlePayload = bundle.Payload

// LoadBundle reads the ConfigMap+optional-Secret pair the operator
// maintains in systemNamespace for the given PodTrace UID, and returns
// the parsed payload.
func LoadBundle(ctx context.Context, c client.Client, systemNamespace string, podtraceUID types.UID) (*BundlePayload, error) {
	name := operator.ExporterBundleName(podtraceUID)

	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: systemNamespace}, &cm); err != nil {
		return nil, fmt.Errorf("get bundle ConfigMap: %w", err)
	}

	payload, err := bundle.FromConfigMapData(cm.Data)
	if err != nil {
		return nil, fmt.Errorf("parse bundle ConfigMap: %w", err)
	}
	payload.ResourceVer = cm.ResourceVersion
	payload.SamplingKey = string(podtraceUID)

	// Credential Secret is only present when the exporter needed one
	// (Splunk HEC token, DataDog API key, or an OTLP Secret-backed
	// header).
	var sec corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: systemNamespace}, &sec); err == nil {
		payload.Credential = sec.Data[bundle.CredentialKey]
		for k, v := range sec.Data {
			if rest, ok := strings.CutPrefix(k, bundle.SecretHeaderKeyPrefix); ok && rest != "" {
				if payload.SecretHeaders == nil {
					payload.SecretHeaders = map[string]string{}
				}
				payload.SecretHeaders[rest] = string(v)
			}
		}
		payload.ResourceVer = cm.ResourceVersion + "/" + sec.ResourceVersion
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get bundle Secret: %w", err)
	}

	return payload, nil
}

// Exporter build error classes. These short, stable strings appear in
// the `podtrace_agent_exporter_init_failures_total` metric reason label
// and in the rule-error classifier that feeds
// PodTrace.status.nodeStatus[].reason.
const (
	ExporterErrUnknown         = "unknown"
	ExporterErrNilPayload      = "nil_payload"
	ExporterErrUnsupportedType = "unsupported_type"
	ExporterErrEndpointMissing = "endpoint_missing"
	ExporterErrTLSInvalid      = "tls_invalid"
	ExporterErrAuthMissing     = "auth_missing"
)

// ClassifyExporterError maps a BuildExporter error to one of the
// ExporterErr* constants.
func ClassifyExporterError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "nil bundle payload"),
		strings.Contains(msg, "nil payload"):
		return ExporterErrNilPayload
	case strings.Contains(msg, "unknown exporter type"),
		strings.Contains(msg, "opentelemetry collector"):
		return ExporterErrUnsupportedType
	case strings.Contains(msg, "endpoint"):
		return ExporterErrEndpointMissing
	case strings.Contains(msg, "tls"),
		strings.Contains(msg, "certificate"):
		return ExporterErrTLSInvalid
	case strings.Contains(msg, "credential"),
		strings.Contains(msg, "missing api key"),
		strings.Contains(msg, "missing token"):
		return ExporterErrAuthMissing
	}
	return ExporterErrUnknown
}

// BuildExporter turns a BundlePayload into a tracer.Exporter that
// accepts []*events.Event.
func BuildExporter(payload *BundlePayload, crKey CRKey, opts ...sdkOption) (tracer.Exporter, error) {
	if payload == nil {
		return nil, fmt.Errorf("nil bundle payload")
	}
	switch payload.Type {
	case bundle.TypeOTLP:
		return newOTLPEventExporter(crKey, payload, opts...)
	case bundle.TypeJaeger:
		return newJaegerEventExporter(crKey, payload, opts...)
	case bundle.TypeZipkin:
		return newZipkinEventExporter(crKey, payload, opts...)
	case bundle.TypeDataDog:
		return newDataDogEventExporter(crKey, payload, opts...)
	case bundle.TypeSplunk:
		return newSplunkEventExporter(crKey, payload, opts...)
	default:
		return nil, fmt.Errorf("unknown exporter type %q", payload.Type)
	}
}
