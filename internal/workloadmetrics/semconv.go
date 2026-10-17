package workloadmetrics

import (
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
)

// This file emits the OpenTelemetry semantic-convention twin of the L7
// families. Both are exposed: the native podtrace_workload_* names and
// these. That doubling is deliberate — it is what lets a stock Grafana,
// Datadog or Honeycomb dashboard work against podtrace unmodified, instead
// of podtrace being a parallel tool whose dialect has to be learned.
//
// Names are the Prometheus rendering of the convention, per OpenTelemetry's
// Prometheus compatibility rules: dots become underscores and the unit is a
// suffix, so http.server.request.duration is
// http_server_request_duration_seconds.
//
// Two deliberate departures, both because the alternative would be to emit
// an attribute podtrace cannot fill:
//
//   - No http.route. podtrace observes the wire, so it sees the request
//     target, not the server's route template. Using the raw path as
//     http.route is what the convention warns against, because the
//     cardinality is unbounded.
//
// Identity uses semconv names here rather than the native namespace/
// workload labels, so that the series read as conventional to a dashboard
// that has never heard of podtrace. Note that semconv's k8s workload keys
// are kind-specific (k8s.deployment.name, k8s.statefulset.name, …) and a
// Prometheus family has one fixed label set, so the workload arrives as
// service.name — which is also the label those dashboards group by.

const (
	semconvHTTPDuration = "http_server_request_duration_seconds"
	semconvRPCDuration  = "rpc_server_duration_seconds"
	semconvDBDuration   = "db_client_operation_duration_seconds"
)

// semconvIdentityLabels are the conventional identity labels every semconv
// family carries.
var semconvIdentityLabels = []string{
	"service_name",
	"k8s_namespace_name",
	"k8s_container_name",
}

func withSemconvIdentity(extra ...string) []string {
	out := make([]string, 0, len(semconvIdentityLabels)+len(extra))
	out = append(out, semconvIdentityLabels...)
	out = append(out, extra...)
	return out
}

// semconvCollectors holds the convention-named families.
type semconvCollectors struct {
	httpDuration *prometheus.HistogramVec
	rpcDuration  *prometheus.HistogramVec
	dbDuration   *prometheus.HistogramVec

	methodValues    *boundedValues
	operationValues *boundedValues
}

func newSemconvCollectors(native bool, limit int) *semconvCollectors {
	return &semconvCollectors{
		httpDuration: prometheus.NewHistogramVec(
			semconvHistogramOpts(semconvHTTPDuration,
				"Duration of inbound HTTP requests, in OpenTelemetry semantic-convention form.", native),
			withSemconvIdentity("http_request_method", "http_response_status_code", "network_protocol_name"),
		),
		rpcDuration: prometheus.NewHistogramVec(
			semconvHistogramOpts(semconvRPCDuration,
				"Duration of inbound RPC calls, in OpenTelemetry semantic-convention form.", native),
			withSemconvIdentity("rpc_system", "rpc_method"),
		),
		dbDuration: prometheus.NewHistogramVec(
			semconvHistogramOpts(semconvDBDuration,
				"Duration of outbound database and cache operations, in OpenTelemetry semantic-convention form.", native),
			withSemconvIdentity("db_system_name", "db_operation_name"),
		),
		methodValues:    newBoundedValues(limit),
		operationValues: newBoundedValues(limit),
	}
}

// semconvHistogramOpts deliberately does NOT apply metricPrefix.
func semconvHistogramOpts(name, help string, native bool) prometheus.HistogramOpts {
	opts := histogramOpts(name, help, native)
	opts.Name = name
	return opts
}

func (c *semconvCollectors) all() []prometheus.Collector {
	return []prometheus.Collector{c.httpDuration, c.rpcDuration, c.dbDuration}
}

func (c *semconvCollectors) register(reg prometheus.Registerer) error {
	for _, collector := range c.all() {
		if err := reg.Register(collector); err != nil {
			return err
		}
	}
	return nil
}

// boundedValues folds an open value space into at most `limit` distinct
// values plus a shared placeholder.
type boundedValues struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	limit int
}

const boundedValuesPlaceholder = "_other"

func newBoundedValues(limit int) *boundedValues {
	return &boundedValues{seen: make(map[string]struct{}), limit: limit}
}

func (b *boundedValues) bound(v string) string {
	if v == "" {
		return "unknown"
	}
	v = labelValue(v)
	if b == nil || b.limit <= 0 {
		return v
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.seen[v]; ok {
		return v
	}
	if len(b.seen) >= b.limit {
		return boundedValuesPlaceholder
	}
	b.seen[v] = struct{}{}
	return v
}

// semconvIdentity projects pod metadata onto the conventional identity
// labels, in the order withSemconvIdentity declares them.
func semconvIdentity(meta events.K8sMetadata) []string {
	return []string{
		meta.WorkloadName,
		meta.Namespace,
		orUnknown(meta.ContainerName),
	}
}

// networkProtocolName renders the transport as semconv's
// network.protocol.name expects: the protocol, lowercased, without a
// version suffix baked into the name.
func networkProtocolName(e *events.Event) string {
	switch protocolLabel(e) {
	case "http3":
		return "http/3"
	case "http2":
		return "http/2"
	case "http":
		return "http/1.1"
	default:
		return "unknown"
	}
}

// statusCodeLabel is the real status code, not the class the native family
// carries. The convention expects a code, and a dashboard filtering on
// status >= 500 needs one.
func statusCodeLabel(e *events.Event) string {
	if code, ok := e.ResponseStatus(); ok {
		return strconv.Itoa(code)
	}
	return "0"
}

// rpcSystem and dbSystem map an event to the convention's system value.
func rpcSystem(t events.EventType) string {
	if t == events.EventGRPCMethod {
		return "grpc"
	}
	return "unknown"
}

func dbSystem(t events.EventType) string {
	switch t {
	case events.EventRedisCmd:
		return "redis"
	case events.EventMemcachedCmd:
		return "memcached"
	case events.EventDBQuery:
		return "other_sql"
	default:
		return "unknown"
	}
}

// firstLine trims an event string field to its first line, so a multi-line
// Details payload cannot smuggle newlines into a label value.
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// httpRequestMethod renders the observed method for semconv's
// http.request.method.
func httpRequestMethod(e *events.Event) string {
	if e.HTTPMethod != "" {
		return e.HTTPMethod
	}
	return "_OTHER"
}

// The OTLP rendering of the convention families.
type otlpIdentity struct {
	name string
	unit string
}

var semconvOTLPFamilies = map[string]otlpIdentity{
	semconvHTTPDuration: {name: "http.server.request.duration", unit: "s"},
	semconvRPCDuration:  {name: "rpc.server.duration", unit: "s"},
	semconvDBDuration:   {name: "db.client.operation.duration", unit: "s"},
}

var semconvOTLPAttributeKeys = map[string]string{
	"service_name":              "service.name",
	"k8s_namespace_name":        "k8s.namespace.name",
	"k8s_container_name":        "k8s.container.name",
	"http_request_method":       "http.request.method",
	"http_response_status_code": "http.response.status_code",
	"network_protocol_name":     "network.protocol.name",
	"rpc_system":                "rpc.system",
	"rpc_method":                "rpc.method",
	"db_system_name":            "db.system.name",
	"db_operation_name":         "db.operation.name",
}

func isSemconvFamily(promName string) bool {
	_, ok := semconvOTLPFamilies[promName]
	return ok
}

// semconvAttributeKey returns the convention's key for a Prometheus label
// of a convention family, or the label unchanged when there is no entry.
func semconvAttributeKey(label string) string {
	if key, ok := semconvOTLPAttributeKeys[label]; ok {
		return key
	}
	return label
}

// otlpIdentityFor gives a family its OTLP name and unit.
func otlpIdentityFor(promName string) (string, string) {
	if identity, ok := semconvOTLPFamilies[promName]; ok {
		return identity.name, identity.unit
	}
	return promName, unitForPrometheusName(promName)
}

// unitForPrometheusName reads the UCUM unit off the conventional
// Prometheus suffix. Only suffixes podtrace actually emits are mapped;
// an unrecognised one yields no unit rather than a wrong one.
func unitForPrometheusName(name string) string {
	trimmed := strings.TrimSuffix(name, "_total")
	switch {
	case strings.HasSuffix(trimmed, "_seconds"):
		return "s"
	case strings.HasSuffix(trimmed, "_bytes"):
		return "By"
	default:
		return ""
	}
}
