package workloadmetrics

import (
	"strings"
	"unicode/utf8"

	"github.com/gma1k/podtrace/internal/events"
)

const maxLabelValueBytes = 256

// labelValue makes a value safe to hand to a Prometheus vector. Client
// libraries panic on a label value that is not valid UTF-8, and comm,
// :path, Redis command words and DNS names all arrive as raw bytes from
// the traced process or the wire: one such byte used to crash the agent.
func labelValue(v string) string {
	if !utf8.ValidString(v) {
		v = strings.ToValidUTF8(v, "\uFFFD")
	}
	if len(v) <= maxLabelValueBytes {
		return v
	}
	cut := maxLabelValueBytes
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut]
}

// Every helper here returns a value from a closed set. That is the whole
// reason they exist: a label value derived straight from observed traffic
// is attacker-influenced and unbounded, and an unbounded label value on a
// permanently scraped series is how a metrics plane takes down the
// monitoring it was meant to serve.
func protocolLabel(e *events.Event) string {
	switch e.Type {
	case events.EventHTTPResp, events.EventHTTPReq:
		switch e.HTTPProtoLabel() {
		case "HTTP/3":
			return "http3"
		case "HTTP/2":
			return "http2"
		default:
			return "http"
		}
	case events.EventGRPCMethod:
		return "grpc"
	case events.EventFastCGIReq, events.EventFastCGIResp:
		return "fastcgi"
	case events.EventRedisCmd:
		return "redis"
	case events.EventMemcachedCmd:
		return "memcached"
	case events.EventKafkaProduce, events.EventKafkaFetch:
		return "kafka"
	case events.EventDBQuery:
		return "database"
	default:
		return "unknown"
	}
}

// statusClass buckets an L7 response status into one of five values.
func statusClass(e *events.Event) string {
	code, ok := e.ResponseStatus()
	if !ok {
		return "unknown"
	}
	switch {
	case code < 200:
		return "1xx"
	case code < 300:
		return "2xx"
	case code < 400:
		return "3xx"
	case code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

const outcomeUnreachable = "unreachable"

// connectOutcome is outcome() for a connection attempt.
func connectOutcome(e *events.Event) string {
	if events.IsUnreachableConnect(e) {
		return outcomeUnreachable
	}
	return outcome(e)
}

func outcome(e *events.Event) string {
	if e.IsError() {
		return "error"
	}
	return "ok"
}

func networkDimensions(t events.EventType) (direction, transport string) {
	switch t {
	case events.EventTCPSend:
		return "egress", "tcp"
	case events.EventTCPRecv:
		return "ingress", "tcp"
	case events.EventUDPSend:
		return "egress", "udp"
	case events.EventUDPRecv:
		return "ingress", "udp"
	default:
		return "unknown", "unknown"
	}
}

func filesystemOperation(t events.EventType) string {
	switch t {
	case events.EventRead:
		return "read"
	case events.EventWrite:
		return "write"
	case events.EventFsync:
		return "fsync"
	case events.EventOpen:
		return "open"
	case events.EventClose:
		return "close"
	case events.EventUnlink:
		return "unlink"
	case events.EventRename:
		return "rename"
	default:
		return "unknown"
	}
}

// errorKind groups failures coarsely, so the error counter answers "what
// broke" without duplicating the per-family label sets.
func errorKind(t events.EventType) string {
	switch t {
	case events.EventHTTPResp, events.EventGRPCMethod,
		events.EventFastCGIResp, events.EventRedisCmd, events.EventMemcachedCmd,
		events.EventKafkaProduce, events.EventKafkaFetch, events.EventDBQuery:
		return "l7"
	case events.EventDNS, events.EventDNSQuery:
		return "dns"
	case events.EventTCPSend, events.EventTCPRecv, events.EventUDPSend,
		events.EventUDPRecv, events.EventConnect, events.EventTCPRetrans,
		events.EventNetDevError, events.EventConnectResult:
		return "network"
	case events.EventRead, events.EventWrite, events.EventFsync,
		events.EventOpen, events.EventClose, events.EventUnlink, events.EventRename:
		return "filesystem"
	case events.EventTLSHandshake, events.EventTLSError:
		return "tls"
	case events.EventLockContention:
		return "lock"
	default:
		return "other"
	}
}
