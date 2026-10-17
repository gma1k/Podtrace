package events

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/safeconv"
)

// PeerIP formats a fused L7<->L4 peer address. v4 is host byte order; family is
// the AF_* value (2=AF_INET, 10=AF_INET6). Returns "" if unknown/unspecified.
func PeerIP(family uint8, v4 uint32, v6 [16]byte) string {
	switch family {
	case 2:
		if v4 == 0 {
			return ""
		}
		ip := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(ip, v4)
		return ip.String()
	case 10:
		ip := net.IP(v6[:])
		if ip.IsUnspecified() {
			return ""
		}
		return ip.String()
	default:
		return ""
	}
}

// TruncateString shortens s to at most max bytes without splitting a
// multi-byte UTF-8 rune, so the result is always valid UTF-8.
func TruncateString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return cutRunes(s, max)
	}
	return cutRunes(s, max-3) + "..."
}

// cutRunes returns s truncated to at most n bytes, backing off to the nearest
// rune boundary.
func cutRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

type EventType uint32

const (
	EventDNS EventType = iota
	EventConnect
	EventTCPSend
	EventTCPRecv
	EventWrite
	EventRead
	EventFsync
	EventSchedSwitch
	EventTCPState
	EventPageFault
	EventOOMKill
	EventUDPSend
	EventUDPRecv
	EventHTTPReq
	EventHTTPResp
	EventLockContention
	EventTCPRetrans
	EventNetDevError
	EventDBQuery
	EventExec
	EventFork
	EventOpen
	EventClose
	EventTLSHandshake
	EventTLSError
	EventResourceLimit
	EventPoolAcquire
	EventPoolRelease
	EventPoolExhausted
	EventUnlink
	EventRename
	EventRedisCmd
	EventMemcachedCmd
	EventFastCGIReq
	EventFastCGIResp
	EventGRPCMethod
	EventKafkaProduce
	EventKafkaFetch
	EventDNSQuery
	EventAFALG
	EventHTTP3
	EventUSDT
	EventDBAcquire
	EventDBPoolStats
	EventTCPRTT
	EventConnectResult
	EventRequestDone
)

type Event struct {
	Timestamp    uint64
	PID          uint32
	CgroupID     uint64
	NetNsID      uint32   // V4: network namespace inum (0 if kernel BTF unavailable)
	DNSServerIP  uint32   // V5: upstream resolver IPv4 for DNS events (0 otherwise)
	DNSTransport uint8    // V5: 0=UDP, 1=TCP for DNS events
	DNSServerIP6 [16]byte // V6: upstream resolver IPv6 for DNS events
	PeerSrcIP    string   // V7: L7<->L4 fused local address ("" if unknown)
	PeerDstIP    string   // V7: L7<->L4 fused remote/peer address
	PeerSrcPort  uint16   // V7: local port
	PeerDstPort  uint16   // V7: remote/peer port
	ProcessName  string
	Type         EventType
	LatencyNS    uint64
	Error        int32
	Bytes        uint64
	TCPState     uint32
	StackKey     uint64
	Stack        []uint64
	Target       string
	Details      string
	TraceID      string
	SpanID       string
	ParentSpanID string
	TraceFlags   uint8
	TraceState   string

	CorrelationID uint64

	HTTPMethod string

	KernelAggregated bool

	K8s *K8sMetadata
}

func (e *Event) Latency() time.Duration {
	return time.Duration(safeconv.Uint64ToInt64(e.LatencyNS)) * time.Nanosecond
}

// IsError reports whether the event represents a failure.
func (e *Event) IsError() bool {
	if kernelRestartCode(e.Error) {
		return false
	}
	switch e.Type {
	case EventResourceLimit, EventDBPoolStats:
		return false
	case EventOpen:
		return e.Error != 0 && e.Error != -errnoENOENT
	case EventLockContention:
		return e.Error < 0 && !futexWaitOutcome(e.Error)
	case EventDNS:
		return e.IsDNSLookup() && DNSAnswerFailed(e.DNSAnswer())
	default:
		return e.Error != 0
	}
}

// IsL7Response reports whether t is a decoded application-protocol response:
// one event per request, the unit an L7 request or error rate counts.
func IsL7Response(t EventType) bool {
	switch t {
	case EventHTTPResp, EventGRPCMethod,
		EventFastCGIResp, EventRedisCmd, EventMemcachedCmd,
		EventKafkaProduce, EventKafkaFetch, EventDBQuery:
		return true
	default:
		return false
	}
}

// CountsAsConnectionAttempt decides which connect events score an attempt, so that
// each one is counted exactly once.
func CountsAsConnectionAttempt(t EventType, failed bool) bool {
	switch t {
	case EventConnectResult:
		return true
	case EventConnect:
		return failed
	default:
		return false
	}
}

// kernelRestartCode reports whether code is one of the kernel-internal
// ERESTART* values (512-516): the syscall layer restarts the call or turns
// it into EINTR, so no application ever sees it as a failure.
func kernelRestartCode(code int32) bool {
	return code <= -errnoERESTARTSYS && code >= -errnoERESTARTRESTARTBLOCK
}

// futexWaitOutcome reports whether a negative futex return is how a wait
// normally ends rather than a failure: the value had already changed
// (EAGAIN), a timed wait expired (ETIMEDOUT), or a signal interrupted it
// (EINTR, or a kernel-internal ERESTART* the syscall layer restarts).
// FUTEX_WAKE returns how many waiters it woke, which is never an error.
func futexWaitOutcome(code int32) bool {
	switch -code {
	case errnoEINTR, errnoEAGAIN, errnoETIMEDOUT,
		errnoERESTARTSYS, errnoERESTARTNOINTR, errnoERESTARTNOHAND, errnoERESTARTRESTARTBLOCK:
		return true
	}
	return false
}

const (
	errnoEINTR                = 4
	errnoEAGAIN               = 11
	errnoETIMEDOUT            = 110
	errnoERESTARTSYS          = 512
	errnoERESTARTNOINTR       = 513
	errnoERESTARTNOHAND       = 514
	errnoERESTARTRESTARTBLOCK = 516
)

const (
	errnoENOENT       = 2
	errnoEAFNOSUPPORT = 97
	errnoENETUNREACH  = 101
)

// IsAddressFamilyUnreachable reports whether a failed connect() had no route
// for the destination's address family, rather than failing to reach a peer.
func IsAddressFamilyUnreachable(errno int32) bool {
	if errno < 0 {
		errno = -errno
	}
	return errno == errnoENETUNREACH || errno == errnoEAFNOSUPPORT
}

// IsUnreachableConnect reports whether e is a synchronous connect failure of
// that kind. A handshake result never is: its SYN was already sent.
func IsUnreachableConnect(e *Event) bool {
	return e != nil && e.Type == EventConnect && IsAddressFamilyUnreachable(e.Error)
}

// TimestampTime returns the event's timestamp as wall-clock time.
func (e *Event) TimestampTime() time.Time {
	return clock.BPFTimestampToWall(e.Timestamp)
}

// HTTP transport for EventHTTPReq/EventHTTPResp, carried in TCPState bits
// 0-2: bit 0 = TLS (encrypted), bit 1 = HTTP/2, bit 2 = HTTP/3. Bits 3-4 carry
// the role (see HTTPRoleKnownBit).
const (
	HTTPTransportPlaintext uint32 = 0 // HTTP/1.x cleartext sockets
	HTTPTransportTLS       uint32 = 1 // HTTP/1.x over TLS (OpenSSL/GnuTLS/Go)
	HTTPTransportH2C       uint32 = 2 // HTTP/2 cleartext
	HTTPTransportH2TLS     uint32 = 3 // HTTP/2 over TLS (Go crypto/tls)
	HTTPTransportH3        uint32 = 5 // HTTP/3 over QUIC: H3 bit | TLS bit

	httpTransportTLSBit uint32 = 1
	httpTransportH2Bit  uint32 = 2
	httpTransportH3Bit  uint32 = 4
	httpTransportMask   uint32 = 0x7
)

// HTTP role bits, carried in TCPState above the transport bits for
// EventHTTPReq, EventHTTPResp and EventGRPCMethod. HTTPRoleKnownBit says the
// producer knew which side of the exchange the traced process was on.
const (
	HTTPRoleKnownBit  uint32 = 0x08
	HTTPRoleServerBit uint32 = 0x10
	HTTPRoleMask             = HTTPRoleKnownBit | HTTPRoleServerBit
)

type HTTPRole uint8

const (
	HTTPRoleUnknown HTTPRole = iota
	HTTPRoleClient
	HTTPRoleServer
)

func (r HTTPRole) String() string {
	switch r {
	case HTTPRoleClient:
		return "client"
	case HTTPRoleServer:
		return "server"
	default:
		return "unknown"
	}
}

// HTTPRoleBits returns the TCPState bits that record a known role.
func HTTPRoleBits(server bool) uint32 {
	if server {
		return HTTPRoleKnownBit | HTTPRoleServerBit
	}
	return HTTPRoleKnownBit
}

// HTTPRole returns the side of the exchange an HTTP or gRPC event was
// observed on.
func (e *Event) HTTPRole() HTTPRole {
	if e.TCPState&HTTPRoleKnownBit == 0 {
		return HTTPRoleUnknown
	}
	if e.TCPState&HTTPRoleServerBit != 0 {
		return HTTPRoleServer
	}
	return HTTPRoleClient
}

// HTTPTransport returns the transport bits of an HTTP event's TCPState,
// without the role bits.
func (e *Event) HTTPTransport() uint32 {
	return e.TCPState & httpTransportMask
}

// IsClientL7Response reports whether e is the caller's view of an HTTP or
// gRPC call: the response to a request the traced process made.
func (e *Event) IsClientL7Response() bool {
	if e.Type != EventHTTPResp && e.Type != EventGRPCMethod {
		return false
	}
	return e.HTTPRole() == HTTPRoleClient
}

// IsServerL7Response reports whether e is an HTTP or gRPC response the traced
// process sent for a request it served.
func (e *Event) IsServerL7Response() bool {
	if e.Type != EventHTTPResp && e.Type != EventGRPCMethod {
		return false
	}
	return e.HTTPRole() == HTTPRoleServer
}

// HTTPScheme returns the URL scheme implied by an HTTP event's transport:
// "https" for any TLS-captured traffic, "http" for cleartext (HTTP/1.x or h2c).
func (e *Event) HTTPScheme() string {
	if e.TCPState&httpTransportTLSBit != 0 {
		return "https"
	}
	return "http"
}

// ResponseStatus returns the HTTP status code carried by an L7 response
// event, and whether one was found.
func (e *Event) ResponseStatus() (int, bool) {
	first := e.Details
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if n, err := strconv.Atoi(strings.TrimSpace(first)); err == nil && n >= 100 && n <= 599 {
		return n, true
	}
	if e.Error >= 100 && e.Error <= 599 {
		return int(e.Error), true
	}
	return 0, false
}

// HTTPProtoLabel is the protocol label for an HTTP event, reflecting its
// transport: "HTTP/3" for QUIC, "HTTP/2" for any h2 traffic, else "HTTPS" over
// TLS or "HTTP".
func (e *Event) HTTPProtoLabel() string {
	if e.TCPState&httpTransportH3Bit != 0 {
		return "HTTP/3"
	}
	if e.TCPState&httpTransportH2Bit != 0 {
		return "HTTP/2"
	}
	if e.TCPState&httpTransportTLSBit != 0 {
		return "HTTPS"
	}
	return "HTTP"
}

func (e *Event) TypeString() string {
	switch e.Type {
	case EventDNS, EventDNSQuery:
		return "DNS"
	case EventConnect:
		return "NET"
	case EventTCPSend, EventTCPRecv, EventTCPState, EventUDPSend, EventUDPRecv:
		return "NET"
	case EventWrite, EventRead:
		return "FS"
	case EventFsync:
		return "FS"
	case EventOpen, EventClose:
		return "FS"
	case EventSchedSwitch:
		return "CPU"
	case EventPageFault, EventOOMKill:
		return "MEM"
	case EventHTTPReq, EventHTTPResp:
		return e.HTTPProtoLabel()
	case EventLockContention:
		return "LOCK"
	case EventTCPRetrans, EventNetDevError, EventTCPRTT, EventConnectResult:
		return "NET"
	case EventDBQuery:
		return "DB"
	case EventExec, EventFork:
		return "PROC"
	case EventTLSHandshake, EventTLSError:
		return "TLS"
	case EventResourceLimit:
		return "RESOURCE"
	case EventPoolAcquire, EventPoolRelease, EventPoolExhausted, EventDBAcquire,
		EventDBPoolStats:
		return "POOL"
	case EventUnlink, EventRename:
		return "FS"
	case EventRedisCmd, EventMemcachedCmd:
		return "CACHE"
	case EventFastCGIReq, EventFastCGIResp:
		return "FASTCGI"
	case EventGRPCMethod:
		return "gRPC"
	case EventKafkaProduce, EventKafkaFetch:
		return "KAFKA"
	case EventAFALG:
		return "CRYPTO"
	case EventHTTP3:
		return "HTTP/3"
	case EventUSDT:
		return "USDT"
	case EventRequestDone:
		return "REQUEST"
	default:
		return "UNKNOWN"
	}
}

// dnsQTypeName maps a DNS query type to its mnemonic (carried in TCPState for
// EVENT_DNS).
func dnsQTypeName(t uint32) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 33:
		return "SRV"
	case 12:
		return "PTR"
	case 16:
		return "TXT"
	case 15:
		return "MX"
	case 2:
		return "NS"
	case 6:
		return "SOA"
	case 0:
		return "lookup"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// dnsServerString formats the upstream resolver IPv4.
func dnsServerString(v uint32) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v&0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff)
}

// DNSServerAddr returns the upstream resolver address for a DNS event,
// preferring the IPv6 server when present, else the IPv4 one.
func (e *Event) DNSServerAddr() string {
	return dnsServerStr(e)
}

// dnsServerStr returns the upstream resolver address for a DNS event, preferring
// the IPv6 server when present, else the IPv4 one. Returns "" when unknown.
func dnsServerStr(e *Event) string {
	for _, b := range e.DNSServerIP6 {
		if b != 0 {
			const hex = "0123456789abcdef"
			out := make([]byte, 0, 39)
			for i := 0; i < 16; i += 2 {
				if i > 0 {
					out = append(out, ':')
				}
				out = append(out, hex[e.DNSServerIP6[i]>>4], hex[e.DNSServerIP6[i]&0xf],
					hex[e.DNSServerIP6[i+1]>>4], hex[e.DNSServerIP6[i+1]&0xf])
			}
			return string(out)
		}
	}
	return dnsServerString(e.DNSServerIP)
}

// DNSQueryType returns the DNS query-type mnemonic (A, AAAA, …) for an
// EVENT_DNS event; the numeric qtype is carried in TCPState.
func (e *Event) DNSQueryType() string { return dnsQTypeName(e.TCPState) }

// Where an EVENT_DNS came from, carried in DNSTransport; mirrors the
// DNS_SOURCE_* values in bpf/events.h.
const (
	DNSSourceUDP       uint8 = 0
	DNSSourceTCP       uint8 = 1
	DNSSourceEncrypted uint8 = 2
	DNSSourceLibc      uint8 = 3
)

const DNSErrorTimeout int32 = -110

// The answers a lookup is classed by, in podtrace_workload_dns_lookups_total's
// rcode label: a small fixed set, so the label stays bounded.
const (
	DNSAnswerNoError  = "NOERROR"
	DNSAnswerNXDomain = "NXDOMAIN"
	DNSAnswerServFail = "SERVFAIL"
	DNSAnswerRefused  = "REFUSED"
	DNSAnswerOther    = "other"
	DNSAnswerTimeout  = "timeout"
)

// dnsAnswerByClass is indexed by the answer class bpf/events.h carries in a
// kernel-aggregated row's status-class slot.
var dnsAnswerByClass = [...]string{
	DNSAnswerNoError, DNSAnswerNXDomain, DNSAnswerServFail, DNSAnswerRefused, DNSAnswerOther,
}

// DNSAnswerOfClass names the answer class of a kernel-aggregated DNS row.
func DNSAnswerOfClass(class uint8) string {
	if int(class) < len(dnsAnswerByClass) {
		return dnsAnswerByClass[class]
	}
	return DNSAnswerOther
}

const (
	dnsRCodeServFail = 2
	dnsRCodeNXDomain = 3
	dnsRCodeRefused  = 5

	eaiNoName = -2
	eaiAgain  = -3
	eaiNoData = -5
)

// DNSAnswer classes an EVENT_DNS's answer as dns_answer_class in
// bpf/events.h does, plus a timeout.
func (e *Event) DNSAnswer() string {
	switch {
	case e.Error == 0:
		return DNSAnswerNoError
	case e.Error == DNSErrorTimeout:
		return DNSAnswerTimeout
	case e.DNSTransport == DNSSourceLibc:
		switch e.Error {
		case eaiNoName:
			return DNSAnswerNXDomain
		case eaiNoData:
			return DNSAnswerNoError
		case eaiAgain:
			return DNSAnswerServFail
		}
		return DNSAnswerOther
	}
	switch e.Error {
	case dnsRCodeNXDomain:
		return DNSAnswerNXDomain
	case dnsRCodeServFail:
		return DNSAnswerServFail
	case dnsRCodeRefused:
		return DNSAnswerRefused
	}
	return DNSAnswerOther
}

// DNSAnswerFailed reports whether an answer is a failure.
func DNSAnswerFailed(answer string) bool {
	return answer != DNSAnswerNoError && answer != DNSAnswerNXDomain
}

// IsDNSLookup reports whether e is a DNS lookup with an answer to class: an
// encrypted resolver's answer cannot be read, so its events are connections,
// not lookups.
func (e *Event) IsDNSLookup() bool {
	return e.Type == EventDNS && e.DNSTransport != DNSSourceEncrypted
}

// CountsAsDNSLookup reports whether e counts in DNS lookup totals.
func (e *Event) CountsAsDNSLookup(packetCapture bool) bool {
	return e.IsDNSLookup() && (!packetCapture || e.DNSTransport != DNSSourceLibc)
}

// DNSResponseCode returns the DNS response-code mnemonic (NOERROR, NXDOMAIN, …)
// for an EVENT_DNS event; the numeric rcode is carried in Error.
func (e *Event) DNSResponseCode() string { return dnsRCodeName(e.Error) }

// dnsRCodeName maps a DNS response code (carried in Error for EVENT_DNS) to its
// mnemonic.
func dnsRCodeName(rcode int32) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("rcode %d", rcode)
	}
}

// IsCopyFailSignal reports whether this event is an AF_ALG bind of an "aead"
// transform by an unprivileged (uid != 0) caller.
func (e *Event) IsCopyFailSignal() bool {
	return e.Type == EventAFALG && e.Target == "aead" && e.Bytes != 0
}

func TCPStateString(state uint32) string {
	states := map[uint32]string{
		1:  "ESTABLISHED",
		2:  "SYN_SENT",
		3:  "SYN_RECV",
		4:  "FIN_WAIT1",
		5:  "FIN_WAIT2",
		6:  "TIME_WAIT",
		7:  "CLOSE",
		8:  "CLOSE_WAIT",
		9:  "LAST_ACK",
		10: "LISTEN",
		11: "CLOSING",
		12: "NEW_SYN_RECV",
	}
	if name, ok := states[state]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}

const (
	httpMethodUnknown uint8 = 0
	httpMethodGet     uint8 = 1
	httpMethodPut     uint8 = 2
	httpMethodPost    uint8 = 3
	httpMethodHead    uint8 = 4
	httpMethodPatch   uint8 = 5
	httpMethodDelete  uint8 = 6
	httpMethodOptions uint8 = 7
)

// NormalizeHTTPMethod maps a method recovered in userspace onto the
// convention's known set, returning "" for anything outside it.
func NormalizeHTTPMethod(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET":
		return "GET"
	case "HEAD":
		return "HEAD"
	case "POST":
		return "POST"
	case "PUT":
		return "PUT"
	case "PATCH":
		return "PATCH"
	case "DELETE":
		return "DELETE"
	case "OPTIONS":
		return "OPTIONS"
	case "CONNECT":
		return "CONNECT"
	case "TRACE":
		return "TRACE"
	default:
		return ""
	}
}

// HTTPMethodFromCode renders a wire method code as its canonical uppercase
// name, or "" when the probe did not recognise one.
func HTTPMethodFromCode(code uint8) string {
	switch code {
	case httpMethodGet:
		return "GET"
	case httpMethodPut:
		return "PUT"
	case httpMethodPost:
		return "POST"
	case httpMethodHead:
		return "HEAD"
	case httpMethodPatch:
		return "PATCH"
	case httpMethodDelete:
		return "DELETE"
	case httpMethodOptions:
		return "OPTIONS"
	default:
		return ""
	}
}
