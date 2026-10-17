// Package h3decode turns one HTTP/3 transaction record (emitted by
// bpf/http3l7.c from the net/http boundary, or by bpf/nghttp3.c) into
// EventHTTPReq / EventHTTPResp events.
package h3decode

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
)

// Offsets mirror struct h3_txn_record in bpf/events.h.
const (
	methodMax         = 16  // H3_TXN_METHOD_MAX
	pathMax           = 256 // H3_TXN_PATH_MAX
	tpMax             = 64  // H3_TXN_TP_MAX
	hdrSlots          = 4   // H3_HDR_SLOTS
	hdrValMax         = 64  // H3_HDR_VAL_MAX
	methodOffset      = 40  // start of method[]
	pathOffset        = methodOffset + methodMax
	tpOffset          = pathOffset + pathMax
	peerOffset        = tpOffset + tpMax // peer_daddr6[16]
	hdrLenOffset      = peerOffset + 16  // hdr_vlen[hdrSlots]
	hdrValOffset      = hdrLenOffset + hdrSlots
	recordSize        = hdrValOffset + hdrSlots*hdrValMax
	adapterConnOffset = recordSize + 4
	adapterExtSize    = adapterConnOffset + 16
)

// Flags mirror H3_TXN_F_* in bpf/events.h: unpaired events from stacks with no
// request/response correlation (the nghttp3 adapter).
const (
	FlagRequestOnly  = 0x1
	FlagResponseOnly = 0x2
	FlagAborted      = 0x4
)

type Header struct {
	Name  string
	Value string
}

// Txn is one decoded HTTP/3 transaction.
type Txn struct {
	Timestamp     uint64
	LatencyNS     uint64
	CgroupID      uint64
	PID           uint32
	Status        uint16
	IsClient      bool
	Flags         uint8
	Method        string
	Path          string
	Traceparent   string
	PeerIP        string
	PeerPort      uint16
	Headers       []Header
	AdapterConn   uint64
	AdapterStream uint64
}

// Decoder decodes h3 transaction records; headerNames is the configured
// capture allowlist, in the same slot order pushed into the h3_hdr_names map.
type Decoder struct {
	headerNames []string
}

func NewDecoder(headerNames []string) *Decoder {
	return &Decoder{headerNames: headerNames}
}

// ParseRecord decodes one ringbuf sample into a Txn.
func (d *Decoder) ParseRecord(data []byte) (*Txn, bool) {
	t, ok := ParseRecord(data)
	if !ok {
		return nil, false
	}
	if len(d.headerNames) > 0 {
		for slot := 0; slot < hdrSlots && slot < len(d.headerNames); slot++ {
			vlen := int(data[hdrLenOffset+slot])
			if vlen == 0 {
				continue
			}
			if vlen > hdrValMax {
				vlen = hdrValMax
			}
			off := hdrValOffset + slot*hdrValMax
			t.Headers = append(t.Headers, Header{
				Name:  d.headerNames[slot],
				Value: string(data[off : off+vlen]),
			})
		}
	}
	return t, true
}

// ParseRecord decodes the fixed fields of one ringbuf sample into a Txn.
func ParseRecord(data []byte) (*Txn, bool) {
	if len(data) < recordSize {
		return nil, false
	}
	methodLen := int(data[31])
	if methodLen > methodMax {
		methodLen = methodMax
	}
	pathLen := int(binary.LittleEndian.Uint16(data[32:34]))
	if pathLen > pathMax {
		pathLen = pathMax
	}
	tpLen := int(data[34])
	if tpLen > tpMax {
		tpLen = tpMax
	}
	t := &Txn{
		Timestamp:   binary.LittleEndian.Uint64(data[0:8]),
		LatencyNS:   binary.LittleEndian.Uint64(data[8:16]),
		CgroupID:    binary.LittleEndian.Uint64(data[16:24]),
		PID:         binary.LittleEndian.Uint32(data[24:28]),
		Status:      binary.LittleEndian.Uint16(data[28:30]),
		IsClient:    data[30] != 0,
		Flags:       data[35],
		Method:      string(data[methodOffset : methodOffset+methodLen]),
		Path:        string(data[pathOffset : pathOffset+pathLen]),
		Traceparent: string(data[tpOffset : tpOffset+tpLen]),
	}
	t.PeerIP, t.PeerPort = decodePeer(data[36], binary.LittleEndian.Uint16(data[38:40]),
		data[peerOffset:peerOffset+16])
	if len(data) >= adapterExtSize {
		t.AdapterConn = binary.LittleEndian.Uint64(data[adapterConnOffset:])
		t.AdapterStream = binary.LittleEndian.Uint64(data[adapterConnOffset+8:])
	}
	return t, true
}

// decodePeer renders the record's peer address, normalizing Go's 16-byte
// IPv4-mapped form back to dotted quad.
func decodePeer(family uint8, port uint16, addr []byte) (string, uint16) {
	if family == 0 || port == 0 {
		return "", 0
	}
	var ip net.IP
	switch family {
	case 2:
		ip = net.IP(addr[:4])
	case 10:
		ip = net.IP(addr[:16])
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
	default:
		return "", 0
	}
	if ip.IsUnspecified() {
		return "", 0
	}
	return ip.String(), port
}

// Events turns a transaction into the request and response events that flow
// through the same enrichment + reporting path as other L7 events.
func (t *Txn) Events() []*events.Event {
	target := "HTTP/3"
	observed := events.NormalizeHTTPMethod(t.Method)
	if t.Path != "" {
		method := t.Method
		if method == "" {
			method = "GET"
		}
		target = method + " " + t.Path
	}
	status := strconv.Itoa(int(t.Status))
	if t.Status == 0 {
		// Paired without a readable status (C-library adapters measure TTFB
		// but cannot decode the peer's headers) or a client-side error.
		status = ""
	}
	if t.Flags&FlagAborted != 0 {
		status = "aborted"
	}

	var extra []string
	for _, h := range t.Headers {
		extra = append(extra, h.Name+": "+h.Value)
	}

	var out []*events.Event
	if t.Flags&FlagResponseOnly == 0 {
		req := &events.Event{
			Timestamp:     t.Timestamp,
			PID:           t.PID,
			CgroupID:      t.CgroupID,
			Type:          events.EventHTTPReq,
			TCPState:      events.HTTPTransportH3 | events.HTTPRoleBits(!t.IsClient),
			Target:        target,
			CorrelationID: t.Timestamp,
			HTTPMethod:    observed,
		}
		var lines []string
		if t.Traceparent != "" {
			lines = append(lines, "traceparent: "+t.Traceparent)
		}
		lines = append(lines, extra...)
		req.Details = strings.Join(lines, "\n")
		setTxnPeer(req, t)
		out = append(out, req)
	}
	if t.Flags&FlagRequestOnly == 0 {
		resp := &events.Event{
			Timestamp:     t.Timestamp + t.LatencyNS,
			PID:           t.PID,
			CgroupID:      t.CgroupID,
			Type:          events.EventHTTPResp,
			TCPState:      events.HTTPTransportH3 | events.HTTPRoleBits(!t.IsClient),
			Target:        target,
			HTTPMethod:    observed,
			Details:       joinNonEmpty(append([]string{status}, extra...)),
			LatencyNS:     t.LatencyNS,
			CorrelationID: t.Timestamp,
		}
		if t.Status >= 500 && t.Status <= 599 {
			resp.Error = safeconv.IntToInt32(int(t.Status))
		}
		setTxnPeer(resp, t)
		out = append(out, resp)
	}
	return out
}

// joinNonEmpty joins the non-empty lines with newlines.
func joinNonEmpty(lines []string) string {
	out := lines[:0]
	for _, l := range lines {
		if l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func setTxnPeer(ev *events.Event, t *Txn) {
	if t.PeerIP == "" {
		return
	}
	ev.PeerDstIP = t.PeerIP
	ev.PeerDstPort = t.PeerPort
}
