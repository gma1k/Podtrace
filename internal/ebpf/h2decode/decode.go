// Package h2decode is the userspace HTTP/2 HPACK decode.

package h2decode

import (
	"container/list"
	"encoding/binary"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
)

// recordHeaderSize is the fixed prefix of struct h2_hdr_record incl. the
// L7<->L4 peer 4-tuple appended after _pad.
const recordHeaderSize = 96

// Flag bits mirror H2_HDR_FLAG_* in bpf/events.h.
const (
	flagEndHeaders   = 0x1
	flagContinuation = 0x2
	flagClose        = 0x4
	flagMidFrame     = 0x8
)

// Direction values mirror H2_DIR_* in bpf/events.h.
const (
	DirEgress  uint8 = 0
	DirIngress uint8 = 1
)

// Tunables. Defaults chosen to bound memory under connection churn while
// tolerating realistic cross-CPU reordering.
const (
	defaultMaxConns         = 4096
	defaultMaxPendingPerDir = 256
	defaultMaxAssembly      = 64 * 1024
	defaultMaxStreams       = 8192
	defaultTTL              = 60 * time.Second
	defaultGapTimeout       = 2 * time.Second

	defaultMaxRetainedBytes = 64 << 20

	maxGrpcStatusCode = 16
)

// unknownPathPlaceholder stands in for a request :path that was HPACK-indexed
// into the connection's dynamic table before capture attached, so its literal
// was never observed.
const unknownPathPlaceholder = "<unknown-path>"

const (
	roleUnknown uint8 = iota
	roleRequest
	roleResponse
)

// RawRecord is a parsed struct h2_hdr_record plus its raw HPACK fragment.
type RawRecord struct {
	ConnID    uint64
	Timestamp uint64
	CgroupID  uint64
	PID       uint32
	Seq       uint32
	StreamID  uint32
	FragLen   uint16
	Direction uint8
	Transport uint8
	Flags     uint8
	Frag      []byte

	PeerSrcIP   string
	PeerDstIP   string
	PeerSrcPort uint16
	PeerDstPort uint16
}

func (r *RawRecord) endHeaders() bool { return r.Flags&flagEndHeaders != 0 }

func (r *RawRecord) IsClose() bool { return r.Flags&flagClose != 0 }

// ParseRecord decodes one ringbuf sample into a RawRecord.
func ParseRecord(data []byte) (*RawRecord, bool) {
	if len(data) < recordHeaderSize {
		return nil, false
	}
	fragLen := binary.LittleEndian.Uint16(data[36:38])
	if recordHeaderSize+int(fragLen) > len(data) {
		return nil, false
	}
	r := &RawRecord{
		ConnID:    binary.LittleEndian.Uint64(data[0:8]),
		Timestamp: binary.LittleEndian.Uint64(data[8:16]),
		CgroupID:  binary.LittleEndian.Uint64(data[16:24]),
		PID:       binary.LittleEndian.Uint32(data[24:28]),
		Seq:       binary.LittleEndian.Uint32(data[28:32]),
		StreamID:  binary.LittleEndian.Uint32(data[32:36]),
		FragLen:   fragLen,
		Direction: data[38],
		Transport: data[39],
		Flags:     data[40],
	}
	var sa6, da6 [16]byte
	copy(sa6[:], data[64:80])
	copy(da6[:], data[80:96])
	family := data[60]
	r.PeerSrcIP = events.PeerIP(family, binary.LittleEndian.Uint32(data[48:52]), sa6)
	r.PeerDstIP = events.PeerIP(family, binary.LittleEndian.Uint32(data[52:56]), da6)
	r.PeerSrcPort = binary.LittleEndian.Uint16(data[56:58])
	r.PeerDstPort = binary.LittleEndian.Uint16(data[58:60])
	if fragLen > 0 {
		r.Frag = make([]byte, fragLen)
		copy(r.Frag, data[recordHeaderSize:recordHeaderSize+int(fragLen)])
	}
	return r, true
}

type connKey struct {
	conn uint64
	dir  uint8
}

type streamKey struct {
	conn   uint64
	stream uint32
}

// dirState is the ordered decode state for one (connection, direction).
type dirState struct {
	key          connKey
	elem         *list.Element
	dec          *lateJoinDecoder
	role         uint8
	nextSeq      uint32
	pending      map[uint32]*RawRecord
	pendingBytes int
	asm          []byte
	lastSeen     time.Time
	stalled      time.Time
	discarding   bool

	skipLow  uint32
	skipHigh uint32
	skipped  bool
}

// footprint is the memory this direction holds that traffic controls.
func (st *dirState) footprint() int {
	return st.dec.trackedBytes + len(st.asm) + st.pendingBytes
}

func (st *dirState) inSkippedRange(seq uint32) bool {
	return st.skipped && !seqLess(seq, st.skipLow) && seqLess(seq, st.skipHigh)
}

func (st *dirState) takePending(seq uint32) (*RawRecord, bool) {
	rec, ok := st.pending[seq]
	if ok {
		delete(st.pending, seq)
		st.pendingBytes -= len(rec.Frag)
	}
	return rec, ok
}

// pendingReq is a request awaiting its response, for latency + endpoint stitching.
type pendingReq struct {
	key       streamKey
	elem      *list.Element
	method    string
	path      string
	transport uint8
	startTS   uint64
	lastSeen  time.Time
	grpc      bool
	held      *events.Event
}

// isGRPCContentType reports whether a content-type header names gRPC.
func isGRPCContentType(v string) bool {
	return strings.HasPrefix(strings.ToLower(v), "application/grpc")
}

// Decoder owns all per-connection decode state.
//
// dirOrder and streamOrder keep their entries least recently used first, so
// eviction under pressure is O(1); connStreams indexes streams by connection
// so a close only touches that connection's streams.
type Decoder struct {
	mu          sync.Mutex
	dirs        map[connKey]*dirState
	dirOrder    *list.List
	streams     map[streamKey]*pendingReq
	streamOrder *list.List
	connStreams map[uint64]map[uint32]struct{}

	captureHeaders []string

	maxConns         int
	maxPendingPerDir int
	maxAssembly      int
	maxStreams       int
	maxRetainedBytes int
	ttl              time.Duration
	gapTimeout       time.Duration

	nowFn func() time.Time

	retainedBytes int

	decodeErrors      uint64
	gapsSkipped       uint64
	evictions         uint64
	partialBlocks     uint64
	anonymousRequests uint64
	lateRecords       uint64
	sequenceRestarts  uint64
	budgetSheds       uint64
}

// New returns a Decoder with default tunables.
func New() *Decoder {
	return &Decoder{
		dirs:             make(map[connKey]*dirState),
		dirOrder:         list.New(),
		streams:          make(map[streamKey]*pendingReq),
		streamOrder:      list.New(),
		connStreams:      make(map[uint64]map[uint32]struct{}),
		maxConns:         defaultMaxConns,
		maxPendingPerDir: defaultMaxPendingPerDir,
		maxAssembly:      defaultMaxAssembly,
		maxStreams:       defaultMaxStreams,
		maxRetainedBytes: defaultMaxRetainedBytes,
		ttl:              defaultTTL,
		gapTimeout:       defaultGapTimeout,
		nowFn:            time.Now,
	}
}

func (d *Decoder) now() time.Time { return d.nowFn() }

// SetCaptureHeaders configures the allowlist of extra header names (matched
// case-insensitively) whose values are appended to event Details.
func (d *Decoder) SetCaptureHeaders(names []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.captureHeaders = d.captureHeaders[:0]
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" {
			d.captureHeaders = append(d.captureHeaders, n)
		}
	}
}

// Ingest feeds one raw record and returns any events whose header blocks
// completed and decoded as a result.
func (d *Decoder) Ingest(rec *RawRecord) []*events.Event {
	if rec == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	key := connKey{conn: rec.ConnID, dir: rec.Direction}
	st := d.dirs[key]
	if st == nil {
		d.evictIfFullLocked()
		st = &dirState{
			key:     key,
			dec:     &lateJoinDecoder{},
			nextSeq: 0,
			pending: make(map[uint32]*RawRecord),
		}
		st.elem = d.dirOrder.PushBack(st)
		d.dirs[key] = st
	}

	before := st.footprint()
	if seqLess(rec.Seq, st.nextSeq) {
		if !d.isSequenceRestart(st, rec.Seq) {
			d.lateRecords++
			return nil
		}
		d.sequenceRestarts++
		restartDir(st, rec.Seq)
	}
	st.lastSeen = d.now()
	d.dirOrder.MoveToBack(st.elem)

	if old, dup := st.pending[rec.Seq]; dup {
		st.pendingBytes -= len(old.Frag)
	}
	st.pending[rec.Seq] = rec
	st.pendingBytes += len(rec.Frag)

	if len(st.pending) > d.maxPendingPerDir {
		d.skipGapLocked(st)
	}

	out := d.drainLocked(st)
	d.settleLocked(st, before)
	return out
}

// isSequenceRestart tells a record behind nextSeq apart: one from a range
// the gap logic already gave up on is late, while seq 0, or a jump back
// further than any reordering window, means BPF restarted the sequence for a
// new connection on this socket (its h2_seq entry was evicted, or the close
// record was lost and the socket address reused).
func (d *Decoder) isSequenceRestart(st *dirState, seq uint32) bool {
	if st.inSkippedRange(seq) {
		return false
	}
	return seq == 0 || st.nextSeq-seq > uint32(d.maxPendingPerDir)
}

// restartDir resets a direction to decode a new connection from seq.
func restartDir(st *dirState, seq uint32) {
	st.dec.reset()
	st.role = roleUnknown
	st.nextSeq = seq
	st.pending = make(map[uint32]*RawRecord)
	st.pendingBytes = 0
	st.asm = nil
	st.stalled = time.Time{}
	st.discarding = false
	st.skipped = false
}

// settleLocked charges a direction's change in footprint to the global
// budget and, when the budget is exceeded, sheds the direction that crossed
// it: its HPACK window, partial block and buffered records.
func (d *Decoder) settleLocked(st *dirState, before int) {
	d.retainedBytes += st.footprint() - before
	if d.retainedBytes <= d.maxRetainedBytes {
		return
	}
	d.budgetSheds++
	shed := st.footprint()
	st.dec.resetEpoch()
	if len(st.asm) > 0 {
		st.discarding = true
	}
	st.asm = nil
	if len(st.pending) > 0 {
		highest := st.nextSeq
		for seq := range st.pending {
			if !seqLess(seq, highest) {
				highest = seq
			}
		}
		st.skipLow, st.skipHigh, st.skipped = st.nextSeq, highest+1, true
		st.nextSeq = highest + 1
		st.pending = make(map[uint32]*RawRecord)
		st.pendingBytes = 0
		st.discarding = true
		st.stalled = time.Time{}
	}
	d.retainedBytes -= shed - st.footprint()
}

// dropDirLocked removes a direction and returns its bytes to the budget.
func (d *Decoder) dropDirLocked(st *dirState) {
	d.retainedBytes -= st.footprint()
	d.dirOrder.Remove(st.elem)
	delete(d.dirs, st.key)
}

// drainLocked releases buffered records in seq order, reassembles complete
// header blocks, and decodes them.
func (d *Decoder) drainLocked(st *dirState) []*events.Event {
	var out []*events.Event
	for {
		rec, ok := st.takePending(st.nextSeq)
		if !ok {
			if len(st.pending) > 0 && st.stalled.IsZero() {
				st.stalled = d.now()
			}
			break
		}
		st.nextSeq++
		st.stalled = time.Time{}

		if !st.discarding && len(st.asm) == 0 && rec.Flags&(flagContinuation|flagMidFrame) != 0 {
			st.discarding = true
		}
		if st.discarding {
			if rec.endHeaders() {
				st.discarding = false
			}
			continue
		}

		st.asm = append(st.asm, rec.Frag...)
		if len(st.asm) > d.maxAssembly {
			st.asm = nil
			d.decodeErrors++
			st.dec.resetEpoch()
			if !rec.endHeaders() {
				st.discarding = true
			}
			continue
		}
		if !rec.endHeaders() {
			continue
		}

		block := st.asm
		st.asm = nil
		if ev := d.decodeBlockLocked(st, rec, block); ev != nil {
			out = append(out, ev)
		}
	}
	return out
}

// decodeBlockLocked decodes one complete header block and builds an event.
func (d *Decoder) decodeBlockLocked(st *dirState, rec *RawRecord, block []byte) *events.Event {
	fields, complete, err := st.dec.decodeBlock(block)
	if err != nil {
		d.decodeErrors++
		st.dec.resetEpoch()
		return nil
	}
	if !complete {
		d.partialBlocks++
	}

	var method, path, status, traceparent, grpcStatus string
	var extra []string
	grpc := false
	for _, f := range fields {
		if strings.EqualFold(f.Name, "content-type") && isGRPCContentType(f.Value) {
			grpc = true
		}
		switch {
		case f.Name == ":method":
			method = f.Value
		case f.Name == ":path":
			path = f.Value
		case f.Name == ":status":
			status = f.Value
		case f.Name == "grpc-status":
			grpcStatus = f.Value
		case strings.EqualFold(f.Name, "traceparent"):
			traceparent = f.Value
		default:
			for _, want := range d.captureHeaders {
				if strings.EqualFold(f.Name, want) {
					extra = append(extra, want+": "+f.Value)
					break
				}
			}
		}
	}

	switch {
	case path != "":
		st.role = roleRequest
		ev := d.buildRequestLocked(rec, method, path, traceparent, extra)
		if req := d.streams[streamKey{conn: rec.ConnID, stream: rec.StreamID}]; req != nil && grpc {
			req.grpc = true
		}
		return ev
	case status != "":
		st.role = roleResponse
		if len(status) == 3 && status[0] == '1' {
			return nil
		}
		if grpcStatus == "" && d.isGRPCStreamLocked(rec, grpc) {
			d.holdGRPCResponseLocked(rec, status, traceparent, extra)
			return nil
		}
		if grpcStatus != "" {
			extra = append(extra, "grpc-status: "+grpcStatus)
		}
		ev := d.buildResponseLocked(rec, status, traceparent, extra)
		if ev != nil && ev.Error == 0 {
			if code, err := strconv.Atoi(grpcStatus); err == nil && code > 0 && code <= maxGrpcStatusCode {
				ev.Error = safeconv.IntToInt32(code)
			}
		}
		return ev
	case grpcStatus != "":
		st.role = roleResponse
		if ev := d.finishHeldGRPCLocked(rec, grpcStatus); ev != nil {
			return ev
		}
		return d.buildGrpcTrailerLocked(rec, grpcStatus)
	case !complete:
		return d.buildAnonymousRequestLocked(st, rec, method, traceparent, extra)
	default:
		return nil
	}
}

// buildAnonymousRequestLocked handles a partially-decoded block carrying no
// recognizable pseudo-header: on a late-joined connection this is the
// steady-state shape of a request whose :path was indexed before capture
// attached.
func (d *Decoder) buildAnonymousRequestLocked(st *dirState, rec *RawRecord, method,
	traceparent string, extra []string) *events.Event {
	requestDir := st.role == roleRequest
	if !requestDir && st.role == roleUnknown {
		other := d.dirs[connKey{conn: rec.ConnID, dir: otherDirection(rec.Direction)}]
		requestDir = other != nil && other.role == roleResponse
	}
	if !requestDir {
		return nil
	}
	if _, exists := d.streams[streamKey{conn: rec.ConnID, stream: rec.StreamID}]; exists {
		return nil
	}
	if method == "" {
		method = "?"
	}
	d.anonymousRequests++
	return d.buildRequestLocked(rec, method, unknownPathPlaceholder, traceparent, extra)
}

// requestRoleBits returns the role a request seen in dir implies: a request
// the process received means it served the call.
func requestRoleBits(dir uint8) uint32 {
	switch dir {
	case DirIngress:
		return events.HTTPRoleBits(true)
	case DirEgress:
		return events.HTTPRoleBits(false)
	default:
		return 0
	}
}

// responseRoleBits returns the role a response seen in dir implies: a
// response the process sent means it served the call.
func responseRoleBits(dir uint8) uint32 {
	switch dir {
	case DirEgress:
		return events.HTTPRoleBits(true)
	case DirIngress:
		return events.HTTPRoleBits(false)
	default:
		return 0
	}
}

func otherDirection(dir uint8) uint8 {
	if dir == DirEgress {
		return DirIngress
	}
	return DirEgress
}

func (d *Decoder) buildRequestLocked(rec *RawRecord, method, path, traceparent string,
	extra []string) *events.Event {
	observed := events.NormalizeHTTPMethod(method)
	if method == "" {
		method = "GET"
	}
	d.rememberStreamLocked(rec, method, path)

	ev := &events.Event{}
	ev.HTTPMethod = observed
	ev.Timestamp = rec.Timestamp
	ev.PID = rec.PID
	ev.CgroupID = rec.CgroupID
	ev.Type = events.EventHTTPReq
	ev.TCPState = uint32(rec.Transport) | requestRoleBits(rec.Direction)
	ev.CorrelationID = rec.Timestamp
	ev.Target = method + " " + path
	var lines []string
	if traceparent != "" {
		lines = append(lines, "traceparent: "+traceparent)
	}
	lines = append(lines, extra...)
	ev.Details = strings.Join(lines, "\n")
	setEventPeer(ev, rec)
	return ev
}

// setEventPeer copies the L7<->L4 fused peer 4-tuple onto a decoded event.
func setEventPeer(ev *events.Event, rec *RawRecord) {
	ev.PeerSrcIP = rec.PeerSrcIP
	ev.PeerDstIP = rec.PeerDstIP
	ev.PeerSrcPort = rec.PeerSrcPort
	ev.PeerDstPort = rec.PeerDstPort
}

func (d *Decoder) buildResponseLocked(rec *RawRecord, status, traceparent string,
	extra []string) *events.Event {
	ev := &events.Event{}
	ev.Timestamp = rec.Timestamp
	ev.PID = rec.PID
	ev.CgroupID = rec.CgroupID
	ev.Type = events.EventHTTPResp
	ev.TCPState = uint32(rec.Transport) | responseRoleBits(rec.Direction)
	ev.Details = status
	if code, err := strconv.Atoi(status); err == nil && code >= 500 && code <= 599 {
		ev.Error = safeconv.IntToInt32(code)
	}

	sk := streamKey{conn: rec.ConnID, stream: rec.StreamID}
	if req, ok := d.streams[sk]; ok {
		ev.Target = req.method + " " + req.path
		ev.HTTPMethod = events.NormalizeHTTPMethod(req.method)
		ev.CorrelationID = req.startTS
		if rec.Timestamp > req.startTS {
			ev.LatencyNS = rec.Timestamp - req.startTS
		}
		d.deleteStreamLocked(sk)
	} else {
		ev.Target = status
	}
	if traceparent != "" && ev.Details == status {
		ev.Details = "traceparent: " + traceparent
	}
	if len(extra) > 0 {
		ev.Details = strings.Join(append([]string{ev.Details}, extra...), "\n")
	}
	setEventPeer(ev, rec)
	return ev
}

// isGRPCStreamLocked reports whether a response belongs to a gRPC call: its
// request said so, or the response itself does.
func (d *Decoder) isGRPCStreamLocked(rec *RawRecord, responseSaysGRPC bool) bool {
	if responseSaysGRPC {
		return true
	}
	req := d.streams[streamKey{conn: rec.ConnID, stream: rec.StreamID}]
	return req != nil && req.grpc
}

// holdGRPCResponseLocked keeps a gRPC call's response HEADERS instead of
// emitting it.
func (d *Decoder) holdGRPCResponseLocked(rec *RawRecord, status, traceparent string, extra []string) {
	sk := streamKey{conn: rec.ConnID, stream: rec.StreamID}
	req, ok := d.streams[sk]
	if !ok {
		req = &pendingReq{transport: rec.Transport}
		d.putStreamLocked(sk, req)
	}
	req.grpc = true
	req.lastSeen = d.now()
	d.streamOrder.MoveToBack(req.elem)
	ev := &events.Event{}
	ev.Timestamp = rec.Timestamp
	ev.PID = rec.PID
	ev.CgroupID = rec.CgroupID
	ev.Type = events.EventHTTPResp
	ev.TCPState = uint32(rec.Transport) | responseRoleBits(rec.Direction)
	ev.Details = status
	if code, err := strconv.Atoi(status); err == nil && code >= 500 && code <= 599 {
		ev.Error = safeconv.IntToInt32(code)
	}
	if req.path != "" {
		ev.Target = req.method + " " + req.path
		ev.HTTPMethod = events.NormalizeHTTPMethod(req.method)
		ev.CorrelationID = req.startTS
	} else {
		ev.Target = status
	}
	if traceparent != "" {
		ev.Details = status + "\ntraceparent: " + traceparent
	}
	if len(extra) > 0 {
		ev.Details = strings.Join(append([]string{ev.Details}, extra...), "\n")
	}
	setEventPeer(ev, rec)
	req.held = ev
}

// finishHeldGRPCLocked completes a held gRPC response with its trailers and
// returns the one event the call counts as, or nil when nothing was held.
func (d *Decoder) finishHeldGRPCLocked(rec *RawRecord, grpcStatus string) *events.Event {
	sk := streamKey{conn: rec.ConnID, stream: rec.StreamID}
	req, ok := d.streams[sk]
	if !ok || req.held == nil {
		return nil
	}
	d.deleteStreamLocked(sk)
	ev := req.held
	ev.Timestamp = rec.Timestamp
	if req.startTS > 0 && rec.Timestamp > req.startTS {
		ev.LatencyNS = rec.Timestamp - req.startTS
	}
	ev.Details += "\ngrpc-status: " + grpcStatus
	if ev.Error == 0 {
		if code, err := strconv.Atoi(grpcStatus); err == nil && code > 0 && code <= maxGrpcStatusCode {
			ev.Error = safeconv.IntToInt32(code)
		}
	}
	return ev
}

// buildGrpcTrailerLocked turns a trailers-only / trailing HEADERS block carrying
// grpc-status into a response event, so gRPC outcomes from non-Go servers are
// visible even though the response HEADERS block held no :status.
func (d *Decoder) buildGrpcTrailerLocked(rec *RawRecord, grpcStatus string) *events.Event {
	ev := &events.Event{}
	ev.Timestamp = rec.Timestamp
	ev.PID = rec.PID
	ev.CgroupID = rec.CgroupID
	ev.Type = events.EventHTTPResp
	ev.TCPState = uint32(rec.Transport) | responseRoleBits(rec.Direction)
	ev.Details = "grpc-status: " + grpcStatus
	if code, err := strconv.Atoi(grpcStatus); err == nil && code > 0 && code <= maxGrpcStatusCode {
		ev.Error = safeconv.IntToInt32(code)
	}

	sk := streamKey{conn: rec.ConnID, stream: rec.StreamID}
	if req, ok := d.streams[sk]; ok {
		ev.Target = req.method + " " + req.path
		ev.HTTPMethod = events.NormalizeHTTPMethod(req.method)
		ev.CorrelationID = req.startTS
		if rec.Timestamp > req.startTS {
			ev.LatencyNS = rec.Timestamp - req.startTS
		}
		d.deleteStreamLocked(sk)
	} else {
		ev.Target = "grpc-status " + grpcStatus
	}
	setEventPeer(ev, rec)
	return ev
}

func (d *Decoder) rememberStreamLocked(rec *RawRecord, method, path string) {
	if rec.StreamID == 0 {
		return
	}
	d.putStreamLocked(streamKey{conn: rec.ConnID, stream: rec.StreamID}, &pendingReq{
		method:    method,
		path:      path,
		transport: rec.Transport,
		startTS:   rec.Timestamp,
		lastSeen:  d.now(),
	})
}

// putStreamLocked stores req under sk, replacing any previous request on
// that stream and evicting the least recently used one when full.
func (d *Decoder) putStreamLocked(sk streamKey, req *pendingReq) {
	d.deleteStreamLocked(sk)
	if len(d.streams) >= d.maxStreams {
		if front := d.streamOrder.Front(); front != nil {
			d.deleteStreamLocked(front.Value.(*pendingReq).key)
		}
	}
	req.key = sk
	req.elem = d.streamOrder.PushBack(req)
	d.streams[sk] = req
	byConn := d.connStreams[sk.conn]
	if byConn == nil {
		byConn = make(map[uint32]struct{})
		d.connStreams[sk.conn] = byConn
	}
	byConn[sk.stream] = struct{}{}
}

func (d *Decoder) deleteStreamLocked(sk streamKey) {
	req, ok := d.streams[sk]
	if !ok {
		return
	}
	d.streamOrder.Remove(req.elem)
	delete(d.streams, sk)
	if byConn := d.connStreams[sk.conn]; byConn != nil {
		delete(byConn, sk.stream)
		if len(byConn) == 0 {
			delete(d.connStreams, sk.conn)
		}
	}
}

// skipGapLocked advances past the lowest missing seq so a lost fragment cannot
// stall the connection. Dynamic-table insertions may have happened inside the
// gap, so the observed-insertion window restarts.
func (d *Decoder) skipGapLocked(st *dirState) {
	lowest, ok := lowestSeq(st.pending)
	if !ok {
		return
	}
	st.skipLow, st.skipHigh, st.skipped = st.nextSeq, lowest, true
	st.nextSeq = lowest
	if len(st.asm) > 0 {
		st.discarding = true
	}
	st.asm = nil
	st.stalled = time.Time{}
	st.dec.resetEpoch()
	d.gapsSkipped++
}

// Sweep releases connections stuck behind a gap past the timeout and evicts
// idle state.
func (d *Decoder) Sweep() []*events.Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()

	var out []*events.Event
	for _, st := range d.dirs {
		if !st.stalled.IsZero() && now.Sub(st.stalled) > d.gapTimeout {
			before := st.footprint()
			d.skipGapLocked(st)
			out = append(out, d.drainLocked(st)...)
			d.settleLocked(st, before)
		}
		if now.Sub(st.lastSeen) > d.ttl {
			d.dropDirLocked(st)
			d.evictions++
		}
	}
	for e := d.streamOrder.Front(); e != nil; {
		req := e.Value.(*pendingReq)
		e = e.Next()
		if now.Sub(req.lastSeen) <= d.ttl {
			break
		}
		if req.held != nil {
			out = append(out, req.held)
		}
		d.deleteStreamLocked(req.key)
	}
	return out
}

// Evict drops all decode state for a connection (both directions) and its
// outstanding stream correlations.
func (d *Decoder) Evict(connID uint64) []*events.Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, dir := range []uint8{DirEgress, DirIngress} {
		if st := d.dirs[connKey{conn: connID, dir: dir}]; st != nil {
			d.dropDirLocked(st)
		}
	}
	var out []*events.Event
	for stream := range d.connStreams[connID] {
		sk := streamKey{conn: connID, stream: stream}
		if req := d.streams[sk]; req != nil && req.held != nil {
			out = append(out, req.held)
		}
		d.deleteStreamLocked(sk)
	}
	return out
}

func (d *Decoder) evictIfFullLocked() {
	if len(d.dirs) < d.maxConns {
		return
	}
	if front := d.dirOrder.Front(); front != nil {
		d.dropDirLocked(front.Value.(*dirState))
		d.evictions++
	}
}

// Stats reports diagnostic counters.
type Stats struct {
	Conns             int
	Streams           int
	RetainedBytes     int
	DecodeErrors      uint64
	GapsSkipped       uint64
	Evictions         uint64
	PartialBlocks     uint64
	AnonymousRequests uint64
	LateRecords       uint64
	SequenceRestarts  uint64
	BudgetSheds       uint64
}

func (d *Decoder) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Stats{
		Conns:             len(d.dirs),
		Streams:           len(d.streams),
		DecodeErrors:      d.decodeErrors,
		GapsSkipped:       d.gapsSkipped,
		Evictions:         d.evictions,
		RetainedBytes:     d.retainedBytes,
		PartialBlocks:     d.partialBlocks,
		AnonymousRequests: d.anonymousRequests,
		LateRecords:       d.lateRecords,
		SequenceRestarts:  d.sequenceRestarts,
		BudgetSheds:       d.budgetSheds,
	}
}

// seqLess reports whether a is before b in u32 sequence space, tolerating
// wraparound.
func seqLess(a, b uint32) bool {
	return a-b >= 1<<31
}

func lowestSeq(m map[uint32]*RawRecord) (uint32, bool) {
	var lowest uint32
	found := false
	for s := range m {
		if !found || seqLess(s, lowest) {
			lowest = s
			found = true
		}
	}
	return lowest, found
}

// IsGRPCResponse reports whether an event is a gRPC call's response as this
// decoder builds it: one carrying the call's grpc-status.
func IsGRPCResponse(ev *events.Event) bool {
	if ev == nil || ev.Type != events.EventHTTPResp {
		return false
	}
	for _, line := range strings.Split(ev.Details, "\n") {
		if strings.HasPrefix(line, "grpc-status: ") {
			return true
		}
	}
	return false
}
