// Package h3stream reassembles inbound HTTP/3 stream bytes captured by the
// C-library adapter probes (struct h3_stream_chunk from
// bpf/nghttp3.c) and decodes the QPACK field sections.
package h3stream

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/qpackdecode"
	"github.com/gma1k/podtrace/internal/safeconv"
)

// ConnKey identifies one HTTP/3 connection of one traced process.
type ConnKey struct {
	TGID uint32
	Conn uint64
}

// Section is one decoded inbound field section.
type Section struct {
	StreamID    uint64
	Fields      []qpackdecode.HeaderField
	Method      string
	Path        string
	Traceparent string
	Status      uint16
}

// Chunk mirrors struct h3_stream_chunk in bpf/events.h.
type Chunk struct {
	TGID      uint32
	Conn      uint64
	StreamID  uint64
	StreamLen uint32
	CopiedLen uint32
	Offset    uint32
	Flags     uint32
	Data      []byte
}

// ChunkFlagConnClosed mirrors H3_CHUNK_F_CONN_CLOSED: the library freed the
// connection, so its address may be reused by the next one.
const ChunkFlagConnClosed = 0x1

const chunkHeaderSize = 40

// ParseChunk decodes one h3_stream_chunks ringbuf sample.
func ParseChunk(raw []byte) (Chunk, bool) {
	if len(raw) < chunkHeaderSize {
		return Chunk{}, false
	}
	c := Chunk{
		TGID:      binary.LittleEndian.Uint32(raw[0:4]),
		Conn:      binary.LittleEndian.Uint64(raw[8:16]),
		StreamID:  binary.LittleEndian.Uint64(raw[16:24]),
		StreamLen: binary.LittleEndian.Uint32(raw[24:28]),
		CopiedLen: binary.LittleEndian.Uint32(raw[28:32]),
		Offset:    binary.LittleEndian.Uint32(raw[32:36]),
		Flags:     binary.LittleEndian.Uint32(raw[36:40]),
	}
	n := int(c.CopiedLen)
	if n > len(raw)-chunkHeaderSize {
		return Chunk{}, false
	}
	c.Data = raw[chunkHeaderSize : chunkHeaderSize+n]
	return c, true
}

// Resource bounds. All are hard caps protecting the agent against hostile
// or malformed traffic; hitting one degrades that stream or connection to
// undecoded, never the agent.
const (
	maxConnections       = 512
	maxStreamsPerConn    = 64
	maxBufferedPerStream = 8192
	maxBlockedSections   = 16
	maxHeadersPayload    = 8192

	connIdleTTL   = 2 * time.Minute
	sweepInterval = 15 * time.Second
)

// HTTP/3 wire constants (RFC 9114).
const (
	frameTypeHeaders = 0x1

	streamTypeQPACKEncoder = 0x02
)

type streamKind int

const (
	kindUnknown streamKind = iota
	kindRequest
	kindEncoder
	kindIgnore
)

type streamState struct {
	kind      streamKind
	broken    bool
	done      bool
	buf       []byte
	received  uint32
	inFrame   bool
	frameType uint64
	frameLen  uint64
	skip      uint64
}

type blockedSection struct {
	streamID uint64
	payload  []byte
}

type connState struct {
	qpack    *qpackdecode.Decoder
	streams  map[uint64]*streamState
	blocked  []blockedSection
	lastSeen time.Time
}

// Assembler turns chunks into decoded sections. It is not safe for
// concurrent use; feed it from a single reader goroutine.
type Assembler struct {
	onSection func(ConnKey, Section)
	conns     map[ConnKey]*connState
	now       func() time.Time
	lastSweep time.Time
}

// NewAssembler returns an assembler that calls onSection for every decoded
// field section.
func NewAssembler(onSection func(ConnKey, Section)) *Assembler {
	return &Assembler{
		onSection: onSection,
		conns:     make(map[ConnKey]*connState),
		now:       time.Now,
	}
}

// Feed processes one captured chunk.
func (a *Assembler) Feed(c Chunk) {
	key := ConnKey{TGID: c.TGID, Conn: c.Conn}
	if c.Flags&ChunkFlagConnClosed != 0 {
		delete(a.conns, key)
		return
	}
	if len(c.Data) == 0 {
		return
	}
	now := a.now()
	a.sweepIdle(now)
	cs := a.conns[key]
	if cs == nil {
		if len(a.conns) >= maxConnections {
			a.evictOldest()
		}
		cs = &connState{
			qpack:   qpackdecode.NewDecoder(0),
			streams: make(map[uint64]*streamState),
		}
		a.conns[key] = cs
	}
	cs.lastSeen = now

	st := cs.streams[c.StreamID]
	if st == nil {
		if len(cs.streams) >= maxStreamsPerConn && !cs.retireStream() {
			return
		}
		st = &streamState{}
		cs.streams[c.StreamID] = st
	}
	if st.broken {
		return
	}
	if c.Offset != st.received {
		st.markBroken()
		return
	}
	st.received += safeconv.IntToUint32(len(c.Data))
	st.buf = append(st.buf, c.Data...)
	if len(st.buf) > maxBufferedPerStream {
		st.markBroken()
		return
	}
	a.process(key, cs, c.StreamID, st)
	if c.CopiedLen < c.StreamLen {
		st.markBroken()
	}
}

func (st *streamState) markBroken() {
	st.broken = true
	st.buf = nil
}

// retireStream frees one stream slot so a long-lived connection keeps
// decoding past maxStreamsPerConn streams.
func (cs *connState) retireStream() bool {
	var finishedID, requestID uint64
	haveFinished, haveRequest := false, false
	for id, st := range cs.streams {
		switch {
		case st.kind == kindEncoder:
			continue
		case st.broken || st.done || st.kind == kindIgnore:
			if !haveFinished || id < finishedID {
				finishedID, haveFinished = id, true
			}
		case id&0x2 == 0:
			if !haveRequest || id < requestID {
				requestID, haveRequest = id, true
			}
		}
	}
	switch {
	case haveFinished:
		delete(cs.streams, finishedID)
	case haveRequest:
		delete(cs.streams, requestID)
	default:
		return false
	}
	return true
}

func (a *Assembler) evictOldest() {
	var oldestKey ConnKey
	var oldest time.Time
	first := true
	for k, cs := range a.conns {
		if first || cs.lastSeen.Before(oldest) {
			oldest = cs.lastSeen
			oldestKey = k
			first = false
		}
	}
	delete(a.conns, oldestKey)
}

// sweepIdle drops connections with no activity for connIdleTTL.
func (a *Assembler) sweepIdle(now time.Time) {
	if now.Sub(a.lastSweep) < sweepInterval {
		return
	}
	a.lastSweep = now
	for k, cs := range a.conns {
		if now.Sub(cs.lastSeen) > connIdleTTL {
			delete(a.conns, k)
		}
	}
}

func (a *Assembler) process(key ConnKey, cs *connState, streamID uint64, st *streamState) {
	if st.kind == kindUnknown {
		if streamID&0x2 == 0 {
			st.kind = kindRequest
		} else {
			v, n, ok := readVarint(st.buf)
			if !ok {
				return
			}
			st.buf = st.buf[n:]
			if v == streamTypeQPACKEncoder {
				st.kind = kindEncoder
			} else {
				st.kind = kindIgnore
			}
		}
	}
	switch st.kind {
	case kindEncoder:
		if len(st.buf) == 0 {
			return
		}
		buf := st.buf
		st.buf = nil
		if err := cs.qpack.ParseEncoderStream(buf); err != nil {
			st.markBroken()
			return
		}
		a.retryBlocked(key, cs)
	case kindIgnore:
		st.buf = nil
	case kindRequest:
		a.processFrames(key, cs, streamID, st)
	}
}

func (a *Assembler) processFrames(key ConnKey, cs *connState, streamID uint64, st *streamState) {
	for {
		if st.skip > 0 {
			n := uint64(len(st.buf))
			if n > st.skip {
				n = st.skip
			}
			st.buf = st.buf[n:]
			st.skip -= n
			if st.skip > 0 {
				return
			}
		}
		if !st.inFrame {
			frameType, n1, ok := readVarint(st.buf)
			if !ok {
				return
			}
			frameLen, n2, ok := readVarint(st.buf[n1:])
			if !ok {
				return
			}
			st.buf = st.buf[n1+n2:]
			if frameType != frameTypeHeaders || frameLen > maxHeadersPayload {
				st.skip = frameLen
				continue
			}
			st.inFrame = true
			st.frameType = frameType
			st.frameLen = frameLen
		}
		if uint64(len(st.buf)) < st.frameLen {
			return
		}
		payload := st.buf[:st.frameLen]
		st.buf = st.buf[st.frameLen:]
		st.inFrame = false
		st.frameType = 0
		st.frameLen = 0
		a.decodeSection(key, cs, streamID, st, payload)
		if st.broken {
			return
		}
	}
}

func (a *Assembler) decodeSection(key ConnKey, cs *connState, streamID uint64, st *streamState, payload []byte) {
	fields, err := cs.qpack.DecodeFieldSection(payload)
	var blocked *qpackdecode.BlockedError
	if errors.As(err, &blocked) {
		if len(cs.blocked) < maxBlockedSections {
			cs.blocked = append(cs.blocked, blockedSection{
				streamID: streamID,
				payload:  append([]byte(nil), payload...),
			})
		}
		return
	}
	if err != nil {
		st.markBroken()
		return
	}
	a.emit(key, cs, streamID, fields)
}

func (a *Assembler) retryBlocked(key ConnKey, cs *connState) {
	if len(cs.blocked) == 0 {
		return
	}
	kept := cs.blocked[:0]
	for _, b := range cs.blocked {
		fields, err := cs.qpack.DecodeFieldSection(b.payload)
		var blocked *qpackdecode.BlockedError
		if errors.As(err, &blocked) {
			kept = append(kept, b)
			continue
		}
		if err == nil {
			a.emit(key, cs, b.streamID, fields)
		}
	}
	cs.blocked = kept
}

func (a *Assembler) emit(key ConnKey, cs *connState, streamID uint64, fields []qpackdecode.HeaderField) {
	sec := Section{StreamID: streamID, Fields: fields}
	for _, f := range fields {
		switch f.Name {
		case ":method":
			sec.Method = f.Value
		case ":path":
			sec.Path = f.Value
		case ":status":
			sec.Status = parseStatus(f.Value)
		case "traceparent":
			sec.Traceparent = f.Value
		}
	}
	if st := cs.streams[streamID]; st != nil && (sec.Method != "" || sec.Status >= 200) {
		st.done = true
	}
	if a.onSection != nil {
		a.onSection(key, sec)
	}
}

func parseStatus(v string) uint16 {
	if len(v) != 3 {
		return 0
	}
	var s uint16
	for i := 0; i < 3; i++ {
		if v[i] < '0' || v[i] > '9' {
			return 0
		}
		s = s*10 + uint16(v[i]-'0')
	}
	return s
}

// readVarint decodes one QUIC variable-length integer (RFC 9000 §16).
func readVarint(p []byte) (uint64, int, bool) {
	if len(p) == 0 {
		return 0, 0, false
	}
	length := 1 << (p[0] >> 6)
	if len(p) < length {
		return 0, 0, false
	}
	v := uint64(p[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(p[i])
	}
	return v, length, true
}
