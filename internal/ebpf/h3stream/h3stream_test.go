package h3stream

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/h3decode"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// frame prepends an HTTP/3 frame header (type, length) to a payload.
func frame(frameType uint64, payload []byte) []byte {
	out := appendVarint(nil, frameType)
	out = appendVarint(out, uint64(len(payload)))
	return append(out, payload...)
}

func appendVarint(dst []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(dst, byte(v))
	case v < 1<<14:
		return append(dst, 0x40|byte(v>>8), byte(v))
	case v < 1<<30:
		return append(dst, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst, 0xc0|byte(v>>56), byte(v>>48), byte(v>>40),
			byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

type collector struct {
	sections []Section
	keys     []ConnKey
}

func (c *collector) collect(k ConnKey, s Section) {
	c.keys = append(c.keys, k)
	c.sections = append(c.sections, s)
}

func feed(a *Assembler, conn, stream uint64, offset uint32, data []byte) {
	a.Feed(Chunk{
		TGID:      42,
		Conn:      conn,
		StreamID:  stream,
		StreamLen: uint32(len(data)),
		CopiedLen: uint32(len(data)),
		Offset:    offset,
		Data:      data,
	})
}

// requestSection is a static-only field section: :method GET (static 17),
// :path /x (literal with static name reference 1).
func requestSection(t *testing.T) []byte {
	return mustHex(t, "0000 d1 51 02 2f 78")
}

// responseSection is :status 200 (static 25).
func responseSection(t *testing.T) []byte {
	return mustHex(t, "0000 d9")
}

func TestStaticRequestSection(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)

	feed(a, 0x1000, 0, 0, frame(frameTypeHeaders, requestSection(t)))

	if len(c.sections) != 1 {
		t.Fatalf("got %d sections, want 1", len(c.sections))
	}
	sec := c.sections[0]
	if sec.Method != "GET" || sec.Path != "/x" || sec.Status != 0 {
		t.Fatalf("section = %+v", sec)
	}
	if c.keys[0] != (ConnKey{TGID: 42, Conn: 0x1000}) {
		t.Fatalf("key = %+v", c.keys[0])
	}
}

// TestDynamicTableAcrossStreams replays RFC 9204 Appendix B through the
// full pipeline.
func TestDynamicTableAcrossStreams(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0x2000

	feed(a, conn, 4, 0, frame(frameTypeHeaders, mustHex(t, "0381 10 11")))
	if len(c.sections) != 0 {
		t.Fatalf("blocked section emitted early: %+v", c.sections)
	}

	control := append([]byte{0x00}, frame(0x4, mustHex(t, "01 40dc"))...)
	feed(a, conn, 3, 0, control)

	encoder := append([]byte{0x02}, mustHex(t,
		"3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468")...)
	feed(a, conn, 7, 0, encoder)

	if len(c.sections) != 1 {
		t.Fatalf("got %d sections after unblocking, want 1", len(c.sections))
	}
	sec := c.sections[0]
	if sec.StreamID != 4 || sec.Path != "/sample/path" {
		t.Fatalf("section = %+v", sec)
	}
}

func TestDataFramesSkippedAndChunkSplits(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0x3000

	stream := frame(frameTypeHeaders, responseSection(t))
	stream = append(stream, frame(0x0, make([]byte, 300))...)
	stream = append(stream, frame(frameTypeHeaders, requestSection(t))...)

	for i, b := range stream {
		feed(a, conn, 0, uint32(i), []byte{b})
	}

	if len(c.sections) != 2 {
		t.Fatalf("got %d sections, want 2", len(c.sections))
	}
	if c.sections[0].Status != 200 || c.sections[1].Path != "/x" {
		t.Fatalf("sections = %+v", c.sections)
	}
}

func TestOffsetGapBreaksStream(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0x4000

	data := frame(frameTypeHeaders, responseSection(t))
	feed(a, conn, 0, 0, data[:2])
	feed(a, conn, 0, 100, data[2:])
	if len(c.sections) != 0 {
		t.Fatalf("sections decoded across a gap: %+v", c.sections)
	}
	feed(a, conn, 0, uint32(100+len(data)-2), data)
	if len(c.sections) != 0 {
		t.Fatalf("broken stream resumed: %+v", c.sections)
	}
}

func TestTruncatedSegmentBreaksStreamAfterPrefix(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0x5000

	full := frame(frameTypeHeaders, responseSection(t))
	a.Feed(Chunk{
		TGID:      42,
		Conn:      conn,
		StreamID:  0,
		StreamLen: uint32(len(full) + 500),
		CopiedLen: uint32(len(full)),
		Offset:    0,
		Data:      full,
	})
	if len(c.sections) != 1 || c.sections[0].Status != 200 {
		t.Fatalf("sections = %+v", c.sections)
	}
	feed(a, conn, 0, uint32(len(full)), frame(frameTypeHeaders, requestSection(t)))
	if len(c.sections) != 1 {
		t.Fatalf("truncated stream kept decoding: %+v", c.sections)
	}
}

func TestUnknownUniStreamIgnored(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	feed(a, 0x6000, 11, 0, append([]byte{0x03}, 0xff, 0xff))
	feed(a, 0x6000, 15, 0, append(appendVarint(nil, 0x21), 0xff))
	if len(c.sections) != 0 {
		t.Fatalf("sections from ignorable streams: %+v", c.sections)
	}
}

func TestParseChunkRawLayout(t *testing.T) {
	raw := make([]byte, chunkHeaderSize+3)
	binary.LittleEndian.PutUint64(raw[0:8], 42)
	binary.LittleEndian.PutUint64(raw[8:16], 0xabc)
	binary.LittleEndian.PutUint64(raw[16:24], 8)
	binary.LittleEndian.PutUint32(raw[24:28], 7)
	binary.LittleEndian.PutUint32(raw[28:32], 3)
	binary.LittleEndian.PutUint32(raw[32:36], 4)
	copy(raw[chunkHeaderSize:], "abc")

	c, ok := ParseChunk(raw)
	if !ok {
		t.Fatal("ParseChunk failed")
	}
	if c.TGID != 42 || c.Conn != 0xabc || c.StreamID != 8 ||
		c.StreamLen != 7 || c.CopiedLen != 3 || c.Offset != 4 || string(c.Data) != "abc" {
		t.Fatalf("chunk = %+v", c)
	}
	if _, ok := ParseChunk(raw[:10]); ok {
		t.Fatal("short chunk parsed")
	}
}

func TestParseChunkRejectsCopiedLenOverrun(t *testing.T) {
	raw := make([]byte, chunkHeaderSize+4)
	binary.LittleEndian.PutUint32(raw[28:32], 64)
	if _, ok := ParseChunk(raw); ok {
		t.Fatal("chunk with copied_len beyond sample parsed")
	}
}

func TestSectionStash(t *testing.T) {
	s := NewSectionStash(time.Hour, 4)
	key := SectionKey{TGID: 1, Conn: 2, Stream: 3}

	s.Put(key, Section{Fields: nil})
	if _, ok := s.Take(key); ok {
		t.Fatal("empty section stashed")
	}

	s.Put(key, Section{Status: 200})
	sec, ok := s.Take(key)
	if !ok || sec.Status != 200 {
		t.Fatalf("take = %+v %v", sec, ok)
	}
	if _, ok := s.Take(key); ok {
		t.Fatal("second take succeeded")
	}
}

func TestEnrichTxn(t *testing.T) {
	client := &h3decode.Txn{IsClient: true}
	if !EnrichTxn(client, Section{Status: 404}) || client.Status != 404 {
		t.Fatalf("client txn = %+v", client)
	}

	server := &h3decode.Txn{Flags: h3decode.FlagResponseOnly, Status: 200}
	if !EnrichTxn(server, Section{Method: "POST", Path: "/api", Traceparent: "00-aa-bb-01"}) {
		t.Fatal("server txn not enriched")
	}
	if server.Method != "POST" || server.Path != "/api" || server.Traceparent != "00-aa-bb-01" {
		t.Fatalf("server txn = %+v", server)
	}
	if server.Flags&h3decode.FlagResponseOnly != 0 {
		t.Fatal("response-only flag not cleared after request recovery")
	}

	// Nothing to fill: no change, flag stays.
	full := &h3decode.Txn{Flags: h3decode.FlagResponseOnly, Status: 200, Method: "GET", Path: "/"}
	if EnrichTxn(full, Section{Status: 500, Method: "PUT"}) {
		t.Fatal("complete txn reported as enriched")
	}
	if full.Status != 200 || full.Method != "GET" {
		t.Fatalf("complete txn overwritten: %+v", full)
	}
}
