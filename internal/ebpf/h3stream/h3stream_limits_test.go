package h3stream

import (
	"testing"
	"time"
)

func TestParseChunkCopiedLenOverrun(t *testing.T) {
	raw := make([]byte, chunkHeaderSize+2)
	raw[28] = 5
	if _, ok := ParseChunk(raw); ok {
		t.Fatal("chunk with CopiedLen past the buffer was accepted")
	}
}

func TestFeedEmptyDataIsNoOp(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	feed(a, 0x1, 0, 0, nil)
	if len(a.conns) != 0 || len(c.sections) != 0 {
		t.Fatalf("empty chunk created state: conns=%d sections=%d", len(a.conns), len(c.sections))
	}
}

func TestMaxStreamsPerConnRetiresFinishedStreams(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0x100
	for i := 0; i <= maxStreamsPerConn; i++ {
		feed(a, conn, uint64(i*4), 0, frame(frameTypeHeaders, requestSection(t)))
	}
	cs := a.conns[ConnKey{TGID: 42, Conn: conn}]
	if cs == nil {
		t.Fatal("connection state missing")
		return
	}
	if len(cs.streams) != maxStreamsPerConn {
		t.Fatalf("streams = %d, want cap %d", len(cs.streams), maxStreamsPerConn)
	}
	if len(c.sections) != maxStreamsPerConn+1 {
		t.Fatalf("sections = %d, want %d", len(c.sections), maxStreamsPerConn+1)
	}
	if _, ok := cs.streams[0]; ok {
		t.Fatal("lowest finished stream was not the one retired")
	}
}

func TestMaxBufferedPerStreamBreaks(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0x200

	header := []byte{0x01, 0x5f, 0x40}
	chunk1 := append(append([]byte{}, header...), make([]byte, 5000)...)
	feed(a, conn, 0, 0, chunk1)
	feed(a, conn, 0, uint32(len(chunk1)), make([]byte, 4000))

	cs := a.conns[ConnKey{TGID: 42, Conn: conn}]
	st := cs.streams[0]
	if !st.broken {
		t.Fatal("over-buffered stream was not broken")
	}
	if len(c.sections) != 0 {
		t.Fatalf("over-buffered stream emitted sections: %+v", c.sections)
	}
}

func TestMaxConnectionsEvictsOldest(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	for i := 0; i <= maxConnections; i++ {
		feed(a, uint64(i), 0, 0, frame(frameTypeHeaders, requestSection(t)))
	}
	if len(a.conns) != maxConnections {
		t.Fatalf("conns = %d, want cap %d", len(a.conns), maxConnections)
	}

	if _, ok := a.conns[ConnKey{TGID: 42, Conn: 0}]; ok {
		t.Fatal("oldest connection was not evicted")
	}
}

func TestDecodeSectionMalformedBreaks(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0x300

	feed(a, conn, 0, 0, frame(frameTypeHeaders, mustHex(t, "0000 ff2c")))
	cs := a.conns[ConnKey{TGID: 42, Conn: conn}]
	if !cs.streams[0].broken {
		t.Fatal("malformed HEADERS did not break the stream")
	}
	if len(c.sections) != 0 {
		t.Fatalf("malformed HEADERS emitted a section: %+v", c.sections)
	}
}

func TestBlockedSectionsBounded(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0x400
	blocked := mustHex(t, "0381 10 11")
	for i := 0; i <= maxBlockedSections; i++ {
		feed(a, conn, uint64(i*4), 0, frame(frameTypeHeaders, blocked))
	}
	cs := a.conns[ConnKey{TGID: 42, Conn: conn}]
	if len(cs.blocked) != maxBlockedSections {
		t.Fatalf("blocked = %d, want cap %d", len(cs.blocked), maxBlockedSections)
	}
	if len(c.sections) != 0 {
		t.Fatalf("blocked sections emitted early: %+v", c.sections)
	}
}

func TestEmitWithNilCallback(t *testing.T) {
	a := NewAssembler(nil)

	feed(a, 0x500, 0, 0, frame(frameTypeHeaders, requestSection(t)))
}

func TestUniStreamIncompleteVarintBuffers(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)

	feed(a, 0x600, 2, 0, []byte{0x80})
	if len(c.sections) != 0 {
		t.Fatalf("incomplete uni-stream type emitted sections: %+v", c.sections)
	}
	cs := a.conns[ConnKey{TGID: 42, Conn: 0x600}]
	if cs.streams[2].kind != kindUnknown {
		t.Fatalf("stream classified before its type varint completed: %v", cs.streams[2].kind)
	}
}

func TestControlStreamIgnored(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)

	control := append([]byte{0x00}, frame(0x4, []byte{0x01, 0x40})...)
	feed(a, 0x700, 3, 0, control)

	cs := a.conns[ConnKey{TGID: 42, Conn: 0x700}]
	if cs.streams[3].kind != kindIgnore {
		t.Fatalf("control stream kind = %v, want ignored", cs.streams[3].kind)
	}
	if len(c.sections) != 0 {
		t.Fatalf("control stream emitted sections: %+v", c.sections)
	}
}

func TestEncoderStreamTypeOnlyIsNoOp(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)

	feed(a, 0x800, 2, 0, []byte{streamTypeQPACKEncoder})
	cs := a.conns[ConnKey{TGID: 42, Conn: 0x800}]
	if cs.streams[2].kind != kindEncoder {
		t.Fatalf("stream kind = %v, want encoder", cs.streams[2].kind)
	}
	if cs.streams[2].broken {
		t.Fatal("empty encoder stream should not break")
	}
}

func TestEncoderStreamErrorBreaks(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)

	data := []byte{streamTypeQPACKEncoder, 0x41, 0x61, 0x01, 0x31}
	feed(a, 0x801, 2, 0, data)
	cs := a.conns[ConnKey{TGID: 42, Conn: 0x801}]
	if !cs.streams[2].broken {
		t.Fatal("encoder-stream decode error did not break the stream")
	}
}

func TestSkipSpanningIntoNextFrame(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)

	stream := frame(0x0, make([]byte, 10))
	stream = append(stream, frame(frameTypeHeaders, responseSection(t))...)
	feed(a, 0x900, 0, 0, stream)
	if len(c.sections) != 1 || c.sections[0].Status != 200 {
		t.Fatalf("sections = %+v, want one 200", c.sections)
	}
}

func TestEmitCapturesTraceparent(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)

	name := "traceparent"
	value := "00-aabbccddeeff00112233445566778899-0011223344556677-01"
	section := []byte{0x00, 0x00}
	section = append(section, 0x27, byte(len(name)-7))
	section = append(section, name...)
	section = append(section, byte(len(value)))
	section = append(section, value...)
	feed(a, 0xa00, 0, 0, frame(frameTypeHeaders, section))
	if len(c.sections) != 1 {
		t.Fatalf("got %d sections, want 1", len(c.sections))
	}
	if c.sections[0].Traceparent != value {
		t.Fatalf("traceparent = %q, want %q", c.sections[0].Traceparent, value)
	}
}

func TestParseStatus(t *testing.T) {
	cases := map[string]uint16{
		"200":  200,
		"404":  404,
		"":     0,
		"20":   0,
		"2000": 0,
		"2a0":  0,
	}
	for in, want := range cases {
		if got := parseStatus(in); got != want {
			t.Errorf("parseStatus(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestStashCapacityDropsWhenFull(t *testing.T) {
	s := NewSectionStash(time.Hour, 2)
	s.Put(SectionKey{Stream: 1}, Section{Status: 200})
	s.Put(SectionKey{Stream: 2}, Section{Status: 201})
	s.Put(SectionKey{Stream: 3}, Section{Status: 202})
	if _, ok := s.Take(SectionKey{Stream: 3}); ok {
		t.Fatal("section stored past capacity with no expired entries to evict")
	}
	if s.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", s.Dropped())
	}
	if _, ok := s.Take(SectionKey{Stream: 1}); !ok {
		t.Fatal("earlier section evicted despite the newcomer being dropped")
	}
}

func TestStashExpiryReclaimsAndTakeExpires(t *testing.T) {

	s := NewSectionStash(-time.Hour, 2)
	s.Put(SectionKey{Stream: 1}, Section{Status: 200})
	s.Put(SectionKey{Stream: 2}, Section{Status: 201})

	s.Put(SectionKey{Stream: 3}, Section{Status: 202})

	if _, ok := s.Take(SectionKey{Stream: 3}); ok {
		t.Fatal("expired section returned by Take")
	}
}
