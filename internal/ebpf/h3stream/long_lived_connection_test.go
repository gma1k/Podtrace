package h3stream

import (
	"encoding/binary"
	"testing"
)

func TestLongLivedConnectionDecodesPastStreamCap(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0xb00

	feed(a, conn, 3, 0, append([]byte{0x00}, frame(0x4, nil)...))
	feed(a, conn, 7, 0, append([]byte{streamTypeQPACKEncoder}, mustHex(t,
		"3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468")...))
	feed(a, conn, 11, 0, []byte{0x03})

	const requests = 100
	for i := 0; i < requests; i++ {
		feed(a, conn, uint64(i*4), 0, frame(frameTypeHeaders, mustHex(t, "0381 10 11")))
	}
	if len(c.sections) != requests {
		t.Fatalf("sections decoded = %d, want %d", len(c.sections), requests)
	}
	last := c.sections[requests-1]
	if last.StreamID != (requests-1)*4 || last.Path != "/sample/path" {
		t.Fatalf("last section = %+v", last)
	}
	cs := a.conns[ConnKey{TGID: 42, Conn: conn}]
	if st := cs.streams[7]; st == nil || st.kind != kindEncoder {
		t.Fatal("encoder stream was retired")
	}
}

func TestLongLivedConnectionRetiresOldestOpenRequest(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0xb01

	partial := frame(frameTypeHeaders, requestSection(t))
	for i := 0; i < maxStreamsPerConn; i++ {
		feed(a, conn, uint64(i*4), 0, partial[:2])
	}
	feed(a, conn, uint64(maxStreamsPerConn*4), 0, frame(frameTypeHeaders, requestSection(t)))
	if len(c.sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(c.sections))
	}
	cs := a.conns[ConnKey{TGID: 42, Conn: conn}]
	if _, ok := cs.streams[0]; ok {
		t.Fatal("oldest open request stream was not retired")
	}
}

func TestLateChunkForRetiredStreamIsIgnored(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0xb02

	for i := 0; i <= maxStreamsPerConn; i++ {
		feed(a, conn, uint64(i*4), 0, frame(frameTypeHeaders, requestSection(t)))
	}
	trailer := frame(frameTypeHeaders, requestSection(t))
	feed(a, conn, 0, uint32(len(trailer)), trailer)
	if len(c.sections) != maxStreamsPerConn+1 {
		t.Fatalf("late chunk of a retired stream was decoded: %d sections", len(c.sections))
	}
}

func TestConnClosedChunkDropsConnectionState(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0xc00

	feed(a, conn, 7, 0, append([]byte{streamTypeQPACKEncoder}, mustHex(t,
		"3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d")...))
	feed(a, conn, 0, 0, frame(frameTypeHeaders, responseSection(t)))

	a.Feed(Chunk{TGID: 42, Conn: conn, Flags: ChunkFlagConnClosed})
	if _, ok := a.conns[ConnKey{TGID: 42, Conn: conn}]; ok {
		t.Fatal("closed connection kept its state")
	}

	feed(a, conn, 7, 0, append([]byte{streamTypeQPACKEncoder}, mustHex(t, "3fbd01")...))
	feed(a, conn, 0, 0, frame(frameTypeHeaders, mustHex(t, "0200 80")))
	if len(c.sections) != 1 {
		t.Fatalf("reused connection resolved a reference against the previous connection's table: %+v", c.sections)
	}
}

func TestParseChunkReadsFlags(t *testing.T) {
	raw := make([]byte, chunkHeaderSize)
	binary.LittleEndian.PutUint32(raw[36:40], ChunkFlagConnClosed)
	c, ok := ParseChunk(raw)
	if !ok || c.Flags != ChunkFlagConnClosed {
		t.Fatalf("ParseChunk = %+v, %v", c, ok)
	}
}

func TestStreamDroppedWhenNoSlotCanBeFreed(t *testing.T) {
	var c collector
	a := NewAssembler(c.collect)
	const conn = 0xd00
	for i := 0; i < maxStreamsPerConn; i++ {
		feed(a, conn, uint64(i*4+2), 0, []byte{0x40})
	}
	feed(a, conn, uint64(maxStreamsPerConn*4), 0, frame(frameTypeHeaders, requestSection(t)))
	cs := a.conns[ConnKey{TGID: 42, Conn: conn}]
	if len(cs.streams) != maxStreamsPerConn || len(c.sections) != 0 {
		t.Fatalf("streams=%d sections=%d, want the new stream refused", len(cs.streams), len(c.sections))
	}
}
