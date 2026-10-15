package h2decode

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/gma1k/podtrace/internal/events"
)

type blockEncoder struct {
	buf bytes.Buffer
	enc *hpack.Encoder
}

func newBlockEncoder() *blockEncoder {
	be := &blockEncoder{}
	be.enc = hpack.NewEncoder(&be.buf)
	return be
}

func (be *blockEncoder) encode(fields ...hpack.HeaderField) []byte {
	be.buf.Reset()
	for _, f := range fields {
		if err := be.enc.WriteField(f); err != nil {
			panic(err)
		}
	}
	out := make([]byte, be.buf.Len())
	copy(out, be.buf.Bytes())
	return out
}

func hf(name, value string) hpack.HeaderField {
	return hpack.HeaderField{Name: name, Value: value}
}

func reqFields(method, path string, extra ...hpack.HeaderField) []hpack.HeaderField {
	base := []hpack.HeaderField{
		hf(":method", method),
		hf(":scheme", "https"),
		hf(":authority", "demo.svc"),
		hf(":path", path),
	}
	return append(base, extra...)
}

func rec(conn uint64, dir uint8, seq, stream uint32, block []byte) *RawRecord {
	return &RawRecord{
		ConnID:    conn,
		Timestamp: 1000 + uint64(seq),
		PID:       42,
		Seq:       seq,
		StreamID:  stream,
		FragLen:   uint16(len(block)),
		Direction: dir,
		Transport: 2,
		Flags:     flagEndHeaders,
		Frag:      block,
	}
}

func singleEvent(t *testing.T, evs []*events.Event) *events.Event {
	t.Helper()
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 event, got %d", len(evs))
	}
	return evs[0]
}

func TestSimpleRequest(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	block := enc.encode(reqFields("GET", "/api/orders")...)

	ev := singleEvent(t, d.Ingest(rec(1, DirEgress, 0, 1, block)))
	if ev.Type != events.EventHTTPReq {
		t.Fatalf("type = %v, want EventHTTPReq", ev.Type)
	}
	if ev.Target != "GET /api/orders" {
		t.Fatalf("target = %q, want %q", ev.Target, "GET /api/orders")
	}
	if ev.TCPState != events.HTTPTransportH2C {
		t.Fatalf("transport = %d, want h2c", ev.TCPState)
	}
}

func TestDynamicTableRepeatedRoute(t *testing.T) {
	d := New()
	enc := newBlockEncoder()

	const conn = 7
	const path = "/api/orders"
	const n = 5
	var firstLen, lastLen int
	for i := 0; i < n; i++ {
		block := enc.encode(reqFields("GET", path)...)
		if i == 0 {
			firstLen = len(block)
		}
		lastLen = len(block)
		ev := singleEvent(t, d.Ingest(rec(conn, DirEgress, uint32(i), uint32(i+1), block)))
		if ev.Target != "GET "+path {
			t.Fatalf("request %d: target = %q, want %q", i, ev.Target, "GET "+path)
		}
	}
	if lastLen >= firstLen {
		t.Fatalf("dynamic indexing not engaged: first=%d last=%d bytes", firstLen, lastLen)
	}
}

func TestContinuationReassembly(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	block := enc.encode(reqFields("POST", "/upload",
		hf("user-agent", "podtrace-test/1.0 with a fairly long value to span"))...)
	if len(block) < 4 {
		t.Fatalf("block too small to split: %d", len(block))
	}
	mid := len(block) / 2

	r0 := rec(2, DirEgress, 0, 1, block[:mid])
	r0.Flags = 0
	r1 := rec(2, DirEgress, 1, 1, block[mid:])
	r1.Flags = flagEndHeaders | flagContinuation

	if evs := d.Ingest(r0); len(evs) != 0 {
		t.Fatalf("partial block should emit nothing, got %d", len(evs))
	}
	ev := singleEvent(t, d.Ingest(r1))
	if ev.Target != "POST /upload" {
		t.Fatalf("target = %q, want %q", ev.Target, "POST /upload")
	}
}

func TestOutOfOrderReorder(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	b0 := enc.encode(reqFields("GET", "/first")...)
	b1 := enc.encode(reqFields("GET", "/second")...)

	r0 := rec(3, DirEgress, 0, 1, b0)
	r1 := rec(3, DirEgress, 1, 3, b1)

	if evs := d.Ingest(r1); len(evs) != 0 {
		t.Fatalf("buffered out-of-order record emitted %d events, want 0", len(evs))
	}
	evs := d.Ingest(r0)
	if len(evs) != 2 {
		t.Fatalf("got %d events after gap filled, want 2", len(evs))
	}
	if evs[0].Target != "GET /first" || evs[1].Target != "GET /second" {
		t.Fatalf("wrong order/targets: %q, %q", evs[0].Target, evs[1].Target)
	}
}

func TestGapSkipByBufferBound(t *testing.T) {
	d := New()
	d.maxPendingPerDir = 4
	enc := newBlockEncoder()

	for i := 1; i <= 6; i++ {
		block := enc.encode(reqFields("GET", "/x")...)
		d.Ingest(rec(9, DirEgress, uint32(i), uint32(i), block))
	}
	if d.Stats().GapsSkipped == 0 {
		t.Fatalf("expected a gap skip")
	}
	enc2 := newBlockEncoder()
	block := enc2.encode(reqFields("GET", "/recovered")...)
	st := d.dirs[connKey{conn: 9, dir: DirEgress}]
	ev := singleEvent(t, d.Ingest(rec(9, DirEgress, st.nextSeq, 99, block)))
	if ev.Target != "GET /recovered" {
		t.Fatalf("post-skip target = %q", ev.Target)
	}
}

func TestGapSkipByTimeout(t *testing.T) {
	now := time.Unix(0, 0)
	d := New()
	d.nowFn = func() time.Time { return now }
	enc := newBlockEncoder()

	b1 := enc.encode(reqFields("GET", "/late")...)
	if evs := d.Ingest(rec(11, DirEgress, 1, 1, b1)); len(evs) != 0 {
		t.Fatalf("buffered record emitted events early")
	}
	now = now.Add(defaultGapTimeout + time.Second)
	evs := d.Sweep()
	if len(evs) != 1 || evs[0].Target != "GET /late" {
		t.Fatalf("timeout gap-skip did not release buffered record: %+v", evs)
	}
}

func TestResponseCorrelation(t *testing.T) {
	d := New()
	reqEnc := newBlockEncoder()
	respEnc := newBlockEncoder()

	const conn, stream = 21, 1
	reqBlock := reqEnc.encode(reqFields("DELETE", "/api/orders/5")...)
	reqEv := singleEvent(t, d.Ingest(&RawRecord{
		ConnID: conn, Direction: DirEgress, Seq: 0, StreamID: stream,
		Timestamp: 1000, Transport: 2, Flags: flagEndHeaders,
		FragLen: uint16(len(reqBlock)), Frag: reqBlock,
	}))
	if reqEv.Type != events.EventHTTPReq {
		t.Fatalf("first event not a request")
	}

	respBlock := respEnc.encode(hf(":status", "204"))
	respEv := singleEvent(t, d.Ingest(&RawRecord{
		ConnID: conn, Direction: DirIngress, Seq: 0, StreamID: stream,
		Timestamp: 1500, Transport: 2, Flags: flagEndHeaders,
		FragLen: uint16(len(respBlock)), Frag: respBlock,
	}))
	if respEv.Type != events.EventHTTPResp {
		t.Fatalf("second event not a response")
	}
	if respEv.Target != "DELETE /api/orders/5" {
		t.Fatalf("response target = %q, want correlated request endpoint", respEv.Target)
	}
	if respEv.LatencyNS != 500 {
		t.Fatalf("latency = %d, want 500 (TTFB)", respEv.LatencyNS)
	}
}

func TestServerError5xxSetsError(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	block := enc.encode(hf(":status", "503"))
	ev := singleEvent(t, d.Ingest(rec(31, DirIngress, 0, 1, block)))
	if ev.Type != events.EventHTTPResp || ev.Error != 503 {
		t.Fatalf("expected EventHTTPResp with Error=503, got type=%v error=%d", ev.Type, ev.Error)
	}
}

func TestTraceparentCaptured(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	tp := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	block := enc.encode(reqFields("GET", "/traced", hf("traceparent", tp))...)
	ev := singleEvent(t, d.Ingest(rec(41, DirEgress, 0, 1, block)))
	if ev.Details != "traceparent: "+tp {
		t.Fatalf("details = %q, want traceparent line", ev.Details)
	}
}

func TestServerSideInboundRequest(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	block := enc.encode(reqFields("PUT", "/inbound")...)
	ev := singleEvent(t, d.Ingest(rec(51, DirIngress, 0, 1, block)))
	if ev.Type != events.EventHTTPReq || ev.Target != "PUT /inbound" {
		t.Fatalf("inbound request not captured: type=%v target=%q", ev.Type, ev.Target)
	}
}

func TestEvict(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	block := enc.encode(reqFields("GET", "/x")...)
	d.Ingest(rec(61, DirEgress, 0, 1, block))
	if d.Stats().Conns == 0 {
		t.Fatalf("expected connection state")
	}
	d.Evict(61)
	if s := d.Stats(); s.Conns != 0 || s.Streams != 0 {
		t.Fatalf("Evict left state: %+v", s)
	}
}

func TestParseRecordRoundTrip(t *testing.T) {
	frag := []byte{0x82, 0x86, 0x84, 0x41, 0x8c}
	buf := make([]byte, recordHeaderSize+len(frag))
	binary.LittleEndian.PutUint64(buf[0:8], 0xdeadbeef)
	binary.LittleEndian.PutUint64(buf[8:16], 123456)
	binary.LittleEndian.PutUint64(buf[16:24], 9999)
	binary.LittleEndian.PutUint32(buf[24:28], 7)
	binary.LittleEndian.PutUint32(buf[28:32], 3)
	binary.LittleEndian.PutUint32(buf[32:36], 11)
	binary.LittleEndian.PutUint16(buf[36:38], uint16(len(frag)))
	buf[38] = DirIngress
	buf[39] = 3 // h2-tls
	buf[40] = flagEndHeaders
	copy(buf[recordHeaderSize:], frag)

	r, ok := ParseRecord(buf)
	if !ok {
		t.Fatal("ParseRecord failed")
	}
	if r.ConnID != 0xdeadbeef || r.PID != 7 || r.Seq != 3 || r.StreamID != 11 {
		t.Fatalf("header fields wrong: %+v", r)
	}
	if r.Direction != DirIngress || r.Transport != 3 || !r.endHeaders() {
		t.Fatalf("flag/dir/transport wrong: %+v", r)
	}
	if !bytes.Equal(r.Frag, frag) {
		t.Fatalf("frag = %x, want %x", r.Frag, frag)
	}
}

func TestParseRecordRejectsTruncated(t *testing.T) {
	if _, ok := ParseRecord(make([]byte, 10)); ok {
		t.Fatal("short buffer accepted")
	}
	buf := make([]byte, recordHeaderSize+2)
	binary.LittleEndian.PutUint16(buf[36:38], 99)
	if _, ok := ParseRecord(buf); ok {
		t.Fatal("overrunning frag length accepted")
	}
}

func TestParseAndIngestEndToEnd(t *testing.T) {
	enc := newBlockEncoder()
	block := enc.encode(reqFields("GET", "/healthz")...)

	buf := make([]byte, recordHeaderSize+len(block))
	binary.LittleEndian.PutUint64(buf[0:8], 0xc0ffee) // conn_id
	binary.LittleEndian.PutUint64(buf[8:16], 5000)    // timestamp
	binary.LittleEndian.PutUint64(buf[16:24], 314)    // cgroup_id
	binary.LittleEndian.PutUint32(buf[24:28], 1234)   // pid
	binary.LittleEndian.PutUint32(buf[28:32], 0)      // seq
	binary.LittleEndian.PutUint32(buf[32:36], 1)      // stream_id
	binary.LittleEndian.PutUint16(buf[36:38], uint16(len(block)))
	buf[38] = DirIngress // inbound — server-side request
	buf[39] = 3          // h2-tls
	buf[40] = flagEndHeaders
	copy(buf[recordHeaderSize:], block)

	rec, ok := ParseRecord(buf)
	if !ok {
		t.Fatal("ParseRecord failed on kernel-format buffer")
	}
	d := New()
	ev := singleEvent(t, d.Ingest(rec))
	if ev.Type != events.EventHTTPReq || ev.Target != "GET /healthz" {
		t.Fatalf("end-to-end decode wrong: type=%v target=%q", ev.Type, ev.Target)
	}
	if ev.TCPState != events.HTTPTransportH2TLS {
		t.Fatalf("transport = %d, want h2-tls", ev.TCPState)
	}
	if ev.CgroupID != 314 || ev.PID != 1234 || ev.Timestamp != 5000 {
		t.Fatalf("metadata not carried through: %+v", ev)
	}
}

func TestCloseRecordParsedAndEvicts(t *testing.T) {
	buf := make([]byte, recordHeaderSize)
	binary.LittleEndian.PutUint64(buf[0:8], 0xabc)
	buf[40] = flagClose
	r, ok := ParseRecord(buf)
	if !ok || !r.IsClose() || r.ConnID != 0xabc {
		t.Fatalf("close record not parsed: ok=%v close=%v conn=%#x", ok, r.IsClose(), r.ConnID)
	}

	d := New()
	enc := newBlockEncoder()
	d.Ingest(rec(0xabc, DirEgress, 0, 1, enc.encode(reqFields("GET", "/x")...)))
	if d.Stats().Conns == 0 {
		t.Fatal("expected seeded connection state")
	}
	d.Evict(r.ConnID)
	if d.Stats().Conns != 0 {
		t.Fatalf("close did not evict decoder state: %+v", d.Stats())
	}
}

func TestStaleDuplicateDropped(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	b0 := enc.encode(reqFields("GET", "/a")...)
	b1 := enc.encode(reqFields("GET", "/b")...)
	d.Ingest(rec(71, DirEgress, 0, 1, b0))
	d.Ingest(rec(71, DirEgress, 1, 3, b1))
	if evs := d.Ingest(rec(71, DirEgress, 1, 3, b1)); len(evs) != 0 {
		t.Fatalf("stale duplicate re-decoded: %d events", len(evs))
	}
}

func TestDecodeErrorResetsDecoder(t *testing.T) {
	d := New()
	garbage := []byte{0xff, 0xff, 0xff, 0x0f} // invalid HPACK
	if evs := d.Ingest(rec(81, DirEgress, 0, 1, garbage)); len(evs) != 0 {
		t.Fatalf("garbage block emitted %d events, want 0", len(evs))
	}
	if d.Stats().DecodeErrors == 0 {
		t.Fatal("expected a decode error")
	}
	enc := newBlockEncoder()
	ev := singleEvent(t, d.Ingest(rec(81, DirEgress, 1, 1, enc.encode(reqFields("GET", "/ok")...))))
	if ev.Target != "GET /ok" {
		t.Fatalf("post-error target = %q", ev.Target)
	}
}

func TestNonPseudoHeaderBlock(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	block := enc.encode(hf("content-type", "text/plain"), hf("x-trailer", "1"))
	if evs := d.Ingest(rec(82, DirIngress, 0, 1, block)); len(evs) != 0 {
		t.Fatalf("non-pseudo block emitted %d events, want 0", len(evs))
	}
	if d.Stats().DecodeErrors != 0 {
		t.Fatalf("non-pseudo block should decode without error: %+v", d.Stats())
	}
}

func TestConnEvictionLRU(t *testing.T) {
	now := time.Unix(100, 0)
	d := New()
	d.nowFn = func() time.Time { return now }
	d.maxConns = 2
	enc := newBlockEncoder()
	for i := 0; i < 4; i++ {
		now = now.Add(time.Second)
		d.Ingest(rec(uint64(100+i), DirEgress, 0, 1, enc.encode(reqFields("GET", "/x")...)))
	}
	s := d.Stats()
	if s.Conns > d.maxConns {
		t.Fatalf("conns = %d, want <= %d", s.Conns, d.maxConns)
	}
	if s.Evictions == 0 {
		t.Fatal("expected LRU evictions")
	}
}

func TestStreamEvictionLRU(t *testing.T) {
	now := time.Unix(200, 0)
	d := New()
	d.nowFn = func() time.Time { return now }
	d.maxStreams = 2
	enc := newBlockEncoder()
	for i := 0; i < 5; i++ {
		now = now.Add(time.Second)
		d.Ingest(rec(300, DirEgress, uint32(i), uint32(i+1), enc.encode(reqFields("GET", "/x")...)))
	}
	if s := d.Stats(); s.Streams > d.maxStreams {
		t.Fatalf("streams = %d, want <= %d", s.Streams, d.maxStreams)
	}
}

func TestSweepEvictsIdle(t *testing.T) {
	now := time.Unix(300, 0)
	d := New()
	d.nowFn = func() time.Time { return now }
	enc := newBlockEncoder()
	d.Ingest(rec(401, DirEgress, 0, 1, enc.encode(reqFields("GET", "/x")...)))
	if d.Stats().Conns == 0 {
		t.Fatal("expected connection state")
	}
	now = now.Add(defaultTTL + time.Second)
	d.Sweep()
	if s := d.Stats(); s.Conns != 0 {
		t.Fatalf("idle connection not swept: %+v", s)
	}
}

func TestInterimResponseKeepsCorrelation(t *testing.T) {
	d := New()
	be := newBlockEncoder()
	d.Ingest(rec(7, DirEgress, 0, 1, be.encode(reqFields("GET", "/early-hints")...)))

	ibe := newBlockEncoder()
	if evs := d.Ingest(rec(7, DirIngress, 0, 1, ibe.encode(hf(":status", "103")))); len(evs) != 0 {
		t.Fatalf("1xx interim response must not emit events, got %d", len(evs))
	}
	ev := singleEvent(t, d.Ingest(rec(7, DirIngress, 1, 1, ibe.encode(hf(":status", "200")))))
	if ev.Type != events.EventHTTPResp || ev.Details != "200" {
		t.Fatalf("unexpected final response: %+v", ev)
	}
	if ev.Target != "GET /early-hints" {
		t.Fatalf("final response lost its request correlation: %q", ev.Target)
	}
}

func TestGrpcTrailerBlock(t *testing.T) {
	d := New()
	be := newBlockEncoder()
	d.Ingest(rec(8, DirEgress, 0, 1, be.encode(reqFields("POST", "/pkg.Svc/Do")...)))

	ibe := newBlockEncoder()
	resp := singleEvent(t, d.Ingest(rec(8, DirIngress, 0, 1, ibe.encode(hf(":status", "200")))))
	if resp.Target != "POST /pkg.Svc/Do" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	trailer := singleEvent(t, d.Ingest(rec(8, DirIngress, 1, 1, ibe.encode(hf("grpc-status", "13")))))
	if trailer.Type != events.EventHTTPResp || trailer.Details != "grpc-status: 13" {
		t.Fatalf("unexpected trailer event: %+v", trailer)
	}
	if trailer.Error != 13 {
		t.Fatalf("non-zero grpc-status should set Error, got %d", trailer.Error)
	}
}

func TestGrpcTrailersOnlyResponse(t *testing.T) {
	d := New()
	be := newBlockEncoder()
	d.Ingest(rec(9, DirEgress, 0, 1, be.encode(reqFields("POST", "/pkg.Svc/Do")...)))

	ibe := newBlockEncoder()
	ev := singleEvent(t, d.Ingest(rec(9, DirIngress, 0, 1,
		ibe.encode(hf(":status", "200"), hf("grpc-status", "5")))))
	if ev.Error != 5 {
		t.Fatalf("Trailers-Only grpc-status should set Error, got %d", ev.Error)
	}
	if want := "200\ngrpc-status: 5"; ev.Details != want {
		t.Fatalf("Details = %q, want %q", ev.Details, want)
	}
}

func TestGrpcStatusZeroIsNotError(t *testing.T) {
	d := New()
	ibe := newBlockEncoder()
	ev := singleEvent(t, d.Ingest(rec(10, DirIngress, 0, 1, ibe.encode(hf("grpc-status", "0")))))
	if ev.Error != 0 {
		t.Fatalf("grpc-status 0 (OK) must not set Error, got %d", ev.Error)
	}
}

func TestCaptureHeadersOnRequestAndResponse(t *testing.T) {
	d := New()
	d.SetCaptureHeaders([]string{"Content-Type", "x-request-id"})
	be := newBlockEncoder()
	req := singleEvent(t, d.Ingest(rec(11, DirEgress, 0, 1,
		be.encode(reqFields("POST", "/x", hf("content-type", "application/json"),
			hf("x-request-id", "r-1"), hf("authorization", "secret"))...))))
	if want := "content-type: application/json\nx-request-id: r-1"; req.Details != want {
		t.Fatalf("request Details = %q, want %q", req.Details, want)
	}
	ibe := newBlockEncoder()
	resp := singleEvent(t, d.Ingest(rec(11, DirIngress, 0, 1,
		ibe.encode(hf(":status", "201"), hf("content-type", "text/plain")))))
	if want := "201\ncontent-type: text/plain"; resp.Details != want {
		t.Fatalf("response Details = %q, want %q", resp.Details, want)
	}
	if resp.Error != 0 {
		t.Fatalf("unexpected Error: %d", resp.Error)
	}
}

func TestLateJoinNewRouteRecoversPath(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	_ = enc.encode(reqFields("POST", "/pkg.Svc/Old")...)

	const conn = 90
	first := singleEvent(t, d.Ingest(rec(conn, DirEgress, 0, 1,
		enc.encode(reqFields("POST", "/pkg.Svc/New")...))))
	if first.Target != "POST /pkg.Svc/New" {
		t.Fatalf("post-attach literal route: target = %q", first.Target)
	}
	repeat := singleEvent(t, d.Ingest(rec(conn, DirEgress, 1, 3,
		enc.encode(reqFields("POST", "/pkg.Svc/New")...))))
	if repeat.Target != "POST /pkg.Svc/New" {
		t.Fatalf("indexed repeat of post-attach route: target = %q", repeat.Target)
	}
	if d.Stats().DecodeErrors != 0 {
		t.Fatalf("late join must not count decode errors: %+v", d.Stats())
	}
	if d.Stats().PartialBlocks == 0 {
		t.Fatal("blocks referencing pre-attach state should count as partial")
	}
}

func TestLateJoinAnonymousRequestPairsWithResponse(t *testing.T) {
	d := New()
	reqEnc := newBlockEncoder()
	_ = reqEnc.encode(reqFields("POST", "/pkg.Svc/Do")...) // pre-attach literal
	steadyState := reqEnc.encode(reqFields("POST", "/pkg.Svc/Do")...)

	const conn = 91
	respEnc := newBlockEncoder()
	singleEvent(t, d.Ingest(rec(conn, DirIngress, 0, 99, respEnc.encode(hf(":status", "200")))))

	reqEv := singleEvent(t, d.Ingest(rec(conn, DirEgress, 0, 1, steadyState)))
	if reqEv.Type != events.EventHTTPReq {
		t.Fatalf("expected request event, got %v", reqEv.Type)
	}
	if reqEv.Target != "POST "+unknownPathPlaceholder {
		t.Fatalf("anonymous request target = %q", reqEv.Target)
	}

	respEv := singleEvent(t, d.Ingest(rec(conn, DirIngress, 1, 1, respEnc.encode(hf(":status", "200")))))
	if respEv.Target != "POST "+unknownPathPlaceholder {
		t.Fatalf("response lost anonymous-request correlation: %q", respEv.Target)
	}
	if respEv.LatencyNS == 0 {
		t.Fatal("anonymous request must still yield latency")
	}
	if d.Stats().AnonymousRequests != 1 {
		t.Fatalf("AnonymousRequests = %d, want 1", d.Stats().AnonymousRequests)
	}
}

func TestLateJoinAnonymousRequestNeedsRoleEvidence(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	_ = enc.encode(reqFields("POST", "/pkg.Svc/Do")...)
	steadyState := enc.encode(reqFields("POST", "/pkg.Svc/Do")...)

	if evs := d.Ingest(rec(92, DirEgress, 0, 1, steadyState)); len(evs) != 0 {
		t.Fatalf("unclassifiable partial block emitted %d events, want 0", len(evs))
	}
	if d.Stats().AnonymousRequests != 0 {
		t.Fatalf("AnonymousRequests = %d, want 0", d.Stats().AnonymousRequests)
	}
}

func TestLateJoinAnonymousRequestFromOwnRole(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	_ = enc.encode(reqFields("POST", "/pkg.Svc/Old")...)

	const conn = 93
	singleEvent(t, d.Ingest(rec(conn, DirEgress, 0, 1,
		enc.encode(reqFields("POST", "/pkg.Svc/New")...))))

	ev := singleEvent(t, d.Ingest(rec(conn, DirEgress, 1, 3,
		enc.encode(reqFields("POST", "/pkg.Svc/Old")...))))
	if ev.Type != events.EventHTTPReq || ev.Target != "POST "+unknownPathPlaceholder {
		t.Fatalf("anonymous request on request-role direction: type=%v target=%q", ev.Type, ev.Target)
	}
}

func TestIndexedResponseTrailerNotMisreported(t *testing.T) {
	d := New()
	respEnc := newBlockEncoder()
	_ = respEnc.encode(hf("grpc-status", "0"))

	const conn = 94
	singleEvent(t, d.Ingest(rec(conn, DirIngress, 0, 1, respEnc.encode(hf(":status", "200")))))
	if evs := d.Ingest(rec(conn, DirIngress, 1, 1, respEnc.encode(hf("grpc-status", "0")))); len(evs) != 0 {
		t.Fatalf("indexed trailer on response direction emitted %d events, want 0", len(evs))
	}
	if d.Stats().AnonymousRequests != 0 {
		t.Fatalf("trailer misreported as request: %+v", d.Stats())
	}
}

func TestCaptureHeadersDisabledByDefault(t *testing.T) {
	d := New()
	be := newBlockEncoder()
	req := singleEvent(t, d.Ingest(rec(12, DirEgress, 0, 1,
		be.encode(reqFields("GET", "/x", hf("content-type", "application/json"))...))))
	if req.Details != "" {
		t.Fatalf("expected no captured headers by default, got %q", req.Details)
	}
}
