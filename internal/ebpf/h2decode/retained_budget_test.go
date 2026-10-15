package h2decode

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func incrementalLiterals(count, valueLen int) []byte {
	var block bytes.Buffer
	for i := 0; i < count; i++ {
		name := []byte{'x', byte('a' + i%26), byte('a' + (i/26)%26)}
		block.WriteByte(0x40)
		block.WriteByte(byte(len(name)))
		block.Write(name)
		block.Write(hpackLength(valueLen))
		block.WriteString(strings.Repeat("v", valueLen))
	}
	return block.Bytes()
}

func hpackLength(n int) []byte {
	if n < 127 {
		return []byte{byte(n)}
	}
	out := []byte{127}
	n -= 127
	for n >= 128 {
		out = append(out, byte(n%128)|0x80)
		n /= 128
	}
	return append(out, byte(n))
}

func TestTrackedWindowFollowsTheTableSize(t *testing.T) {
	d := New()
	d.Ingest(rec(0x61, DirEgress, 0, 1, incrementalLiterals(40, 1000)))
	st := d.dirs[connKey{conn: 0x61, dir: DirEgress}]
	if st.dec.trackedBytes > hpackDefaultTableSize {
		t.Fatalf("tracked %d bytes, want at most the default table size %d", st.dec.trackedBytes, hpackDefaultTableSize)
	}

	update := []byte{0x3f, 0xe1, 0xff, 0x03}
	d.Ingest(rec(0x61, DirEgress, 1, 3, append(update, incrementalLiterals(50, 1000)...)))
	if st.dec.trackedBytes > maxTrackedBytes {
		t.Fatalf("tracked %d bytes after a huge size update, want at most %d", st.dec.trackedBytes, maxTrackedBytes)
	}
	if st.dec.trackedBytes <= hpackDefaultTableSize {
		t.Fatalf("tracked %d bytes, want the size update to raise the window", st.dec.trackedBytes)
	}
}

func TestSizeUpdateToZeroEmptiesTheWindow(t *testing.T) {
	var dec lateJoinDecoder
	dec.insert(tableEntry{field: hpack.HeaderField{Name: "a", Value: "b"}})
	if _, _, err := dec.decodeBlock([]byte{0x20}); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(dec.inserts) != 0 || dec.trackedBytes != 0 {
		t.Fatalf("size update to 0 left %d entries, %d bytes", len(dec.inserts), dec.trackedBytes)
	}
}

func TestRetainedBytesStayWithinTheGlobalBudget(t *testing.T) {
	d := New()
	d.maxRetainedBytes = 16 << 10
	for conn := uint64(1); conn <= 20; conn++ {
		d.Ingest(rec(conn, DirEgress, 0, 1, incrementalLiterals(4, 1000)))
	}
	s := d.Stats()
	if s.RetainedBytes > d.maxRetainedBytes {
		t.Fatalf("retained %d bytes, budget %d", s.RetainedBytes, d.maxRetainedBytes)
	}
	if s.BudgetSheds == 0 {
		t.Fatal("budget exceeded without shedding")
	}

	for conn := uint64(1); conn <= 20; conn++ {
		d.Evict(conn)
	}
	if s := d.Stats(); s.RetainedBytes != 0 {
		t.Fatalf("retained bytes drifted to %d after evicting every connection", s.RetainedBytes)
	}
}

func TestPendingRecordsCountTowardTheBudget(t *testing.T) {
	d := New()
	frag := make([]byte, 1000)
	for seq := uint32(1); seq <= 10; seq++ {
		r := rec(0x62, DirEgress, seq, 1, frag)
		r.Flags = 0
		d.Ingest(r)
	}
	if s := d.Stats(); s.RetainedBytes != 10*1000 {
		t.Fatalf("retained %d bytes with 10 buffered 1000-byte records", s.RetainedBytes)
	}
	d.Evict(0x62)
	if s := d.Stats(); s.RetainedBytes != 0 {
		t.Fatalf("retained bytes drifted to %d", s.RetainedBytes)
	}
}

func TestDuplicatePendingRecordIsChargedOnce(t *testing.T) {
	d := New()
	frag := make([]byte, 500)
	for i := 0; i < 2; i++ {
		r := rec(0x63, DirEgress, 5, 1, frag)
		r.Flags = 0
		d.Ingest(r)
	}
	if s := d.Stats(); s.RetainedBytes != 500 {
		t.Fatalf("retained %d bytes for one buffered record seen twice", s.RetainedBytes)
	}
}

func TestBudgetShedDropsAPartialBlockAndBufferedRecords(t *testing.T) {
	d := New()
	d.maxRetainedBytes = 1500
	open := rec(0x64, DirEgress, 0, 1, make([]byte, 1000))
	open.Flags = 0
	d.Ingest(open)
	ahead := rec(0x64, DirEgress, 3, 1, make([]byte, 1000))
	ahead.Flags = 0
	d.Ingest(ahead)

	s := d.Stats()
	if s.BudgetSheds != 1 || s.RetainedBytes != 0 {
		t.Fatalf("sheds=%d retained=%d, want one shed releasing everything", s.BudgetSheds, s.RetainedBytes)
	}
	st := d.dirs[connKey{conn: 0x64, dir: DirEgress}]
	if !st.discarding || st.nextSeq != 4 || !st.inSkippedRange(2) {
		t.Fatalf("after shed: discarding=%v nextSeq=%d", st.discarding, st.nextSeq)
	}
	enc := newBlockEncoder()
	end := rec(0x64, DirEgress, 4, 1, enc.encode(reqFields("GET", "/tail")...))
	if evs := d.Ingest(end); len(evs) != 0 {
		t.Fatalf("tail of a shed block decoded: %+v", evs)
	}
	evs := d.Ingest(rec(0x64, DirEgress, 5, 3, enc.encode(reqFields("GET", "/next")...)))
	if len(evs) != 1 {
		t.Fatalf("decoding did not resume after a shed: %+v", evs)
	}
}

func TestSizeUpdateAboveTheCapIsClamped(t *testing.T) {
	var dec lateJoinDecoder
	dec.setTableSize(maxTrackedBytes * 4)
	if dec.tableLimit() != maxTrackedBytes {
		t.Fatalf("table limit = %d, want %d", dec.tableLimit(), maxTrackedBytes)
	}
}
