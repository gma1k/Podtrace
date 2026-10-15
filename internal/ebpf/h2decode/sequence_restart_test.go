package h2decode

import (
	"fmt"
	"testing"
	"time"
)

func ingestRequests(d *Decoder, enc *blockEncoder, conn uint64, firstSeq uint32, count int, prefix string) int {
	events := 0
	for i := 0; i < count; i++ {
		seq := firstSeq + uint32(i)
		block := enc.encode(reqFields("GET", fmt.Sprintf("/%s/%d", prefix, i))...)
		events += len(d.Ingest(rec(conn, DirEgress, seq, 2*seq+1, block)))
	}
	return events
}

func TestSequenceRestartStartsANewConnection(t *testing.T) {
	d := New()
	if got := ingestRequests(d, newBlockEncoder(), 0x51, 0, 1000, "old"); got != 1000 {
		t.Fatalf("first connection events = %d, want 1000", got)
	}

	enc := newBlockEncoder()
	var last string
	got := 0
	for i := 0; i < 900; i++ {
		block := enc.encode(reqFields("GET", fmt.Sprintf("/new/%d", i))...)
		for _, ev := range d.Ingest(rec(0x51, DirEgress, uint32(i), uint32(2*i+1), block)) {
			got++
			last = ev.Target
		}
	}
	if got != 900 {
		t.Fatalf("events after sequence restart = %d, want 900", got)
	}
	if last != "GET /new/899" {
		t.Fatalf("last target = %q, want the new connection's own path", last)
	}
	if s := d.Stats(); s.SequenceRestarts != 1 {
		t.Fatalf("sequence restarts = %d, want 1", s.SequenceRestarts)
	}
}

func TestRecordFromSkippedGapIsLateNotRestart(t *testing.T) {
	d := New()
	d.maxPendingPerDir = 2
	enc := newBlockEncoder()
	d.Ingest(rec(0x52, DirEgress, 0, 1, enc.encode(reqFields("GET", "/a")...)))
	for seq := uint32(2); seq <= 4; seq++ {
		d.Ingest(rec(0x52, DirEgress, seq, 2*seq+1, enc.encode(reqFields("GET", "/b")...)))
	}
	if evs := d.Ingest(rec(0x52, DirEgress, 1, 3, enc.encode(reqFields("GET", "/late")...))); len(evs) != 0 {
		t.Fatalf("late record decoded: %d events", len(evs))
	}
	s := d.Stats()
	if s.LateRecords != 1 || s.SequenceRestarts != 0 {
		t.Fatalf("late=%d restarts=%d, want 1 and 0", s.LateRecords, s.SequenceRestarts)
	}
}

func TestDroppedRecordsDoNotKeepStateAlive(t *testing.T) {
	now := time.Unix(1000, 0)
	d := New()
	d.nowFn = func() time.Time { return now }
	enc := newBlockEncoder()
	ingestRequests(d, enc, 0x53, 0, 3, "a")

	for i := 0; i < 10; i++ {
		now = now.Add(10 * time.Second)
		d.Ingest(rec(0x53, DirEgress, 1, 3, enc.encode(reqFields("GET", "/dup")...)))
	}
	d.Sweep()
	if s := d.Stats(); s.Conns != 0 {
		t.Fatalf("idle direction kept alive by dropped records: %+v", s)
	}
}
