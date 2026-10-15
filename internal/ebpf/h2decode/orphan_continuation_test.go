package h2decode

import "testing"

func TestOrphanContinuationIsDiscardedThroughEndHeaders(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	orphanStart := rec(0x71, DirEgress, 0, 1, enc.encode(reqFields("GET", "/orphan")...))
	orphanStart.Flags = flagContinuation
	orphanEnd := rec(0x71, DirEgress, 1, 1, enc.encode(reqFields("GET", "/orphan-end")...))
	orphanEnd.Flags = flagContinuation | flagEndHeaders

	if evs := d.Ingest(orphanStart); len(evs) != 0 {
		t.Fatalf("orphan continuation decoded: %d events", len(evs))
	}
	if evs := d.Ingest(orphanEnd); len(evs) != 0 {
		t.Fatalf("orphan continuation end decoded: %d events", len(evs))
	}
	evs := d.Ingest(rec(0x71, DirEgress, 2, 3, enc.encode(reqFields("GET", "/next")...)))
	if len(evs) != 1 || evs[0].Target != "GET /next" {
		t.Fatalf("next block after the orphan = %+v", evs)
	}
}

func TestEvictLeavesOtherConnectionsStreams(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	d.Ingest(rec(0x81, DirEgress, 0, 1, enc.encode(reqFields("GET", "/a")...)))
	enc2 := newBlockEncoder()
	d.Ingest(rec(0x82, DirEgress, 0, 1, enc2.encode(reqFields("GET", "/b")...)))
	d.Evict(0x81)
	if s := d.Stats(); s.Streams != 1 {
		t.Fatalf("streams after evicting one connection = %d, want 1", s.Streams)
	}
	resp := newBlockEncoder()
	evs := d.Ingest(rec(0x82, DirIngress, 0, 1, resp.encode(respFields("200")...)))
	if len(evs) != 1 || evs[0].Target != "GET /b" {
		t.Fatalf("surviving connection lost its request: %+v", evs)
	}
}
