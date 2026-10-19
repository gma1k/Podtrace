package tracker

import "testing"

func TestAZeroTraceCapTracksNothing(t *testing.T) {
	withTraceCap(t, 0)
	tt := NewTraceTracker()

	trackTrace(tt, "ignored")

	if got := tt.GetTraceCount(); got != 0 {
		t.Fatalf("tracked %d traces with a cap of 0, want none", got)
	}
	if got := tt.EvictedTraceCount(); got != 0 {
		t.Fatalf("evicted %d traces with a cap of 0, want none: nothing was ever admitted", got)
	}
}
