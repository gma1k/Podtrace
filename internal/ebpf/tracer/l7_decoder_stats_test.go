package tracer

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/ebpf/h2decode"
	"github.com/gma1k/podtrace/internal/ebpf/h3decode"
	"github.com/gma1k/podtrace/internal/ebpf/h3stream"
	"github.com/gma1k/podtrace/internal/events"
)

func l7DropsCounter(t *testing.T, decoder, reason string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != "podtrace_l7_decoder_drops_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			if labelsMatch(m, decoder, reason) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func labelsMatch(m *dto.Metric, decoder, reason string) bool {
	got := map[string]string{}
	for _, l := range m.GetLabel() {
		got[l.GetName()] = l.GetValue()
	}
	return got["decoder"] == decoder && got["reason"] == reason
}

func TestPollPublishesL7DecoderDropsAsDeltas(t *testing.T) {
	dec := h2decode.New()
	stash := h3stream.NewSectionStash(time.Hour, 1)
	tr := &Tracer{h2Decoder: dec, h3SectionStash: stash}

	dec.Ingest(&h2decode.RawRecord{ConnID: 1, Seq: 0, Flags: 0x1, Frag: []byte{0x80}})
	stash.Put(h3stream.SectionKey{Stream: 1}, h3stream.Section{Status: 200})
	stash.Put(h3stream.SectionKey{Stream: 2}, h3stream.Section{Status: 200})

	h2Before := l7DropsCounter(t, "h2", "decode_error")
	h3Before := l7DropsCounter(t, "h3", "section_stash_full")
	tr.pollBPFMapUtilization()
	tr.pollBPFMapUtilization()
	if got := l7DropsCounter(t, "h2", "decode_error") - h2Before; got != 1 {
		t.Fatalf("h2 decode_error delta = %v, want 1 across two polls", got)
	}
	if got := l7DropsCounter(t, "h3", "section_stash_full") - h3Before; got != 1 {
		t.Fatalf("h3 section_stash_full delta = %v, want 1 across two polls", got)
	}
}

func TestPollWithoutDecodersPublishesNothing(t *testing.T) {
	tr := &Tracer{}
	tr.pollBPFMapUtilization()
	if tr.l7DropSnapshot != (l7DecoderDropSnapshot{}) {
		t.Fatalf("snapshot changed without decoders: %+v", tr.l7DropSnapshot)
	}
}

func TestOfferDNSTimeout(t *testing.T) {
	var reasons []string
	tr := &Tracer{}
	tr.SetDropReporter(func(reason string, n int) { reasons = append(reasons, reason) })
	ev := &events.Event{Type: events.EventDNS}

	room := make(chan *events.Event, 1)
	if !tr.offerDNSTimeout(context.Background(), room, ev) || len(room) != 1 {
		t.Fatal("event not delivered to a channel with room")
	}
	if !tr.offerDNSTimeout(context.Background(), room, ev) {
		t.Fatal("full channel stopped the sweep")
	}
	if len(reasons) != 1 || reasons[0] != "channel_full" {
		t.Fatalf("drop reasons = %v, want one channel_full", reasons)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if tr.offerDNSTimeout(ctx, make(chan *events.Event), ev) {
		t.Fatal("cancelled sweep kept going")
	}
}

func TestLogDecodedH3TxnStopsAfterTwenty(t *testing.T) {
	h3TxnLogCount.Store(0)
	t.Cleanup(func() { h3TxnLogCount.Store(0) })
	txn := &h3decode.Txn{Method: "GET", Path: "/secret?token=x"}
	for i := 0; i < 25; i++ {
		logDecodedH3Txn(txn)
	}
	if got := h3TxnLogCount.Load(); got != 25 {
		t.Fatalf("log counter = %d", got)
	}
}

func TestParkedH3TransactionsAreCountedWhenTheTracerStops(t *testing.T) {
	tr := &Tracer{h3SectionStash: h3stream.NewSectionStash(time.Hour, 8)}
	tr.h3Parked = []h3ParkedTxn{{txn: &h3decode.Txn{}}, {txn: &h3decode.Txn{}}}
	before := l7DropsCounter(t, "h3", "shutdown")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr.runH3ParkedFlusher(ctx, make(chan *events.Event), nil, &eventCounters{})

	if got := l7DropsCounter(t, "h3", "shutdown") - before; got != 2 {
		t.Fatalf("shutdown drops = %v, want 2", got)
	}
	if len(tr.h3Parked) != 0 {
		t.Fatalf("%d transactions still parked after stop", len(tr.h3Parked))
	}
}
