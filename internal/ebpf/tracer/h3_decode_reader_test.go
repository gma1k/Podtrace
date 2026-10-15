package tracer

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/gma1k/podtrace/internal/ebpf/h3decode"
	"github.com/gma1k/podtrace/internal/events"
)

type fakeRecordReader struct {
	records [][]byte
	reads   int
}

func (f *fakeRecordReader) Read() (ringbuf.Record, error) {
	f.reads++
	if len(f.records) == 0 {
		return ringbuf.Record{}, ringbuf.ErrClosed
	}
	raw := f.records[0]
	f.records = f.records[1:]
	if raw == nil {
		return ringbuf.Record{}, errors.New("transient read error")
	}
	return ringbuf.Record{RawSample: raw}, nil
}

func (f *fakeRecordReader) Close() error { return nil }

func TestH3DecodeReaderDispatchesRecordsUntilClosed(t *testing.T) {
	h3TxnLogCount.Store(0)
	t.Cleanup(func() { h3TxnLogCount.Store(0) })
	tr := newDispatchTestTracer()
	tr.h3Decoder = h3decode.NewDecoder(nil)
	reader := &fakeRecordReader{records: [][]byte{nil, make([]byte, 4096), make([]byte, 8)}}
	tr.h3Reader = reader

	var collected, filtered, parsed atomic.Int64
	var filteringDisabled atomic.Bool
	ch := make(chan *events.Event, 16)
	tr.runH3DecodeReader(context.Background(), ch, nil, &eventCounters{
		collected: &collected, filtered: &filtered, parsed: &parsed, filteringDisabled: &filteringDisabled,
	})

	if reader.reads != 4 {
		t.Fatalf("reads = %d, want the loop to continue past errors until closed", reader.reads)
	}
	if h3TxnLogCount.Load() != 1 {
		t.Fatalf("decoded transactions = %d, want the one valid record", h3TxnLogCount.Load())
	}
}

func TestAsRecordReaderKeepsAMissingReaderNil(t *testing.T) {
	if asRecordReader(nil) != nil {
		t.Fatal("a nil ring buffer reader became a non-nil interface")
	}
	if asRecordReader(&ringbuf.Reader{}) == nil {
		t.Fatal("a real reader was dropped")
	}
}
