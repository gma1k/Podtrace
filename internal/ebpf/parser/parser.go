package parser

import (
	"bytes"
	"encoding/binary"
	"sync"
	"unsafe"

	"github.com/podtrace/podtrace/internal/events"
)

var (
	binaryRead = binary.Read
	eventPool  = sync.Pool{
		New: func() interface{} {
			return &events.Event{}
		},
	}
)

type rawEvent struct {
	Timestamp uint64
	PID       uint32
	Type      uint32
	LatencyNS uint64
	Error     int32
	_         uint32
	Bytes     uint64
	TCPState  uint32
	_         uint32
	StackKey  uint64
	Target    [128]byte
	Details   [128]byte
}

func ParseEvent(data []byte) *events.Event {
	const expectedEventSize = int(unsafe.Sizeof(rawEvent{}))
	if len(data) < expectedEventSize {
		return nil
	}

	var e rawEvent
	if err := binaryRead(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
		return nil
	}

	event := eventPool.Get().(*events.Event)
	event.Timestamp = e.Timestamp
	event.PID = e.PID
	event.Type = events.EventType(e.Type)
	event.LatencyNS = e.LatencyNS
	event.Error = e.Error
	event.Bytes = e.Bytes
	event.TCPState = e.TCPState
	event.StackKey = e.StackKey
	event.Target = string(bytes.TrimRight(e.Target[:], "\x00"))
	event.Details = string(bytes.TrimRight(e.Details[:], "\x00"))
	event.ProcessName = ""
	event.Stack = nil

	return event
}

func PutEvent(event *events.Event) {
	if event == nil {
		return
	}
	event.Stack = nil
	event.ProcessName = ""
	event.Target = ""
	event.Details = ""
	eventPool.Put(event)
}
