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
	type rawEventV1 = rawEvent
	type rawEventV2 struct {
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
		CgroupID  uint64
		Target    [128]byte
		Details   [128]byte
	}
	type rawEventV3 struct {
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
		CgroupID  uint64
		Comm      [16]byte
		Target    [128]byte
		Details   [128]byte
	}

	expectedV3 := int(unsafe.Sizeof(rawEventV3{}))
	expectedV2 := int(unsafe.Sizeof(rawEventV2{}))
	expectedV1 := int(unsafe.Sizeof(rawEventV1{}))
	if len(data) < expectedV1 {
		return nil
	}

	event := eventPool.Get().(*events.Event)
	event.ProcessName = ""
	event.Stack = nil
	event.CgroupID = 0

	if len(data) >= expectedV3 {
		var e rawEventV3
		if err := binaryRead(bytes.NewReader(data[:expectedV3]), binary.LittleEndian, &e); err != nil {
			return nil
		}

		event.Timestamp = e.Timestamp
		event.PID = e.PID
		event.Type = events.EventType(e.Type)
		event.LatencyNS = e.LatencyNS
		event.Error = e.Error
		event.Bytes = e.Bytes
		event.TCPState = e.TCPState
		event.StackKey = e.StackKey
		event.CgroupID = e.CgroupID
		event.ProcessName = string(bytes.TrimRight(e.Comm[:], "\x00"))
		event.Target = string(bytes.TrimRight(e.Target[:], "\x00"))
		event.Details = string(bytes.TrimRight(e.Details[:], "\x00"))

		return event
	}

	if len(data) >= expectedV2 {
		var e rawEventV2
		if err := binaryRead(bytes.NewReader(data[:expectedV2]), binary.LittleEndian, &e); err != nil {
			return nil
		}

		event.Timestamp = e.Timestamp
		event.PID = e.PID
		event.Type = events.EventType(e.Type)
		event.LatencyNS = e.LatencyNS
		event.Error = e.Error
		event.Bytes = e.Bytes
		event.TCPState = e.TCPState
		event.StackKey = e.StackKey
		event.CgroupID = e.CgroupID
		event.Target = string(bytes.TrimRight(e.Target[:], "\x00"))
		event.Details = string(bytes.TrimRight(e.Details[:], "\x00"))

		return event
	}

	var e rawEventV1
	if err := binaryRead(bytes.NewReader(data[:expectedV1]), binary.LittleEndian, &e); err != nil {
		return nil
	}

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
