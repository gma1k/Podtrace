package parser

import (
	"bytes"
	"encoding/binary"
	"sync"
	"unsafe"

	"github.com/gma1k/podtrace/internal/events"
)

var (
	binaryRead = binary.Read
	eventPool  = sync.Pool{
		New: func() interface{} {
			return &events.Event{}
		},
	}
)

const maxStringLen = 128

// decodeTarget turns a raw fixed-size target buffer into a string.
func decodeTarget(eventType uint32, raw []byte) string {
	if events.EventType(eventType) == events.EventRename && len(raw) >= maxStringLen {
		half := maxStringLen / 2
		oldName := string(bytes.TrimRight(raw[:half-1], "\x00"))
		newName := string(bytes.TrimRight(raw[half:maxStringLen], "\x00"))
		if newName == "" {
			return oldName
		}
		return oldName + ">" + newName
	}
	return string(bytes.TrimRight(raw, "\x00"))
}

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
	type rawEventV4 struct {
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
		NetNsID   uint32
		_         uint32 // explicit padding
	}

	type rawEventV5 struct {
		Timestamp    uint64
		PID          uint32
		Type         uint32
		LatencyNS    uint64
		Error        int32
		_            uint32
		Bytes        uint64
		TCPState     uint32
		_            uint32
		StackKey     uint64
		CgroupID     uint64
		Comm         [16]byte
		Target       [128]byte
		Details      [128]byte
		NetNsID      uint32
		_            uint32
		DNSServerIP  uint32
		DNSTransport uint8
		_            [3]uint8
	}

	type rawEventV6 struct {
		Timestamp    uint64
		PID          uint32
		Type         uint32
		LatencyNS    uint64
		Error        int32
		_            uint32
		Bytes        uint64
		TCPState     uint32
		_            uint32
		StackKey     uint64
		CgroupID     uint64
		Comm         [16]byte
		Target       [128]byte
		Details      [128]byte
		NetNsID      uint32
		_            uint32
		DNSServerIP  uint32
		DNSTransport uint8
		_            [3]uint8
		DNSServerIP6 [16]byte
	}

	type rawEventV7 struct {
		Timestamp    uint64
		PID          uint32
		Type         uint32
		LatencyNS    uint64
		Error        int32
		_            uint32
		Bytes        uint64
		TCPState     uint32
		_            uint32
		StackKey     uint64
		CgroupID     uint64
		Comm         [16]byte
		Target       [128]byte
		Details      [128]byte
		NetNsID      uint32
		_            uint32
		DNSServerIP  uint32
		DNSTransport uint8
		_            [3]uint8
		DNSServerIP6 [16]byte
		PeerSaddr    uint32
		PeerDaddr    uint32
		PeerSport    uint16
		PeerDport    uint16
		PeerFamily   uint8
		_            [3]uint8
		PeerSaddr6   [16]byte
		PeerDaddr6   [16]byte
	}

	type rawEventV8 struct {
		Timestamp     uint64
		PID           uint32
		Type          uint32
		LatencyNS     uint64
		Error         int32
		_             uint32
		Bytes         uint64
		TCPState      uint32
		_             uint32
		StackKey      uint64
		CgroupID      uint64
		Comm          [16]byte
		Target        [128]byte
		Details       [128]byte
		NetNsID       uint32
		_             uint32
		DNSServerIP   uint32
		DNSTransport  uint8
		_             [3]uint8
		DNSServerIP6  [16]byte
		PeerSaddr     uint32
		PeerDaddr     uint32
		PeerSport     uint16
		PeerDport     uint16
		PeerFamily    uint8
		_             [3]uint8
		PeerSaddr6    [16]byte
		PeerDaddr6    [16]byte
		CorrelationID uint64
	}

	type rawEventV9 struct {
		rawEventV8
		HTTPMethod  uint8
		AggRecorded uint8
		_           [6]uint8
	}

	expectedV9 := int(unsafe.Sizeof(rawEventV9{}))
	expectedV8 := int(unsafe.Sizeof(rawEventV8{}))
	expectedV7 := int(unsafe.Sizeof(rawEventV7{}))
	expectedV6 := int(unsafe.Sizeof(rawEventV6{}))
	expectedV5 := int(unsafe.Sizeof(rawEventV5{}))
	expectedV4 := int(unsafe.Sizeof(rawEventV4{}))
	expectedV3 := int(unsafe.Sizeof(rawEventV3{}))
	expectedV2 := int(unsafe.Sizeof(rawEventV2{}))
	expectedV1 := int(unsafe.Sizeof(rawEventV1{}))
	if len(data) < expectedV1 {
		return nil
	}

	event := eventPool.Get().(*events.Event)
	*event = events.Event{}

	if len(data) >= expectedV9 {
		var e rawEventV9
		if err := binaryRead(bytes.NewReader(data[:expectedV9]), binary.LittleEndian, &e); err != nil {
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
		event.Target = decodeTarget(e.Type, e.Target[:])
		event.Details = string(bytes.TrimRight(e.Details[:], "\x00"))
		event.NetNsID = e.NetNsID
		event.DNSServerIP = e.DNSServerIP
		event.DNSTransport = e.DNSTransport
		event.DNSServerIP6 = e.DNSServerIP6
		event.PeerSrcIP = events.PeerIP(e.PeerFamily, e.PeerSaddr, e.PeerSaddr6)
		event.PeerDstIP = events.PeerIP(e.PeerFamily, e.PeerDaddr, e.PeerDaddr6)
		event.PeerSrcPort = e.PeerSport
		event.PeerDstPort = e.PeerDport
		event.CorrelationID = e.CorrelationID
		event.HTTPMethod = events.HTTPMethodFromCode(e.HTTPMethod)
		event.KernelAggregated = e.AggRecorded != 0
		return event
	}

	if len(data) >= expectedV8 {
		var e rawEventV8
		if err := binaryRead(bytes.NewReader(data[:expectedV8]), binary.LittleEndian, &e); err != nil {
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
		event.Target = decodeTarget(e.Type, e.Target[:])
		event.Details = string(bytes.TrimRight(e.Details[:], "\x00"))
		event.NetNsID = e.NetNsID
		event.DNSServerIP = e.DNSServerIP
		event.DNSTransport = e.DNSTransport
		event.DNSServerIP6 = e.DNSServerIP6
		event.PeerSrcIP = events.PeerIP(e.PeerFamily, e.PeerSaddr, e.PeerSaddr6)
		event.PeerDstIP = events.PeerIP(e.PeerFamily, e.PeerDaddr, e.PeerDaddr6)
		event.PeerSrcPort = e.PeerSport
		event.PeerDstPort = e.PeerDport
		event.CorrelationID = e.CorrelationID
		return event
	}

	if len(data) >= expectedV7 {
		var e rawEventV7
		if err := binaryRead(bytes.NewReader(data[:expectedV7]), binary.LittleEndian, &e); err != nil {
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
		event.Target = decodeTarget(e.Type, e.Target[:])
		event.Details = string(bytes.TrimRight(e.Details[:], "\x00"))
		event.NetNsID = e.NetNsID
		event.DNSServerIP = e.DNSServerIP
		event.DNSTransport = e.DNSTransport
		event.DNSServerIP6 = e.DNSServerIP6
		event.PeerSrcIP = events.PeerIP(e.PeerFamily, e.PeerSaddr, e.PeerSaddr6)
		event.PeerDstIP = events.PeerIP(e.PeerFamily, e.PeerDaddr, e.PeerDaddr6)
		event.PeerSrcPort = e.PeerSport
		event.PeerDstPort = e.PeerDport
		return event
	}

	if len(data) >= expectedV6 {
		var e rawEventV6
		if err := binaryRead(bytes.NewReader(data[:expectedV6]), binary.LittleEndian, &e); err != nil {
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
		event.Target = decodeTarget(e.Type, e.Target[:])
		event.Details = string(bytes.TrimRight(e.Details[:], "\x00"))
		event.NetNsID = e.NetNsID
		event.DNSServerIP = e.DNSServerIP
		event.DNSTransport = e.DNSTransport
		event.DNSServerIP6 = e.DNSServerIP6
		return event
	}

	if len(data) >= expectedV5 {
		var e rawEventV5
		if err := binaryRead(bytes.NewReader(data[:expectedV5]), binary.LittleEndian, &e); err != nil {
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
		event.Target = decodeTarget(e.Type, e.Target[:])
		event.Details = string(bytes.TrimRight(e.Details[:], "\x00"))
		event.NetNsID = e.NetNsID
		event.DNSServerIP = e.DNSServerIP
		event.DNSTransport = e.DNSTransport
		return event
	}

	if len(data) >= expectedV4 {
		var e rawEventV4
		if err := binaryRead(bytes.NewReader(data[:expectedV4]), binary.LittleEndian, &e); err != nil {
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
		event.Target = decodeTarget(e.Type, e.Target[:])
		event.Details = string(bytes.TrimRight(e.Details[:], "\x00"))
		event.NetNsID = e.NetNsID

		return event
	}

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
		event.Target = decodeTarget(e.Type, e.Target[:])
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
		event.Target = decodeTarget(e.Type, e.Target[:])
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
	event.Target = decodeTarget(e.Type, e.Target[:])
	event.Details = string(bytes.TrimRight(e.Details[:], "\x00"))

	return event
}

func PutEvent(event *events.Event) {
	if event == nil {
		return
	}
	*event = events.Event{}
	eventPool.Put(event)
}
