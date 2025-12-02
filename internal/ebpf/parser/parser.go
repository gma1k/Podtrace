package parser

import (
	"bytes"
	"encoding/binary"

	"github.com/podtrace/podtrace/internal/events"
)

func ParseEvent(data []byte) *events.Event {
	const expectedEventSize = 312
	if len(data) < expectedEventSize {
		return nil
	}

	var e struct {
		Timestamp uint64
		PID       uint32
		Type      uint32
		LatencyNS uint64
		Error     int32
		Bytes     uint64
		TCPState  uint32
		StackKey  uint64
		Target    [128]byte
		Details   [128]byte
	}

	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
		return nil
	}

	return &events.Event{
		Timestamp: e.Timestamp,
		PID:       e.PID,
		Type:      events.EventType(e.Type),
		LatencyNS: e.LatencyNS,
		Error:     e.Error,
		Bytes:     e.Bytes,
		TCPState:  e.TCPState,
		StackKey:  e.StackKey,
		Target:    string(bytes.TrimRight(e.Target[:], "\x00")),
		Details:   string(bytes.TrimRight(e.Details[:], "\x00")),
	}
}
