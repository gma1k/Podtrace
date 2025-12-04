package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestParseEvent_ValidEvent(t *testing.T) {
	var raw rawEvent
	raw.Timestamp = 1234567890
	raw.PID = 1234
	raw.Type = uint32(events.EventDNS)
	raw.LatencyNS = 5000000 // 5ms
	raw.Error = 0
	raw.Bytes = 1024
	raw.TCPState = 0
	raw.StackKey = 0
	copy(raw.Target[:], "example.com")
	copy(raw.Details[:], "details")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("Failed to write binary data: %v", err)
	}

	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil for valid event")
	}

	if event.Timestamp != raw.Timestamp {
		t.Errorf("Expected timestamp %d, got %d", raw.Timestamp, event.Timestamp)
	}
	if event.PID != raw.PID {
		t.Errorf("Expected PID %d, got %d", raw.PID, event.PID)
	}
	if event.Type != events.EventType(raw.Type) {
		t.Errorf("Expected type %d, got %d", raw.Type, event.Type)
	}
	if event.LatencyNS != raw.LatencyNS {
		t.Errorf("Expected latency %d, got %d", raw.LatencyNS, event.LatencyNS)
	}
	if event.Error != raw.Error {
		t.Errorf("Expected error %d, got %d", raw.Error, event.Error)
	}
	if event.Bytes != raw.Bytes {
		t.Errorf("Expected bytes %d, got %d", raw.Bytes, event.Bytes)
	}
	if event.Target != "example.com" {
		t.Errorf("Expected target 'example.com', got '%s'", event.Target)
	}
}

func TestParseEvent_TooSmall(t *testing.T) {
	data := make([]byte, 10) // Too small
	event := ParseEvent(data)
	if event != nil {
		t.Error("ParseEvent should return nil for data that's too small")
	}
}

func TestParseEvent_EmptyData(t *testing.T) {
	event := ParseEvent([]byte{})
	if event != nil {
		t.Error("ParseEvent should return nil for empty data")
	}
}

func TestParseEvent_NilData(t *testing.T) {
	event := ParseEvent(nil)
	if event != nil {
		t.Error("ParseEvent should return nil for nil data")
	}
}

func TestParseEvent_AllEventTypes(t *testing.T) {
	eventTypes := []events.EventType{
		events.EventDNS,
		events.EventConnect,
		events.EventTCPSend,
		events.EventTCPRecv,
		events.EventWrite,
		events.EventRead,
		events.EventFsync,
		events.EventSchedSwitch,
		events.EventTCPState,
		events.EventPageFault,
		events.EventOOMKill,
		events.EventUDPSend,
		events.EventUDPRecv,
		events.EventHTTPReq,
		events.EventHTTPResp,
		events.EventLockContention,
		events.EventTCPRetrans,
		events.EventNetDevError,
		events.EventDBQuery,
		events.EventExec,
		events.EventFork,
		events.EventOpen,
		events.EventClose,
	}

	for i, et := range eventTypes {
		t.Run(fmt.Sprintf("EventType_%d", i), func(t *testing.T) {
			var raw rawEvent
			raw.Type = uint32(et)
			raw.PID = 1
			raw.Timestamp = 1000

			var buf bytes.Buffer
			if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
				t.Fatalf("Failed to write binary data: %v", err)
			}

			event := ParseEvent(buf.Bytes())
			if event == nil {
				t.Fatalf("ParseEvent returned nil for event type %d", et)
			}
			if event.Type != et {
				t.Errorf("Expected type %d, got %d", et, event.Type)
			}
		})
	}
}

func TestParseEvent_TargetTruncation(t *testing.T) {
	var raw rawEvent
	longTarget := make([]byte, 200)
	for i := range longTarget {
		longTarget[i] = 'a'
	}
	copy(raw.Target[:], longTarget)

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("Failed to write binary data: %v", err)
	}

	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil")
	}
	if len(event.Target) > 128 {
		t.Errorf("Target should be truncated to 128 bytes, got %d", len(event.Target))
	}
}

func TestParseEvent_NullTerminatedStrings(t *testing.T) {
	var raw rawEvent
	// Test with trailing nulls (which get trimmed)
	copy(raw.Target[:], []byte("test\x00\x00\x00"))
	copy(raw.Details[:], []byte("details\x00\x00"))

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("Failed to write binary data: %v", err)
	}

	event := ParseEvent(buf.Bytes())
	if event == nil {
		t.Fatal("ParseEvent returned nil")
	}
	// bytes.TrimRight removes trailing nulls only
	if event.Target != "test" {
		t.Errorf("Expected target 'test', got '%s'", event.Target)
	}
	if event.Details != "details" {
		t.Errorf("Expected details 'details', got '%s'", event.Details)
	}
}

func BenchmarkParseEvent(b *testing.B) {
	var raw rawEvent
	raw.Timestamp = 1234567890
	raw.PID = 1234
	raw.Type = uint32(events.EventDNS)
	raw.LatencyNS = 5000000
	copy(raw.Target[:], "example.com")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		b.Fatalf("Failed to write binary data: %v", err)
	}
	eventData := buf.Bytes()

	// Pre-allocate to avoid allocation overhead during benchmark
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseEvent(eventData)
	}
}
