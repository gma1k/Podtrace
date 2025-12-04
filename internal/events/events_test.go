package events

import (
	"testing"
	"time"
)

func TestEvent_Latency(t *testing.T) {
	e := &Event{LatencyNS: 5000000}
	expected := 5 * time.Millisecond
	if e.Latency() != expected {
		t.Errorf("Expected latency %v, got %v", expected, e.Latency())
	}
}

func TestEvent_TimestampTime(t *testing.T) {
	ts := uint64(1609459200000000000)
	e := &Event{Timestamp: ts}
	result := e.TimestampTime()
	if result.UnixNano() != int64(ts) {
		t.Errorf("Expected timestamp %d, got %d", ts, result.UnixNano())
	}
}

func TestEvent_TypeString(t *testing.T) {
	tests := []struct {
		eventType EventType
		expected  string
	}{
		{EventDNS, "DNS"},
		{EventConnect, "NET"},
		{EventTCPSend, "NET"},
		{EventTCPRecv, "NET"},
		{EventWrite, "FS"},
		{EventRead, "FS"},
		{EventFsync, "FS"},
		{EventSchedSwitch, "CPU"},
		{EventPageFault, "MEM"},
		{EventOOMKill, "MEM"},
		{EventHTTPReq, "HTTP"},
		{EventHTTPResp, "HTTP"},
		{EventLockContention, "LOCK"},
		{EventTCPRetrans, "NET"},
		{EventNetDevError, "NET"},
		{EventDBQuery, "DB"},
		{EventExec, "PROC"},
		{EventFork, "PROC"},
		{EventOpen, "PROC"},
		{EventClose, "PROC"},
		{EventType(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			e := &Event{Type: tt.eventType}
			result := e.TypeString()
			if result != tt.expected {
				t.Errorf("Expected type string '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestEvent_FormatMessage_DNS(t *testing.T) {
	tests := []struct {
		name     string
		event    *Event
		expected string
	}{
		{
			"successful lookup",
			&Event{Type: EventDNS, LatencyNS: 5000000, Target: "example.com", Error: 0},
			"[DNS] lookup example.com took 5.00ms",
		},
		{
			"failed lookup",
			&Event{Type: EventDNS, LatencyNS: 1000000, Target: "invalid.com", Error: 1},
			"[DNS] lookup invalid.com failed: error 1",
		},
		{
			"long target truncated",
			&Event{Type: EventDNS, LatencyNS: 5000000, Target: string(make([]byte, 300)), Error: 0},
			"[DNS] lookup " + string(make([]byte, 253)) + "... took 5.00ms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if len(result) > 0 && result[:len("[DNS]")] != "[DNS]" {
				t.Errorf("Expected DNS format message, got '%s'", result)
			}
		})
	}
}

func TestEvent_FormatMessage_Connect(t *testing.T) {
	tests := []struct {
		name     string
		event    *Event
		shouldBe string
	}{
		{
			"fast connection (no output)",
			&Event{Type: EventConnect, LatencyNS: 500000, Target: "example.com:80", Error: 0},
			"",
		},
		{
			"slow connection",
			&Event{Type: EventConnect, LatencyNS: 2000000, Target: "example.com:80", Error: 0},
			"[NET] connect to example.com:80 took 2.00ms",
		},
		{
			"failed connection",
			&Event{Type: EventConnect, LatencyNS: 1000000, Target: "invalid.com:80", Error: 111},
			"[NET] connect to invalid.com:80 failed: error 111",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if result != tt.shouldBe {
				t.Errorf("Expected '%s', got '%s'", tt.shouldBe, result)
			}
		})
	}
}

func TestEvent_FormatMessage_TCP(t *testing.T) {
	tests := []struct {
		name     string
		event    *Event
		shouldBe string
	}{
		{
			"normal latency (no output)",
			&Event{Type: EventTCPSend, LatencyNS: 5000000, Error: 0},
			"",
		},
		{
			"high latency spike",
			&Event{Type: EventTCPSend, LatencyNS: 150000000, Error: 0, Bytes: 1024},
			"[NET] TCP send latency spike: 150.00ms (1024 bytes)",
		},
		{
			"error",
			&Event{Type: EventTCPSend, LatencyNS: 1000000, Error: -1},
			"[NET] TCP send error: -1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if result != tt.shouldBe {
				t.Errorf("Expected '%s', got '%s'", tt.shouldBe, result)
			}
		})
	}
}

func TestEvent_FormatMessage_Filesystem(t *testing.T) {
	tests := []struct {
		name     string
		event    *Event
		expected string
	}{
		{
			"read operation",
			&Event{Type: EventRead, LatencyNS: 2000000, Target: "/tmp/file", Bytes: 4096},
			"[FS] read() from /tmp/file took 2.00ms (4096 bytes)",
		},
		{
			"write operation",
			&Event{Type: EventWrite, LatencyNS: 3000000, Target: "/tmp/file", Bytes: 2048},
			"[FS] write() to /tmp/file took 3.00ms (2048 bytes)",
		},
		{
			"fsync operation",
			&Event{Type: EventFsync, LatencyNS: 1000000, Target: "/tmp/file"},
			"[FS] fsync() to /tmp/file took 1.00ms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.FormatMessage()
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestTCPStateString(t *testing.T) {
	tests := []struct {
		state    uint32
		expected string
	}{
		{1, "ESTABLISHED"},
		{2, "SYN_SENT"},
		{3, "SYN_RECV"},
		{4, "FIN_WAIT1"},
		{5, "FIN_WAIT2"},
		{6, "TIME_WAIT"},
		{7, "CLOSE"},
		{8, "CLOSE_WAIT"},
		{9, "LAST_ACK"},
		{10, "LISTEN"},
		{11, "CLOSING"},
		{12, "NEW_SYN_RECV"},
		{99, "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := TCPStateString(tt.state)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal", "normal"},
		{"with%percent", "with%%percent"},
		{"multiple%%percent", "multiple%%%%percent"},
		{"no percent", "no percent"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"short string", "short", 10, "short"},
		{"exact length", "exact", 5, "exact"},
		{"truncate with ellipsis", "very long string", 10, "very lo..."},
		{"max 3", "long", 3, "lon"},
		{"max 1", "long", 1, "l"},
		{"max 0", "long", 0, "long"},
		{"max negative", "long", -1, "long"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.max)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func BenchmarkFormatMessage(b *testing.B) {
	event := &Event{
		Type:      EventDNS,
		LatencyNS: 5000000,
		Target:    "example.com",
		Error:     0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = event.FormatMessage()
	}
}

func BenchmarkTypeString(b *testing.B) {
	event := &Event{Type: EventDNS}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = event.TypeString()
	}
}
