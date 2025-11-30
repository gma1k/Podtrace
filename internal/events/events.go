package events

import (
	"fmt"
	"strings"
	"time"
)

func sanitizeString(s string) string {
	return strings.ReplaceAll(s, "%", "%%")
}

type EventType uint32

const (
	EventDNS EventType = iota
	EventConnect
	EventTCPSend
	EventTCPRecv
	EventWrite
	EventRead
	EventFsync
	EventSchedSwitch
	EventTCPState
	EventPageFault
	EventOOMKill
	EventUDPSend
	EventUDPRecv
	EventHTTPReq
	EventHTTPResp
)

type Event struct {
	Timestamp   uint64
	PID         uint32
	ProcessName string
	Type        EventType
	LatencyNS   uint64
	Error       int32
	Bytes       uint64
	TCPState    uint32
	Target      string
	Details     string
}

func (e *Event) Latency() time.Duration {
	return time.Duration(e.LatencyNS) * time.Nanosecond
}

func (e *Event) TimestampTime() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

func (e *Event) TypeString() string {
	switch e.Type {
	case EventDNS:
		return "DNS"
	case EventConnect:
		return "NET"
	case EventTCPSend, EventTCPRecv, EventTCPState, EventUDPSend, EventUDPRecv:
		return "NET"
	case EventWrite, EventRead:
		return "FS"
	case EventFsync:
		return "FS"
	case EventSchedSwitch:
		return "CPU"
	case EventPageFault, EventOOMKill:
		return "MEM"
	case EventHTTPReq, EventHTTPResp:
		return "HTTP"
	default:
		return "UNKNOWN"
	}
}

func (e *Event) FormatMessage() string {
	latencyMs := float64(e.LatencyNS) / 1e6

	switch e.Type {
	case EventDNS:
		if e.Error != 0 {
			return fmt.Sprintf("[DNS] lookup %s failed: error %d", sanitizeString(e.Target), e.Error)
		}
		return fmt.Sprintf("[DNS] lookup %s took %.2fms", sanitizeString(e.Target), latencyMs)

	case EventConnect:
		target := e.Target
		if target == "" || target == "?" {
			target = "file"
		}
		if e.Error != 0 {
			return fmt.Sprintf("[NET] connect to %s failed: error %d", sanitizeString(target), e.Error)
		}
		if latencyMs > 1 {
			return fmt.Sprintf("[NET] connect to %s took %.2fms", sanitizeString(target), latencyMs)
		}
		return ""

	case EventTCPSend:
		if e.Error < 0 && e.Error != -11 {
			return fmt.Sprintf("[NET] TCP send error: %d", e.Error)
		}
		if latencyMs > 100 {
			msg := fmt.Sprintf("[NET] TCP send latency spike: %.2fms", latencyMs)
			if e.Bytes > 0 {
				msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
			}
			return msg
		}
		return ""

	case EventTCPRecv:
		if e.Error < 0 && e.Error != -11 {
			return fmt.Sprintf("[NET] TCP recv error: %d", e.Error)
		}
		if latencyMs > 100 {
			msg := fmt.Sprintf("[NET] TCP recv RTT spike: %.2fms", latencyMs)
			if e.Bytes > 0 {
				msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
			}
			return msg
		}
		return ""

	case EventUDPSend:
		if e.Error < 0 {
			return fmt.Sprintf("[NET] UDP send error: %d", e.Error)
		}
		if latencyMs > 100 {
			msg := fmt.Sprintf("[NET] UDP send latency spike: %.2fms", latencyMs)
			if e.Bytes > 0 {
				msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
			}
			return msg
		}
		return ""

	case EventUDPRecv:
		if e.Error < 0 {
			return fmt.Sprintf("[NET] UDP recv error: %d", e.Error)
		}
		if latencyMs > 100 {
			msg := fmt.Sprintf("[NET] UDP recv latency spike: %.2fms", latencyMs)
			if e.Bytes > 0 {
				msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
			}
			return msg
		}
		return ""

	case EventHTTPReq:
		target := e.Target
		if target == "" {
			target = "unknown"
		}
		return fmt.Sprintf("[HTTP] request to %s took %.2fms", sanitizeString(target), latencyMs)

	case EventHTTPResp:
		target := e.Target
		if target == "" {
			target = "unknown"
		}
		msg := fmt.Sprintf("[HTTP] response from %s took %.2fms", sanitizeString(target), latencyMs)
		if e.Bytes > 0 {
			msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
		}
		return msg

	case EventTCPState:
		stateStr := TCPStateString(e.TCPState)
		target := e.Target
		if target == "" {
			target = "unknown"
		}
		return fmt.Sprintf("[NET] TCP state change to %s for %s", stateStr, sanitizeString(target))

	case EventPageFault:
		return fmt.Sprintf("[MEM] Page fault (error: %d)", e.Error)

	case EventOOMKill:
		target := e.Target
		if target == "" {
			target = "unknown"
		}
		memMB := float64(e.Bytes) / (1024 * 1024)
		return fmt.Sprintf("[MEM] OOM kill: %s (%.2f MB)", sanitizeString(target), memMB)

	case EventWrite:
		target := e.Target
		if target == "" || target == "?" {
			target = "file"
		}
		msg := fmt.Sprintf("[FS] write() to %s took %.2fms", sanitizeString(target), latencyMs)
		if e.Bytes > 0 {
			msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
		}
		return msg

	case EventRead:
		target := e.Target
		if target == "" || target == "?" {
			target = "file"
		}
		msg := fmt.Sprintf("[FS] read() from %s took %.2fms", sanitizeString(target), latencyMs)
		if e.Bytes > 0 {
			msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
		}
		return msg

	case EventFsync:
		target := e.Target
		if target == "" {
			target = "file"
		}
		return fmt.Sprintf("[FS] fsync() to %s took %.2fms", sanitizeString(target), latencyMs)

	case EventSchedSwitch:
		return fmt.Sprintf("[CPU] thread blocked %.2fms", latencyMs)

	default:
		return fmt.Sprintf("[UNKNOWN] event type %d", e.Type)
	}
}

func TCPStateString(state uint32) string {
	states := map[uint32]string{
		1:  "ESTABLISHED",
		2:  "SYN_SENT",
		3:  "SYN_RECV",
		4:  "FIN_WAIT1",
		5:  "FIN_WAIT2",
		6:  "TIME_WAIT",
		7:  "CLOSE",
		8:  "CLOSE_WAIT",
		9:  "LAST_ACK",
		10: "LISTEN",
		11: "CLOSING",
		12: "NEW_SYN_RECV",
	}
	if name, ok := states[state]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", state)
}

func (e *Event) FormatRealtimeMessage() string {
	latencyMs := float64(e.LatencyNS) / 1e6

	switch e.Type {
	case EventDNS:
		if e.Error != 0 {
			return fmt.Sprintf("[DNS] lookup %s failed: error %d", sanitizeString(e.Target), e.Error)
		}
		return fmt.Sprintf("[DNS] lookup %s took %.2fms", sanitizeString(e.Target), latencyMs)

	case EventConnect:
		target := e.Target
		if target == "" || target == "?" {
			target = "file"
		}
		if e.Error != 0 {
			return fmt.Sprintf("[NET] connect to %s failed: error %d", sanitizeString(target), e.Error)
		}
		return fmt.Sprintf("[NET] connect to %s (%.2fms)", sanitizeString(target), latencyMs)

	case EventTCPSend:
		if e.Error < 0 && e.Error != -11 {
			return fmt.Sprintf("[NET] TCP send error: %d", e.Error)
		}
		if latencyMs > 10 {
			msg := fmt.Sprintf("[NET] TCP send latency: %.2fms", latencyMs)
			if e.Bytes > 0 {
				msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
			}
			return msg
		}
		return ""

	case EventTCPRecv:
		if e.Error < 0 && e.Error != -11 {
			return fmt.Sprintf("[NET] TCP recv error: %d", e.Error)
		}
		if latencyMs > 10 {
			msg := fmt.Sprintf("[NET] TCP recv RTT: %.2fms", latencyMs)
			if e.Bytes > 0 {
				msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
			}
			return msg
		}
		return ""

	case EventTCPState:
		stateStr := TCPStateString(e.TCPState)
		target := e.Target
		if target == "" {
			target = "unknown"
		}
		return fmt.Sprintf("[NET] TCP state: %s for %s", stateStr, sanitizeString(target))

	case EventPageFault:
		return fmt.Sprintf("[MEM] Page fault (error: %d)", e.Error)

	case EventOOMKill:
		target := e.Target
		if target == "" {
			target = "unknown"
		}
		memMB := float64(e.Bytes) / (1024 * 1024)
		return fmt.Sprintf("[MEM] OOM kill: %s (%.2f MB)", sanitizeString(target), memMB)

	case EventWrite:
		target := e.Target
		if target == "" || target == "?" {
			target = "file"
		}
		msg := fmt.Sprintf("[FS] write() to %s took %.2fms", sanitizeString(target), latencyMs)
		if e.Bytes > 0 {
			msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
		}
		return msg

	case EventRead:
		target := e.Target
		if target == "" || target == "?" {
			target = "file"
		}
		msg := fmt.Sprintf("[FS] read() from %s took %.2fms", sanitizeString(target), latencyMs)
		if e.Bytes > 0 {
			msg += fmt.Sprintf(" (%d bytes)", e.Bytes)
		}
		return msg

	case EventFsync:
		target := e.Target
		if target == "" {
			target = "file"
		}
		return fmt.Sprintf("[FS] fsync() to %s took %.2fms", sanitizeString(target), latencyMs)

	case EventSchedSwitch:
		return fmt.Sprintf("[CPU] thread blocked %.2fms", latencyMs)

	default:
		return fmt.Sprintf("[UNKNOWN] event type %d", e.Type)
	}
}
