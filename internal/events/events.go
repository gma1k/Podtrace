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
)

type Event struct {
	Timestamp   uint64
	PID         uint32
	ProcessName string
	Type        EventType
	LatencyNS   uint64
	Error       int32
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
	case EventTCPSend, EventTCPRecv:
		return "NET"
	case EventWrite, EventRead:
		return "FS"
	case EventFsync:
		return "FS"
	case EventSchedSwitch:
		return "CPU"
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
			return fmt.Sprintf("[NET] TCP send latency spike: %.2fms", latencyMs)
		}
		return ""

	case EventTCPRecv:
		if e.Error < 0 && e.Error != -11 {
			return fmt.Sprintf("[NET] TCP recv error: %d", e.Error)
		}
		if latencyMs > 100 {
			return fmt.Sprintf("[NET] TCP recv RTT spike: %.2fms", latencyMs)
		}
		return ""

	case EventWrite:
		target := e.Target
		if target == "" || target == "?" {
			target = "file"
		}
		return fmt.Sprintf("[FS] write() to %s took %.2fms", sanitizeString(target), latencyMs)

	case EventRead:
		target := e.Target
		if target == "" || target == "?" {
			target = "file"
		}
		return fmt.Sprintf("[FS] read() from %s took %.2fms", sanitizeString(target), latencyMs)

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
			return fmt.Sprintf("[NET] TCP send latency: %.2fms", latencyMs)
		}
		return ""

	case EventTCPRecv:
		if e.Error < 0 && e.Error != -11 {
			return fmt.Sprintf("[NET] TCP recv error: %d", e.Error)
		}
		if latencyMs > 10 {
			return fmt.Sprintf("[NET] TCP recv RTT: %.2fms", latencyMs)
		}
		return ""

	case EventWrite:
		target := e.Target
		if target == "" || target == "?" {
			target = "file"
		}
		return fmt.Sprintf("[FS] write() to %s took %.2fms", sanitizeString(target), latencyMs)

	case EventRead:
		target := e.Target
		if target == "" || target == "?" {
			target = "file"
		}
		return fmt.Sprintf("[FS] read() from %s took %.2fms", sanitizeString(target), latencyMs)

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
