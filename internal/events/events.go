package events

import (
	"fmt"
	"time"
)

type EventType uint32

const (
	EventDNS EventType = iota
	EventConnect
	EventTCPSend
	EventTCPRecv
	EventWrite
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
	case EventWrite:
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
			return sprintf("[DNS] lookup %s failed: error %d", e.Target, e.Error)
		}
		return sprintf("[DNS] lookup %s took %.2fms", e.Target, latencyMs)
		
	case EventConnect:
		target := e.Target
		if target == "" || target == "?" {
			target = "unknown"
		}
		if e.Error != 0 {
			return sprintf("[NET] connect to %s failed: error %d", target, e.Error)
		}
		if latencyMs > 1 {
			return sprintf("[NET] connect to %s took %.2fms", target, latencyMs)
		}
		return ""
		
	case EventTCPSend:
		if e.Error < 0 && e.Error != -11 {
			return sprintf("[NET] TCP send error: %d", e.Error)
		}
		if latencyMs > 100 {
			return sprintf("[NET] TCP send latency spike: %.2fms", latencyMs)
		}
		return ""
		
	case EventTCPRecv:
		if e.Error < 0 && e.Error != -11 {
			return sprintf("[NET] TCP recv error: %d", e.Error)
		}
		if latencyMs > 100 {
			return sprintf("[NET] TCP recv RTT spike: %.2fms", latencyMs)
		}
		return ""
		
	case EventWrite:
		return sprintf("[FS] write() to %s took %.2fms", e.Target, latencyMs)
		
	case EventFsync:
		return sprintf("[FS] fsync() to %s took %.2fms", e.Target, latencyMs)
		
	case EventSchedSwitch:
		return sprintf("[CPU] thread blocked %.2fms", latencyMs)
		
	default:
		return sprintf("[UNKNOWN] event type %d", e.Type)
	}
}

func (e *Event) FormatRealtimeMessage() string {
	latencyMs := float64(e.LatencyNS) / 1e6
	
	switch e.Type {
	case EventDNS:
		if e.Error != 0 {
			return sprintf("[DNS] lookup %s failed: error %d", e.Target, e.Error)
		}
		return sprintf("[DNS] lookup %s took %.2fms", e.Target, latencyMs)
		
	case EventConnect:
		target := e.Target
		if target == "" || target == "?" {
			target = "unknown"
		}
		if e.Error != 0 {
			return sprintf("[NET] connect to %s failed: error %d", target, e.Error)
		}
		return sprintf("[NET] connect to %s (%.2fms)", target, latencyMs)
		
	case EventTCPSend:
		if e.Error < 0 && e.Error != -11 {
			return sprintf("[NET] TCP send error: %d", e.Error)
		}
		if latencyMs > 10 {
			return sprintf("[NET] TCP send latency: %.2fms", latencyMs)
		}
		return ""
		
	case EventTCPRecv:
		if e.Error < 0 && e.Error != -11 {
			return sprintf("[NET] TCP recv error: %d", e.Error)
		}
		if latencyMs > 10 {
			return sprintf("[NET] TCP recv RTT: %.2fms", latencyMs)
		}
		return ""
		
	case EventWrite:
		return sprintf("[FS] write() to %s took %.2fms", e.Target, latencyMs)
		
	case EventFsync:
		return sprintf("[FS] fsync() to %s took %.2fms", e.Target, latencyMs)
		
	case EventSchedSwitch:
		return sprintf("[CPU] thread blocked %.2fms", latencyMs)
		
	default:
		return sprintf("[UNKNOWN] event type %d", e.Type)
	}
}

func sprintf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}
