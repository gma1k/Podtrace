package alerting

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

type AlertSeverity string

const (
	SeverityFatal    AlertSeverity = "fatal"
	SeverityCritical AlertSeverity = "critical"
	SeverityWarning  AlertSeverity = "warning"
	SeverityError    AlertSeverity = "error"
)

type Alert struct {
	Severity        AlertSeverity
	Title           string
	Message         string
	Timestamp       time.Time
	Source          string
	PodName         string
	Namespace       string
	Context         map[string]interface{}
	ErrorCode       string
	Recommendations []string
}

func (a *Alert) Key() string {
	if a == nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(a.Severity))
	h.Write([]byte(a.Source))
	h.Write([]byte(a.PodName))
	h.Write([]byte(a.Namespace))
	h.Write([]byte(a.Title))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (a *Alert) Validate() error {
	if a == nil {
		return fmt.Errorf("alert is nil")
	}
	if a.Severity == "" {
		return fmt.Errorf("alert severity is required")
	}
	if a.Title == "" {
		return fmt.Errorf("alert title is required")
	}
	if a.Message == "" {
		return fmt.Errorf("alert message is required")
	}
	if a.Timestamp.IsZero() {
		return fmt.Errorf("alert timestamp is required")
	}
	if a.Source == "" {
		return fmt.Errorf("alert source is required")
	}
	return nil
}

func (a *Alert) Sanitize() {
	if a == nil {
		return
	}
	if len(a.Title) > 256 {
		a.Title = a.Title[:253] + "..."
	}
	if len(a.Message) > 1024 {
		a.Message = a.Message[:1021] + "..."
	}
	if len(a.PodName) > 256 {
		a.PodName = a.PodName[:253] + "..."
	}
	if len(a.Namespace) > 256 {
		a.Namespace = a.Namespace[:253] + "..."
	}
	if len(a.Source) > 128 {
		a.Source = a.Source[:125] + "..."
	}
	if len(a.ErrorCode) > 64 {
		a.ErrorCode = a.ErrorCode[:61] + "..."
	}
	if len(a.Recommendations) > 10 {
		a.Recommendations = a.Recommendations[:10]
	}
	for i, rec := range a.Recommendations {
		if len(rec) > 512 {
			a.Recommendations[i] = rec[:509] + "..."
		}
	}
}

func MapResourceAlertLevel(level uint32) AlertSeverity {
	switch level {
	case 3:
		return SeverityFatal
	case 2:
		return SeverityCritical
	case 1:
		return SeverityWarning
	default:
		return SeverityError
	}
}

func ParseSeverity(severity string) AlertSeverity {
	switch severity {
	case "fatal":
		return SeverityFatal
	case "critical":
		return SeverityCritical
	case "warning":
		return SeverityWarning
	case "error":
		return SeverityError
	default:
		return SeverityError
	}
}

func SeverityLevel(severity AlertSeverity) int {
	switch severity {
	case SeverityFatal:
		return 4
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityError:
		return 1
	default:
		return 0
	}
}

func ShouldSendAlert(severity AlertSeverity) bool {
	if !config.AlertingEnabled {
		return false
	}
	minSeverity := ParseSeverity(config.GetAlertMinSeverity())
	return SeverityLevel(severity) >= SeverityLevel(minSeverity)
}

