package alerting

import (
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

const (
	DefaultAlertRetryBackoffBase = 1 * time.Second
)

var (
	AlertingEnabled         = config.AlertingEnabled
	AlertWebhookURL         = config.AlertWebhookURL
	AlertSlackWebhookURL    = config.AlertSlackWebhookURL
	AlertSlackChannel       = config.AlertSlackChannel
	AlertSplunkEnabled      = config.AlertSplunkEnabled
	AlertDeduplicationWindow = config.AlertDeduplicationWindow
	AlertRateLimitPerMinute  = config.AlertRateLimitPerMinute
	AlertHTTPTimeout         = config.AlertHTTPTimeout
	AlertMaxRetries          = config.AlertMaxRetries
	AlertMaxPayloadSize      = config.AlertMaxPayloadSize
)

func GetSplunkEndpoint() string {
	if AlertSplunkEnabled {
		return config.SplunkEndpoint
	}
	return ""
}

func GetSplunkToken() string {
	if AlertSplunkEnabled {
		return config.SplunkToken
	}
	return ""
}

func ShouldSendAlert(severity AlertSeverity) bool {
	if !AlertingEnabled {
		return false
	}
	minSeverity := ParseSeverity(config.GetAlertMinSeverity())
	return SeverityLevel(severity) >= SeverityLevel(minSeverity)
}

