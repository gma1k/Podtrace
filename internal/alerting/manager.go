package alerting

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
)

// alertLog is a package-level zap logger for the alerting package.
// It cannot use internal/logger because logger imports alerting (cycle).
var alertLog *zap.Logger

func init() {
	if l, err := zap.NewProduction(); err == nil {
		alertLog = l
	} else {
		alertLog = zap.NewNop()
	}
}

type Manager struct {
	senders       []Sender
	deduplicator  *AlertDeduplicator
	rateLimiter   *RateLimiter
	enabled       bool
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	stopCh        chan struct{}
	stopOnce      sync.Once
	shuttingDown  bool
	wg            sync.WaitGroup
}

// deliveryBudget is the per-alert deadline handed to each sender.
func deliveryBudget() time.Duration {
	budget := time.Duration(config.AlertMaxRetries+1) * config.AlertHTTPTimeout
	for attempt := 1; attempt <= config.AlertMaxRetries; attempt++ {
		budget += cappedBackoff(config.DefaultAlertRetryBackoffBase, attempt)
	}
	return budget + 5*time.Second
}

// redactURLForLog returns a URL safe to log (userinfo, query and fragment
// stripped, only scheme://host retained).
func redactURLForLog(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "[invalid-url]"
	}
	return u.Scheme + "://" + u.Host
}

func RedactURLForLog(raw string) string {
	return redactURLForLog(raw)
}

var embeddedURLPattern = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>` + "`" + `]+`)

func RedactURLsInText(s string) string {
	return embeddedURLPattern.ReplaceAllStringFunc(s, func(match string) string {
		trimmed := strings.TrimRight(match, `.,:;!?)]}"'`)
		return redactURLForLog(trimmed) + match[len(trimmed):]
	})
}

// redactedError presents err with every embedded URL cut down to
// scheme://host.
type redactedError struct{ err error }

func (e redactedError) Error() string { return RedactURLsInText(e.err.Error()) }

func (e redactedError) Unwrap() error { return e.err }

// redactSendError returns err with the request URL redacted. A *url.Error is
// rebuilt rather than wrapped so errors.As callers find only the redacted
// URL, while errors.Is still reaches context.DeadlineExceeded and friends.
func redactSendError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return &url.Error{Op: ue.Op, URL: redactURLForLog(ue.URL), Err: redactedError{ue.Err}}
	}
	return redactedError{err}
}

func NewManager() (*Manager, error) {
	if !config.AlertingEnabled {
		return &Manager{enabled: false}, nil
	}
	manager := &Manager{
		senders:      make([]Sender, 0),
		deduplicator: NewAlertDeduplicator(config.AlertDeduplicationWindow),
		rateLimiter:  NewRateLimiter(config.AlertRateLimitPerMinute),
		enabled:      true,
		stopCh:       make(chan struct{}),
	}
	if config.AlertWebhookURL != "" {
		webhookSender, err := NewWebhookSender(config.AlertWebhookURL, config.AlertHTTPTimeout)
		if err != nil {
			alertLog.Warn("Failed to create webhook alert sender — alerts will not be delivered via webhook",
				zap.Error(err), zap.String("url", redactURLForLog(config.AlertWebhookURL)))
		} else {
			retrySender := NewRetrySender(webhookSender, config.AlertMaxRetries, config.DefaultAlertRetryBackoffBase)
			manager.senders = append(manager.senders, retrySender)
		}
	}
	if config.AlertSlackWebhookURL != "" {
		slackSender, err := NewSlackSender(config.AlertSlackWebhookURL, config.AlertSlackChannel, config.AlertHTTPTimeout)
		if err != nil {
			alertLog.Warn("Failed to create Slack alert sender — alerts will not be delivered via Slack",
				zap.Error(err), zap.String("url", redactURLForLog(config.AlertSlackWebhookURL)))
		} else {
			retrySender := NewRetrySender(slackSender, config.AlertMaxRetries, config.DefaultAlertRetryBackoffBase)
			manager.senders = append(manager.senders, retrySender)
		}
	}
	if config.AlertSplunkEnabled {
		splunkEndpoint := config.GetSplunkEndpoint()
		splunkToken := config.GetSplunkToken()
		if splunkEndpoint != "" && splunkToken != "" {
			splunkSender, err := NewSplunkAlertSender(splunkEndpoint, splunkToken, config.AlertHTTPTimeout)
			if err != nil {
				alertLog.Warn("Failed to create Splunk alert sender — alerts will not be delivered via Splunk",
					zap.Error(err), zap.String("endpoint", redactURLForLog(splunkEndpoint)))
			} else {
				retrySender := NewRetrySender(splunkSender, config.AlertMaxRetries, config.DefaultAlertRetryBackoffBase)
				manager.senders = append(manager.senders, retrySender)
			}
		}
	}
	if len(manager.senders) == 0 {
		return &Manager{enabled: false}, nil
	}
	manager.cleanupTicker = time.NewTicker(1 * time.Hour)
	manager.wg.Add(1)
	go manager.cleanupLoop()
	return manager, nil
}

func (m *Manager) SendAlert(alert *Alert) {
	if alert == nil {
		return
	}
	m.mu.RLock()
	enabled, deduplicator, rateLimiter := m.enabled, m.deduplicator, m.rateLimiter
	m.mu.RUnlock()
	if !enabled {
		return
	}
	if !ShouldSendAlert(alert.Severity) {
		return
	}
	if !deduplicator.ShouldSend(alert) {
		return
	}
	if !rateLimiter.Allow() {
		deduplicator.Forget(alert)
		return
	}
	m.mu.RLock()
	if m.shuttingDown {
		m.mu.RUnlock()
		return
	}
	senders := make([]Sender, len(m.senders))
	copy(senders, m.senders)
	// wg.Add must happen before RUnlock so Shutdown cannot observe a zero
	// counter between the shutting-down check and the goroutine spawn.
	m.wg.Add(len(senders) + 1)
	m.mu.RUnlock()

	// Fan out one goroutine per sender, each with its OWN copy of the
	// alert: senders mutate it (Sanitize truncates fields), and a shared
	// pointer raced sibling goroutines marshaling it concurrently.
	var successes atomic.Int64
	var deliveries sync.WaitGroup
	for _, sender := range senders {
		deliveries.Add(1)
		go func(s Sender, a *Alert) {
			defer m.wg.Done()
			defer deliveries.Done()
			ctx, cancel := context.WithTimeout(context.Background(), deliveryBudget())
			defer cancel()
			if err := s.Send(ctx, a); err != nil {
				alertLog.Warn("Alert delivery failed",
					zap.String("sender", s.Name()),
					zap.String("alert", a.Title),
					zap.String("error", RedactURLsInText(err.Error())))
			} else {
				successes.Add(1)
			}
		}(sender, alert.Clone())
	}
	go func() {
		defer m.wg.Done()
		deliveries.Wait()
		if successes.Load() == 0 {
			// Every sender failed: forget the dedup record so the next
			// occurrence is attempted again instead of being silenced for
			// the rest of the window.
			m.deduplicator.Forget(alert)
		}
	}()
}

func (m *Manager) cleanupLoop() {
	defer m.wg.Done()
	for {
		select {
		case <-m.stopCh:
			return
		case <-m.cleanupTicker.C:
			m.deduplicator.Cleanup(config.AlertDeduplicationWindow * 2)
		}
	}
}

// Shutdown waits for in-flight alert deliveries (bounded by ctx) and is
// idempotent — a second call no longer panics on the closed stop channel.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if !m.enabled {
		m.mu.Unlock()
		return nil
	}
	m.shuttingDown = true
	stopCh, cleanupTicker := m.stopCh, m.cleanupTicker
	m.mu.Unlock()
	m.stopOnce.Do(func() {
		close(stopCh)
	})
	if cleanupTicker != nil {
		cleanupTicker.Stop()
	}
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) AddSender(sender Sender) {
	if sender == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.senders = append(m.senders, sender)
}

// EnsureEnabledWithSender guarantees the manager is active and includes the
// given sender, even when no external senders were configured (in which case
// NewManager returns a disabled manager).
func (m *Manager) EnsureEnabledWithSender(sender Sender) {
	if sender == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		m.enabled = true
		if m.deduplicator == nil {
			m.deduplicator = NewAlertDeduplicator(config.AlertDeduplicationWindow)
		}
		if m.rateLimiter == nil {
			m.rateLimiter = NewRateLimiter(config.AlertRateLimitPerMinute)
		}
		if m.stopCh == nil {
			m.stopCh = make(chan struct{})
		}
		if m.cleanupTicker == nil {
			m.cleanupTicker = time.NewTicker(1 * time.Hour)
			m.wg.Add(1)
			go m.cleanupLoop()
		}
	}
	m.senders = append(m.senders, sender)
}

func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}
