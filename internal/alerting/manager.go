package alerting

import (
	"context"
	"sync"
	"time"
)

type Manager struct {
	senders       []Sender
	deduplicator  *AlertDeduplicator
	rateLimiter   *RateLimiter
	enabled       bool
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

func NewManager() (*Manager, error) {
	if !AlertingEnabled {
		return &Manager{enabled: false}, nil
	}
	manager := &Manager{
		senders:      make([]Sender, 0),
		deduplicator: NewAlertDeduplicator(AlertDeduplicationWindow),
		rateLimiter:  NewRateLimiter(AlertRateLimitPerMinute),
		enabled:      true,
		stopCh:       make(chan struct{}),
	}
	if AlertWebhookURL != "" {
		webhookSender, err := NewWebhookSender(AlertWebhookURL, AlertHTTPTimeout)
		if err != nil {
		} else {
			retrySender := NewRetrySender(webhookSender, AlertMaxRetries, DefaultAlertRetryBackoffBase)
			manager.senders = append(manager.senders, retrySender)
		}
	}
	if AlertSlackWebhookURL != "" {
		slackSender, err := NewSlackSender(AlertSlackWebhookURL, AlertSlackChannel, AlertHTTPTimeout)
		if err != nil {
		} else {
			retrySender := NewRetrySender(slackSender, AlertMaxRetries, DefaultAlertRetryBackoffBase)
			manager.senders = append(manager.senders, retrySender)
		}
	}
	if AlertSplunkEnabled {
		splunkEndpoint := GetSplunkEndpoint()
		splunkToken := GetSplunkToken()
		if splunkEndpoint != "" && splunkToken != "" {
			splunkSender, err := NewSplunkAlertSender(splunkEndpoint, splunkToken, AlertHTTPTimeout)
			if err != nil {
			} else {
				retrySender := NewRetrySender(splunkSender, AlertMaxRetries, DefaultAlertRetryBackoffBase)
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
	if !m.enabled || alert == nil {
		return
	}
	if !ShouldSendAlert(alert.Severity) {
		return
	}
	if !m.rateLimiter.Allow() {
		return
	}
	if !m.deduplicator.ShouldSend(alert) {
		return
	}
	m.mu.RLock()
	senders := make([]Sender, len(m.senders))
	copy(senders, m.senders)
	m.mu.RUnlock()
		for _, sender := range senders {
			go func(s Sender) {
				ctx, cancel := context.WithTimeout(context.Background(), AlertHTTPTimeout*2)
				defer cancel()
				_ = s.Send(ctx, alert)
			}(sender)
		}
}

func (m *Manager) cleanupLoop() {
	defer m.wg.Done()
	for {
		select {
		case <-m.stopCh:
			return
		case <-m.cleanupTicker.C:
			m.deduplicator.Cleanup(AlertDeduplicationWindow * 2)
		}
	}
}

func (m *Manager) Shutdown(ctx context.Context) error {
	if !m.enabled {
		return nil
	}
	close(m.stopCh)
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
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

func (m *Manager) IsEnabled() bool {
	return m.enabled
}

