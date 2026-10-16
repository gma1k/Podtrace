package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

func enableAlerting(t *testing.T) {
	t.Helper()
	orig := config.AlertingEnabled
	config.AlertingEnabled = true
	t.Cleanup(func() { config.AlertingEnabled = orig })
}

func deliveryTestAlert() *Alert {
	return &Alert{
		Severity:  SeverityCritical,
		Title:     "title",
		Message:   "message",
		Timestamp: time.Now(),
		Source:    "test",
		Context:   map[string]interface{}{"k": "v"},
	}
}

func deliveryTestManager(senders ...Sender) *Manager {
	return &Manager{
		senders:      senders,
		deduplicator: NewAlertDeduplicator(time.Hour),
		rateLimiter:  NewRateLimiter(1000),
		enabled:      true,
		stopCh:       make(chan struct{}),
	}
}

// marshalingSender JSON-marshals the alert on every send — combined with a
// sibling sender mutating the same alert (Sanitize), this is the exact
// data race the per-sender clone fixes. Run under -race.
type marshalingSender struct {
	sends atomic.Int64
	err   error
}

func (m *marshalingSender) Send(_ context.Context, alert *Alert) error {
	alert.Sanitize()
	if _, err := json.Marshal(alert); err != nil {
		return err
	}
	m.sends.Add(1)
	return m.err
}
func (m *marshalingSender) Name() string { return "marshaling" }

// TestSendAlert_ConcurrentSendersDoNotShareTheAlert: N sender goroutines
// used to share one *Alert; each Send sanitized (mutated) it while siblings
// marshaled — a guaranteed race with two or more senders.
func TestSendAlert_ConcurrentSendersDoNotShareTheAlert(t *testing.T) {
	enableAlerting(t)
	s1, s2, s3 := &marshalingSender{}, &marshalingSender{}, &marshalingSender{}
	m := deliveryTestManager(s1, s2, s3)

	for i := 0; i < 20; i++ {
		alert := deliveryTestAlert()
		alert.Title = alert.Title + string(rune('a'+i)) // distinct dedup keys
		m.SendAlert(alert)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if s1.sends.Load() != 20 || s2.sends.Load() != 20 || s3.sends.Load() != 20 {
		t.Errorf("sends = %d/%d/%d, want 20 each", s1.sends.Load(), s2.sends.Load(), s3.sends.Load())
	}
}

// TestSendAlert_TotalFailureForgetsDedup: the dedup record was written at
// decision time, so when every sender failed the alert stayed silenced for
// the whole window. A total failure must allow the next occurrence through.
func TestSendAlert_TotalFailureForgetsDedup(t *testing.T) {
	enableAlerting(t)
	failing := &marshalingSender{err: errors.New("backend down")}
	m := deliveryTestManager(failing)

	m.SendAlert(deliveryTestAlert())
	waitForDeliveries(t, m)

	m.SendAlert(deliveryTestAlert())
	waitForDeliveries(t, m)

	if got := failing.sends.Load(); got != 2 {
		t.Errorf("sends = %d, want 2 (total failure must not silence the dedup window)", got)
	}

	ok := &marshalingSender{}
	m2 := deliveryTestManager(ok)
	m2.SendAlert(deliveryTestAlert())
	waitForDeliveries(t, m2)
	m2.SendAlert(deliveryTestAlert())
	waitForDeliveries(t, m2)
	if got := ok.sends.Load(); got != 1 {
		t.Errorf("sends = %d, want 1 (successful delivery dedups the window)", got)
	}
}

func waitForDeliveries(t *testing.T, m *Manager) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("deliveries never finished")
	}
}

// TestDeliveryBudget_CoversRetrySchedule: the 2×HTTP-timeout deadline
// expired mid-retry-schedule, making PODTRACE_ALERT_MAX_RETRIES mostly
// dead config. The budget must cover every attempt plus every backoff.
func TestDeliveryBudget_CoversRetrySchedule(t *testing.T) {
	var schedule time.Duration
	schedule += time.Duration(config.AlertMaxRetries+1) * config.AlertHTTPTimeout
	for attempt := 1; attempt <= config.AlertMaxRetries; attempt++ {
		backoff := config.DefaultAlertRetryBackoffBase * time.Duration(1<<uint(attempt-1))
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		schedule += backoff
	}
	if got := deliveryBudget(); got < schedule {
		t.Errorf("deliveryBudget() = %v, want at least the full retry schedule %v", got, schedule)
	}
}

// TestShutdown_WaitsForInFlightAndIsIdempotent: delivery goroutines were
// not tracked by the WaitGroup (Shutdown dropped in-flight alerts), and a
// second Shutdown panicked closing the closed stop channel.
func TestShutdown_WaitsForInFlightAndIsIdempotent(t *testing.T) {
	enableAlerting(t)
	release := make(chan struct{})
	var delivered atomic.Bool
	slow := &testMockSender{name: "slow", sendFunc: func(ctx context.Context, _ *Alert) error {
		<-release
		delivered.Store(true)
		return nil
	}}
	m := deliveryTestManager(slow)
	m.SendAlert(deliveryTestAlert())

	var wg sync.WaitGroup
	wg.Add(1)
	shutdownDone := make(chan error, 1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownDone <- m.Shutdown(ctx)
	}()

	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned (%v) while a delivery was still in flight", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if !delivered.Load() {
		t.Error("in-flight delivery was dropped by Shutdown")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
}
