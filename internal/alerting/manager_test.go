package alerting

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

func TestNewManager_Disabled(t *testing.T) {
	_ = os.Setenv("PODTRACE_ALERTING_ENABLED", "false")
	defer func() {
		_ = os.Unsetenv("PODTRACE_ALERTING_ENABLED")
	}()
	config.AlertingEnabled = false
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if manager.IsEnabled() {
		t.Error("Manager should be disabled")
	}
}

func TestManager_SendAlert_Disabled(t *testing.T) {
	manager := &Manager{enabled: false}
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
	}
	manager.SendAlert(alert)
}

func TestManager_SendAlert_Nil(t *testing.T) {
	manager := &Manager{enabled: true}
	manager.SendAlert(nil)
}

func TestManager_Shutdown(t *testing.T) {
	manager := &Manager{
		enabled: true,
		stopCh:  make(chan struct{}),
	}
	manager.cleanupTicker = time.NewTicker(1 * time.Hour)
	manager.wg.Add(1)
	go func() {
		defer manager.wg.Done()
		<-manager.stopCh
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_AddSender(t *testing.T) {
	manager := &Manager{
		enabled: true,
		senders: make([]Sender, 0),
	}
	mockSender := &testMockSender{name: "test"}
	manager.AddSender(mockSender)
	if len(manager.senders) != 1 {
		t.Errorf("Expected 1 sender, got %d", len(manager.senders))
	}
	manager.AddSender(nil)
	if len(manager.senders) != 1 {
		t.Errorf("Expected 1 sender after adding nil, got %d", len(manager.senders))
	}
}

type testMockSender struct {
	sendFunc func(ctx context.Context, alert *Alert) error
	name     string
}

func (m *testMockSender) Send(ctx context.Context, alert *Alert) error {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, alert)
	}
	return nil
}

func (m *testMockSender) Name() string {
	return m.name
}
