package alerting

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockSender struct {
	sendFunc func(ctx context.Context, alert *Alert) error
	name     string
}

func (m *mockSender) Send(ctx context.Context, alert *Alert) error {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, alert)
	}
	return nil
}

func (m *mockSender) Name() string {
	return m.name
}

func TestRetrySender_Send_Success(t *testing.T) {
	mock := &mockSender{
		sendFunc: func(ctx context.Context, alert *Alert) error {
			return nil
		},
		name: "mock",
	}
	retrySender := NewRetrySender(mock, 3, 10*time.Millisecond)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
	}
	err := retrySender.Send(context.Background(), alert)
	if err != nil {
		t.Errorf("Send() error = %v, want nil", err)
	}
}

func TestRetrySender_Send_Retry(t *testing.T) {
	attempts := 0
	mock := &mockSender{
		sendFunc: func(ctx context.Context, alert *Alert) error {
			attempts++
			if attempts < 2 {
				return errors.New("temporary error")
			}
			return nil
		},
		name: "mock",
	}
	retrySender := NewRetrySender(mock, 3, 10*time.Millisecond)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
	}
	err := retrySender.Send(context.Background(), alert)
	if err != nil {
		t.Errorf("Send() error = %v, want nil", err)
	}
	if attempts != 2 {
		t.Errorf("Expected 2 attempts, got %d", attempts)
	}
}

func TestRetrySender_Send_MaxRetries(t *testing.T) {
	mock := &mockSender{
		sendFunc: func(ctx context.Context, alert *Alert) error {
			return errors.New("persistent error")
		},
		name: "mock",
	}
	retrySender := NewRetrySender(mock, 2, 10*time.Millisecond)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
	}
	err := retrySender.Send(context.Background(), alert)
	if err == nil {
		t.Error("Send() should return error after max retries")
	}
}

func TestRetrySender_Send_NilAlert(t *testing.T) {
	mock := &mockSender{name: "mock"}
	retrySender := NewRetrySender(mock, 3, 10*time.Millisecond)
	err := retrySender.Send(context.Background(), nil)
	if err == nil {
		t.Error("Send() should return error for nil alert")
	}
}

func TestRetrySender_Send_InvalidAlert(t *testing.T) {
	mock := &mockSender{name: "mock"}
	retrySender := NewRetrySender(mock, 3, 10*time.Millisecond)
	alert := &Alert{
		Severity: SeverityWarning,
	}
	err := retrySender.Send(context.Background(), alert)
	if err == nil {
		t.Error("Send() should return error for invalid alert")
	}
}

func TestRetrySender_Send_ContextCanceled(t *testing.T) {
	mock := &mockSender{
		sendFunc: func(ctx context.Context, alert *Alert) error {
			return context.Canceled
		},
		name: "mock",
	}
	retrySender := NewRetrySender(mock, 3, 10*time.Millisecond)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
	}
	err := retrySender.Send(context.Background(), alert)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Send() error = %v, want context.Canceled", err)
	}
}

