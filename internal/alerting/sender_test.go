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

func TestRetrySender_Send_ContextDeadlineExceeded(t *testing.T) {
	mock := &mockSender{
		sendFunc: func(ctx context.Context, alert *Alert) error {
			return context.DeadlineExceeded
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
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Send() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestRetrySender_Send_ContextCanceledDuringBackoff(t *testing.T) {
	attempts := 0
	mock := &mockSender{
		sendFunc: func(ctx context.Context, alert *Alert) error {
			attempts++
			return errors.New("temporary error")
		},
		name: "mock",
	}
	retrySender := NewRetrySender(mock, 3, 100*time.Millisecond)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := retrySender.Send(ctx, alert)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Send() error = %v, want context.Canceled", err)
	}
}

func TestRetrySender_Send_BackoffLimit(t *testing.T) {
	attempts := 0
	mock := &mockSender{
		sendFunc: func(ctx context.Context, alert *Alert) error {
			attempts++
			return errors.New("temporary error")
		},
		name: "mock",
	}
	retrySender := NewRetrySender(mock, 3, 1*time.Second)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := retrySender.Send(ctx, alert)
	if err == nil {
		t.Error("Send() should return error after max retries")
	}
}

func TestRetrySender_Name(t *testing.T) {
	mock := &mockSender{name: "test-sender"}
	retrySender := NewRetrySender(mock, 3, 10*time.Millisecond)
	if retrySender.Name() != "test-sender" {
		t.Errorf("Name() = %s, want test-sender", retrySender.Name())
	}
}


func TestRetrySender_Send_ContextDeadlineExceededDuringBackoff(t *testing.T) {
	attempts := 0
	mock := &mockSender{
		sendFunc: func(ctx context.Context, alert *Alert) error {
			attempts++
			return errors.New("temporary error")
		},
		name: "mock",
	}
	retrySender := NewRetrySender(mock, 3, 100*time.Millisecond)
	alert := &Alert{
		Severity:  SeverityWarning,
		Title:     "Test",
		Message:   "Test",
		Timestamp: time.Now(),
		Source:    "test",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := retrySender.Send(ctx, alert)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Send() error = %v, want context.DeadlineExceeded", err)
	}
}


