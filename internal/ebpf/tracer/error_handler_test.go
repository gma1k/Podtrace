package tracer

import (
	"errors"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

func TestNewErrorRateLimiter(t *testing.T) {
	limiter := newErrorRateLimiter()
	if limiter == nil {
		t.Fatal("Expected non-nil error rate limiter")
	}
	if limiter.backoffFactor != 1 {
		t.Errorf("Expected backoffFactor 1, got %d", limiter.backoffFactor)
	}
	if limiter.minInterval != config.DefaultErrorBackoffMinInterval {
		t.Errorf("Expected minInterval %v, got %v", config.DefaultErrorBackoffMinInterval, limiter.minInterval)
	}
}

func TestErrorRateLimiter_ShouldLog(t *testing.T) {
	limiter := newErrorRateLimiter()
	limiter.lastLogTime = time.Now().Add(-2 * time.Second)

	if !limiter.shouldLog() {
		t.Error("Expected shouldLog to return true after sufficient time")
	}

	limiter.lastLogTime = time.Now()
	if limiter.shouldLog() {
		t.Error("Expected shouldLog to return false immediately after logging")
	}
}

func TestErrorRateLimiter_Backoff(t *testing.T) {
	limiter := newErrorRateLimiter()
	limiter.lastLogTime = time.Now().Add(-10 * time.Second)

	for i := 0; i < 5; i++ {
		limiter.shouldLog()
		limiter.lastLogTime = time.Now().Add(-10 * time.Second)
	}

	if limiter.backoffFactor <= 1 {
		t.Error("Expected backoffFactor to increase")
	}
}

func TestNewSlidingWindow(t *testing.T) {
	window := newSlidingWindow(5*time.Second, 10)
	if window == nil {
		t.Fatal("Expected non-nil sliding window")
	}
	if window.window != 5*time.Second {
		t.Errorf("Expected window %v, got %v", 5*time.Second, window.window)
	}
}

func TestSlidingWindow_AddError(t *testing.T) {
	window := newSlidingWindow(5*time.Second, 10)
	window.addError()
	window.addError()

	rate := window.getErrorRate()
	if rate != 2 {
		t.Errorf("Expected error rate 2, got %d", rate)
	}
}

func TestSlidingWindow_GetErrorRate(t *testing.T) {
	window := newSlidingWindow(1*time.Second, 10)
	window.addError()
	window.addError()
	window.addError()

	rate := window.getErrorRate()
	if rate != 3 {
		t.Errorf("Expected error rate 3, got %d", rate)
	}
}

func TestSlidingWindow_Expiration(t *testing.T) {
	window := newSlidingWindow(100*time.Millisecond, 10)
	window.addError()
	window.addError()

	time.Sleep(150 * time.Millisecond)

	rate := window.getErrorRate()
	if rate != 0 {
		t.Errorf("Expected error rate 0 after expiration, got %d", rate)
	}
}

func TestNewCircuitBreaker(t *testing.T) {
	cb := newCircuitBreaker(100, 30*time.Second)
	if cb == nil {
		t.Fatal("Expected non-nil circuit breaker")
	}
	if cb.threshold != 100 {
		t.Errorf("Expected threshold 100, got %d", cb.threshold)
	}
	if cb.timeout != 30*time.Second {
		t.Errorf("Expected timeout %v, got %v", 30*time.Second, cb.timeout)
	}
}

func TestCircuitBreaker_CanProceed_Closed(t *testing.T) {
	cb := newCircuitBreaker(100, 30*time.Second)
	if !cb.canProceed() {
		t.Error("Expected canProceed to return true when circuit is closed")
	}
}

func TestCircuitBreaker_RecordFailure(t *testing.T) {
	cb := newCircuitBreaker(2, 30*time.Second)
	cb.recordFailure()
	cb.recordFailure()

	if cb.canProceed() {
		t.Error("Expected canProceed to return false after threshold failures")
	}
}

func TestCircuitBreaker_RecordSuccess(t *testing.T) {
	cb := newCircuitBreaker(2, 30*time.Second)
	cb.recordFailure()
	cb.recordFailure()

	cb.lastFailure = time.Now().Add(-31 * time.Second)
	if !cb.canProceed() {
		t.Error("Expected canProceed to return true after timeout")
	}

	cb.recordSuccess()
	cb.recordSuccess()
	cb.recordSuccess()

	if !cb.canProceed() {
		t.Error("Expected canProceed to return true after successful recovery")
	}
}

func TestClassifyError_Transient(t *testing.T) {
	err := errors.New("EAGAIN error")
	err2 := errors.New("temporary failure")
	
	category := classifyError(err)
	if category != ErrorCategoryTransient {
		t.Errorf("Expected ErrorCategoryTransient for EAGAIN, got %d", category)
	}

	category = classifyError(err2)
	if category != ErrorCategoryTransient {
		t.Errorf("Expected ErrorCategoryTransient for temporary, got %d", category)
	}

	err3 := errors.New("closed connection")
	category = classifyError(err3)
	if category != ErrorCategoryTransient {
		t.Errorf("Expected ErrorCategoryTransient for closed, got %d", category)
	}
}

func TestClassifyError_Permanent(t *testing.T) {
	err := errors.New("permission denied")
	category := classifyError(err)
	if category != ErrorCategoryPermanent {
		t.Errorf("Expected ErrorCategoryPermanent for permission error, got %d", category)
	}
}

func TestClassifyError_Recoverable(t *testing.T) {
	err := errors.New("some other error")
	category := classifyError(err)
	if category != ErrorCategoryRecoverable {
		t.Errorf("Expected ErrorCategoryRecoverable for generic error, got %d", category)
	}
}

func TestClassifyError_Nil(t *testing.T) {
	category := classifyError(nil)
	if category != ErrorCategoryTransient {
		t.Errorf("Expected ErrorCategoryTransient for nil error, got %d", category)
	}
}

func TestErrorCategoryString(t *testing.T) {
	if errorCategoryString(ErrorCategoryTransient) != "transient" {
		t.Error("Expected 'transient' for ErrorCategoryTransient")
	}
	if errorCategoryString(ErrorCategoryRecoverable) != "recoverable" {
		t.Error("Expected 'recoverable' for ErrorCategoryRecoverable")
	}
	if errorCategoryString(ErrorCategoryPermanent) != "permanent" {
		t.Error("Expected 'permanent' for ErrorCategoryPermanent")
	}
	if errorCategoryString(ErrorCategory(999)) != "unknown" {
		t.Error("Expected 'unknown' for invalid category")
	}
}

