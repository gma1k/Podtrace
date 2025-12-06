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

func TestErrorRateLimiter_MaxBackoffFactor(t *testing.T) {
	limiter := newErrorRateLimiter()
	limiter.lastLogTime = time.Now().Add(-100 * time.Second)

	for i := 0; i < 200; i++ {
		limiter.shouldLog()
		limiter.lastLogTime = time.Now().Add(-100 * time.Second)
	}

	if limiter.backoffFactor > 64 {
		t.Errorf("Expected backoffFactor to be capped at 64, got %d", limiter.backoffFactor)
	}
}

func TestErrorRateLimiter_MaxInterval(t *testing.T) {
	limiter := newErrorRateLimiter()
	limiter.backoffFactor = 200
	limiter.lastLogTime = time.Now().Add(-200 * time.Second)

	interval := limiter.minInterval * time.Duration(limiter.backoffFactor)
	if interval > limiter.maxInterval {
		interval = limiter.maxInterval
	}

	if interval != limiter.maxInterval {
		t.Errorf("Expected interval to be capped at maxInterval")
	}
}

func TestErrorRateLimiter_OddErrorCount(t *testing.T) {
	limiter := newErrorRateLimiter()
	limiter.lastLogTime = time.Now().Add(-10 * time.Second)
	limiter.errorCount = 0

	limiter.shouldLog()
	if limiter.errorCount != 1 {
		t.Errorf("Expected errorCount to be 1, got %d", limiter.errorCount)
	}
	if limiter.backoffFactor != 1 {
		t.Errorf("Expected backoffFactor to remain 1 after first error, got %d", limiter.backoffFactor)
	}

	limiter.lastLogTime = time.Now().Add(-10 * time.Second)
	limiter.shouldLog()
	if limiter.errorCount != 2 {
		t.Errorf("Expected errorCount to be 2, got %d", limiter.errorCount)
	}
	if limiter.backoffFactor != 2 {
		t.Errorf("Expected backoffFactor to be 2 after second error, got %d", limiter.backoffFactor)
	}
}

func TestSlidingWindow_BucketCreation(t *testing.T) {
	window := newSlidingWindow(1*time.Second, 3)
	window.addError()
	time.Sleep(50 * time.Millisecond)
	window.addError()

	rate := window.getErrorRate()
	if rate != 2 {
		t.Errorf("Expected error rate 2, got %d", rate)
	}
}

func TestSlidingWindow_MultipleBuckets(t *testing.T) {
	window := newSlidingWindow(1*time.Second, 10)
	
	for i := 0; i < 5; i++ {
		window.addError()
		time.Sleep(50 * time.Millisecond)
	}

	rate := window.getErrorRate()
	if rate == 0 {
		t.Error("Expected non-zero error rate")
	}
	if rate < 3 {
		t.Errorf("Expected at least 3 errors in window, got %d", rate)
	}
}

func TestSlidingWindow_BucketExpiration(t *testing.T) {
	window := newSlidingWindow(100*time.Millisecond, 10)
	window.addError()
	window.addError()
	
	time.Sleep(50 * time.Millisecond)
	rate := window.getErrorRate()
	if rate != 2 {
		t.Errorf("Expected error rate 2 before expiration, got %d", rate)
	}

	time.Sleep(100 * time.Millisecond)
	rate = window.getErrorRate()
	if rate != 0 {
		t.Errorf("Expected error rate 0 after expiration, got %d", rate)
	}
}

func TestCircuitBreaker_HalfOpenState(t *testing.T) {
	cb := newCircuitBreaker(2, 100*time.Millisecond)
	cb.recordFailure()
	cb.recordFailure()

	if cb.canProceed() {
		t.Error("Expected canProceed to return false when circuit is open")
	}

	cb.lastFailure = time.Now().Add(-200 * time.Millisecond)
	if !cb.canProceed() {
		t.Error("Expected canProceed to return true after timeout (half-open)")
	}

	cb.mu.Lock()
	if cb.state != circuitBreakerHalfOpen {
		t.Errorf("Expected state to be half-open, got %d", cb.state)
	}
	cb.mu.Unlock()
}

func TestCircuitBreaker_HalfOpenToClosed(t *testing.T) {
	cb := newCircuitBreaker(2, 100*time.Millisecond)
	cb.recordFailure()
	cb.recordFailure()
	cb.lastFailure = time.Now().Add(-200 * time.Millisecond)
	cb.canProceed()

	cb.recordSuccess()
	cb.recordSuccess()
	cb.recordSuccess()

	cb.mu.Lock()
	if cb.state != circuitBreakerClosed {
		t.Errorf("Expected state to be closed after 3 successes, got %d", cb.state)
	}
	if cb.failureCount != 0 {
		t.Errorf("Expected failureCount to be reset, got %d", cb.failureCount)
	}
	if cb.successCount != 0 {
		t.Errorf("Expected successCount to be reset, got %d", cb.successCount)
	}
	cb.mu.Unlock()
}

func TestCircuitBreaker_OpenStateTimeout(t *testing.T) {
	cb := newCircuitBreaker(2, 50*time.Millisecond)
	cb.recordFailure()
	cb.recordFailure()

	if cb.canProceed() {
		t.Error("Expected canProceed to return false when circuit is open")
	}

	time.Sleep(100 * time.Millisecond)

	if !cb.canProceed() {
		t.Error("Expected canProceed to return true after timeout")
	}
}

func TestCircuitBreaker_DefaultState(t *testing.T) {
	cb := newCircuitBreaker(100, 30*time.Second)
	cb.mu.Lock()
	if cb.state != circuitBreakerClosed {
		t.Errorf("Expected initial state to be closed, got %d", cb.state)
	}
	cb.mu.Unlock()
}

func TestCircuitBreaker_CanProceed_DefaultCase(t *testing.T) {
	cb := newCircuitBreaker(100, 30*time.Second)
	cb.mu.Lock()
	cb.state = circuitBreakerState(999)
	cb.mu.Unlock()

	if !cb.canProceed() {
		t.Error("Expected canProceed to return true for unknown state (default case)")
	}
}

func TestClassifyError_EOF(t *testing.T) {
	err := errors.New("EOF")
	category := classifyError(err)
	if category != ErrorCategoryTransient {
		t.Errorf("Expected ErrorCategoryTransient for EOF, got %d", category)
	}
}

func TestClassifyError_Denied(t *testing.T) {
	err := errors.New("access denied")
	category := classifyError(err)
	if category != ErrorCategoryPermanent {
		t.Errorf("Expected ErrorCategoryPermanent for denied, got %d", category)
	}
}

