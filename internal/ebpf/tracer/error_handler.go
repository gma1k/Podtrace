package tracer

import (
	"strings"
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/config"
)

type ErrorCategory int

const (
	ErrorCategoryTransient ErrorCategory = iota + 1
	ErrorCategoryRecoverable
	ErrorCategoryPermanent
)

type errorRateLimiter struct {
	errorCount    int
	lastLogTime   time.Time
	backoffFactor int
	minInterval   time.Duration
	maxInterval   time.Duration
	mu            sync.Mutex
}

func newErrorRateLimiter() *errorRateLimiter {
	return &errorRateLimiter{
		backoffFactor: 1,
		minInterval:   config.DefaultErrorBackoffMinInterval,
		maxInterval:   config.DefaultErrorBackoffMaxInterval,
		lastLogTime:   time.Now(),
	}
}

func (erl *errorRateLimiter) shouldLog() bool {
	erl.mu.Lock()
	defer erl.mu.Unlock()

	now := time.Now()
	interval := erl.minInterval * time.Duration(erl.backoffFactor)
	if interval > erl.maxInterval {
		interval = erl.maxInterval
	}

	if now.Sub(erl.lastLogTime) < interval {
		return false
	}

	erl.lastLogTime = now
	erl.errorCount++
	if erl.errorCount%2 == 0 {
		erl.backoffFactor *= 2
		if erl.backoffFactor > 64 {
			erl.backoffFactor = 64
		}
	}
	return true
}

type timeBucket struct {
	count     int
	timestamp time.Time
}

type slidingWindow struct {
	buckets []timeBucket
	window  time.Duration
	mu      sync.Mutex
}

func newSlidingWindow(window time.Duration, numBuckets int) *slidingWindow {
	return &slidingWindow{
		buckets: make([]timeBucket, 0, numBuckets),
		window:  window,
	}
}

func (sw *slidingWindow) addError() {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-sw.window)

	var validBuckets []timeBucket
	for _, bucket := range sw.buckets {
		if bucket.timestamp.After(cutoff) {
			validBuckets = append(validBuckets, bucket)
		}
	}

	if len(validBuckets) == 0 || now.Sub(validBuckets[len(validBuckets)-1].timestamp) >= sw.window/time.Duration(cap(sw.buckets)) {
		validBuckets = append(validBuckets, timeBucket{
			count:     1,
			timestamp: now,
		})
	} else {
		validBuckets[len(validBuckets)-1].count++
	}

	sw.buckets = validBuckets
}

func (sw *slidingWindow) getErrorRate() int {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-sw.window)
	total := 0

	for _, bucket := range sw.buckets {
		if bucket.timestamp.After(cutoff) {
			total += bucket.count
		}
	}

	return total
}

type circuitBreakerState int

const (
	circuitBreakerClosed circuitBreakerState = iota
	circuitBreakerOpen
	circuitBreakerHalfOpen
)

type circuitBreaker struct {
	state         circuitBreakerState
	failureCount  int
	lastFailure   time.Time
	threshold     int
	timeout       time.Duration
	successCount  int
	mu            sync.Mutex
}

func newCircuitBreaker(threshold int, timeout time.Duration) *circuitBreaker {
	return &circuitBreaker{
		state:    circuitBreakerClosed,
		threshold: threshold,
		timeout:   timeout,
	}
}

func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount++
	cb.lastFailure = time.Now()

	if cb.state == circuitBreakerClosed && cb.failureCount >= cb.threshold {
		cb.state = circuitBreakerOpen
	}
}

func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.successCount++
	if cb.state == circuitBreakerHalfOpen && cb.successCount >= 3 {
		cb.state = circuitBreakerClosed
		cb.failureCount = 0
		cb.successCount = 0
	}
}

func (cb *circuitBreaker) canProceed() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case circuitBreakerClosed:
		return true
	case circuitBreakerOpen:
		if now.Sub(cb.lastFailure) >= cb.timeout {
			cb.state = circuitBreakerHalfOpen
			cb.successCount = 0
			return true
		}
		return false
	case circuitBreakerHalfOpen:
		return true
	default:
		return true
	}
}

func classifyError(err error) ErrorCategory {
	if err == nil {
		return ErrorCategoryTransient
	}

	errStr := err.Error()
	if strings.Contains(errStr, "EAGAIN") || strings.Contains(errStr, "temporary") {
		return ErrorCategoryTransient
	}
	if strings.Contains(errStr, "permission") || strings.Contains(errStr, "denied") {
		return ErrorCategoryPermanent
	}
	if strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF") {
		return ErrorCategoryTransient
	}

	return ErrorCategoryRecoverable
}

func errorCategoryString(category ErrorCategory) string {
	switch category {
	case ErrorCategoryTransient:
		return "transient"
	case ErrorCategoryRecoverable:
		return "recoverable"
	case ErrorCategoryPermanent:
		return "permanent"
	default:
		return "unknown"
	}
}

