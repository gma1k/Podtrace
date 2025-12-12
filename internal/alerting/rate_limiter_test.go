package alerting

import (
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(5)
	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}
	if rl.Allow() {
		t.Error("Request 6 should not be allowed (rate limit exceeded)")
	}
}

func TestRateLimiter_Allow_TimeWindow(t *testing.T) {
	rl := NewRateLimiter(2)
	if !rl.Allow() {
		t.Error("First request should be allowed")
	}
	if !rl.Allow() {
		t.Error("Second request should be allowed")
	}
	if rl.Allow() {
		t.Error("Third request should not be allowed")
	}
	time.Sleep(61 * time.Second)
	if !rl.Allow() {
		t.Error("Request after window should be allowed")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(2)
	rl.Allow()
	rl.Allow()
	if rl.Allow() {
		t.Error("Request should not be allowed after limit")
	}
	rl.Reset()
	if !rl.Allow() {
		t.Error("Request should be allowed after reset")
	}
}

