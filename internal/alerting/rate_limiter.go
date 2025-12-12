package alerting

import (
	"sync"
	"time"
)

type RateLimiter struct {
	limit     int
	window    time.Duration
	counts    []time.Time
	mu        sync.Mutex
}

func NewRateLimiter(limitPerMinute int) *RateLimiter {
	return &RateLimiter{
		limit:  limitPerMinute,
		window: time.Minute,
		counts: make([]time.Time, 0, limitPerMinute),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	validCounts := make([]time.Time, 0, rl.limit)
	for _, t := range rl.counts {
		if t.After(cutoff) {
			validCounts = append(validCounts, t)
		}
	}
	if len(validCounts) >= rl.limit {
		return false
	}
	validCounts = append(validCounts, now)
	rl.counts = validCounts
	return true
}

func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.counts = make([]time.Time, 0, rl.limit)
}

