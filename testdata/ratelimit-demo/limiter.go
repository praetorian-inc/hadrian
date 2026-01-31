package main

import (
	"sync"
	"time"
)

// RateLimiter provides in-memory rate limiting with sliding windows
type RateLimiter struct {
	counters map[string]*Counter
	mu       sync.RWMutex
}

// Counter tracks request count and window expiration for a single key
type Counter struct {
	count     int
	windowEnd time.Time
	limit     int
	window    time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		counters: make(map[string]*Counter),
	}
}

// Allow checks if a request should be allowed under the rate limit
// Returns true if allowed, false if rate limited
func (rl *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	counter, exists := rl.counters[key]

	// Initialize counter if it doesn't exist or window has expired
	if !exists || now.After(counter.windowEnd) {
		rl.counters[key] = &Counter{
			count:     1,
			windowEnd: now.Add(window),
			limit:     limit,
			window:    window,
		}
		return true
	}

	// Check if limit exceeded
	if counter.count >= limit {
		return false
	}

	// Increment counter
	counter.count++
	return true
}

// Remaining returns the number of remaining requests before rate limit
func (rl *RateLimiter) Remaining(key string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	counter, exists := rl.counters[key]
	if !exists {
		return 0
	}

	remaining := counter.limit - counter.count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ResetTime returns when the rate limit window will reset
func (rl *RateLimiter) ResetTime(key string) time.Time {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	counter, exists := rl.counters[key]
	if !exists {
		return time.Time{}
	}

	return counter.windowEnd
}

// Reset manually resets the rate limit counter for a key
func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.counters, key)
}
