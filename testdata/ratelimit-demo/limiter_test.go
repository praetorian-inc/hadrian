package main

import (
	"testing"
	"time"
)

// TestNewRateLimiter verifies rate limiter initialization
func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter()
	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}
	if rl.counters == nil {
		t.Error("counters map not initialized")
	}
}

// TestAllow_FirstRequest verifies first request is always allowed
func TestAllow_FirstRequest(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-endpoint"
	limit := 5
	window := 60 * time.Second

	allowed := rl.Allow(key, limit, window)
	if !allowed {
		t.Error("first request should be allowed")
	}
}

// TestAllow_WithinLimit verifies requests within limit are allowed
func TestAllow_WithinLimit(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-endpoint"
	limit := 3
	window := 60 * time.Second

	// Make 3 requests (within limit)
	for i := 0; i < 3; i++ {
		if !rl.Allow(key, limit, window) {
			t.Errorf("request %d should be allowed (within limit of %d)", i+1, limit)
		}
	}
}

// TestAllow_ExceedsLimit verifies requests exceeding limit are denied
func TestAllow_ExceedsLimit(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-endpoint"
	limit := 3
	window := 60 * time.Second

	// Make 3 requests (within limit)
	for i := 0; i < 3; i++ {
		rl.Allow(key, limit, window)
	}

	// 4th request should be denied
	allowed := rl.Allow(key, limit, window)
	if allowed {
		t.Error("request exceeding limit should be denied")
	}
}

// TestAllow_WindowExpires verifies counter resets after window expiration
func TestAllow_WindowExpires(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-endpoint"
	limit := 2
	window := 100 * time.Millisecond

	// Exhaust limit
	rl.Allow(key, limit, window)
	rl.Allow(key, limit, window)

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Next request should be allowed (window reset)
	allowed := rl.Allow(key, limit, window)
	if !allowed {
		t.Error("request after window expiration should be allowed")
	}
}

// TestAllow_IndependentKeys verifies different keys have independent counters
func TestAllow_IndependentKeys(t *testing.T) {
	rl := NewRateLimiter()
	limit := 2
	window := 60 * time.Second

	// Exhaust limit for key1
	rl.Allow("key1", limit, window)
	rl.Allow("key1", limit, window)

	// key2 should still be allowed
	allowed := rl.Allow("key2", limit, window)
	if !allowed {
		t.Error("different key should have independent counter")
	}
}

// TestRemaining_ZeroWhenExhausted verifies remaining returns 0 when limit exhausted
func TestRemaining_ZeroWhenExhausted(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-endpoint"
	limit := 3
	window := 60 * time.Second

	// Exhaust limit
	for i := 0; i < 3; i++ {
		rl.Allow(key, limit, window)
	}

	remaining := rl.Remaining(key)
	if remaining != 0 {
		t.Errorf("expected remaining=0, got %d", remaining)
	}
}

// TestRemaining_DecreasesWithUse verifies remaining counter decreases
func TestRemaining_DecreasesWithUse(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-endpoint"
	limit := 5
	window := 60 * time.Second

	// Make 2 requests
	rl.Allow(key, limit, window)
	rl.Allow(key, limit, window)

	remaining := rl.Remaining(key)
	if remaining != 3 {
		t.Errorf("expected remaining=3, got %d", remaining)
	}
}

// TestResetTime_ReturnsWindowEnd verifies reset time calculation
func TestResetTime_ReturnsWindowEnd(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-endpoint"
	limit := 5
	window := 60 * time.Second

	before := time.Now()
	rl.Allow(key, limit, window)
	resetTime := rl.ResetTime(key)
	after := time.Now()

	// Reset time should be approximately now + window
	expectedMin := before.Add(window)
	expectedMax := after.Add(window)

	if resetTime.Before(expectedMin) || resetTime.After(expectedMax) {
		t.Errorf("reset time %v outside expected range [%v, %v]", resetTime, expectedMin, expectedMax)
	}
}

// TestReset_ClearsCounter verifies manual counter reset
func TestReset_ClearsCounter(t *testing.T) {
	rl := NewRateLimiter()
	key := "test-endpoint"
	limit := 2
	window := 60 * time.Second

	// Exhaust limit
	rl.Allow(key, limit, window)
	rl.Allow(key, limit, window)

	// Reset counter
	rl.Reset(key)

	// Next request should be allowed
	allowed := rl.Allow(key, limit, window)
	if !allowed {
		t.Error("request after reset should be allowed")
	}
}
