package runner

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitConfig configures rate limiting behavior including reactive backoff
type RateLimitConfig struct {
	Rate           float64       // Requests per second (default 5.0)
	Enabled        bool          // Whether rate limiting is active (default true)
	BackoffType    string        // "exponential" or "fixed" (default "exponential")
	BackoffInitial time.Duration // Initial backoff duration (default 1s)
	BackoffMax     time.Duration // Maximum backoff duration (default 60s)
	MaxRetries     int           // Maximum retry attempts on rate limit (default 5)
	StatusCodes    []int         // HTTP status codes that trigger rate limiting (default [429, 503])
	BodyPatterns   []string      // Optional body patterns to detect rate limiting
}

// DefaultRateLimitConfig returns the default rate limiting configuration
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Rate:           5.0,
		Enabled:        true,
		BackoffType:    "exponential",
		BackoffInitial: 1 * time.Second,
		BackoffMax:     60 * time.Second,
		MaxRetries:     5,
		StatusCodes:    []int{429, 503},
		BodyPatterns:   []string{},
	}
}

// RateLimiter controls request rate to prevent DoS (DoS prevention)
// Provides both global rate limiting and per-endpoint rate limiting
// Thread-safe for concurrent use
type RateLimiter struct {
	globalLimiter    *rate.Limiter
	endpointLimiters map[string]*rate.Limiter
	endpointRate     rate.Limit
	mu               sync.RWMutex
}

// NewRateLimiter creates a new rate limiter with specified rates
// globalRate: maximum requests per second across all endpoints
// endpointRate: maximum requests per second per individual endpoint
func NewRateLimiter(globalRate, endpointRate float64) *RateLimiter {
	return &RateLimiter{
		globalLimiter:    rate.NewLimiter(rate.Limit(globalRate), int(globalRate)*2),
		endpointLimiters: make(map[string]*rate.Limiter),
		endpointRate:     rate.Limit(endpointRate),
	}
}

// Wait blocks until request is allowed (respects both global and endpoint limits)
// Returns error if context is canceled before permission is granted
func (rl *RateLimiter) Wait(ctx context.Context, endpoint string) error {
	// Global rate limit (all endpoints)
	if err := rl.globalLimiter.Wait(ctx); err != nil {
		return err
	}

	// Per-endpoint rate limit
	limiter := rl.getEndpointLimiter(endpoint)
	return limiter.Wait(ctx)
}

// getEndpointLimiter retrieves or creates a rate limiter for the specified endpoint
// Uses double-check locking pattern to prevent race conditions during concurrent access
func (rl *RateLimiter) getEndpointLimiter(endpoint string) *rate.Limiter {
	// Fast path: check if limiter exists with read lock
	rl.mu.RLock()
	limiter, ok := rl.endpointLimiters[endpoint]
	rl.mu.RUnlock()

	if ok {
		return limiter
	}

	// Slow path: create new limiter with write lock
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check: another goroutine might have created it while we waited for write lock
	if limiter, ok := rl.endpointLimiters[endpoint]; ok {
		return limiter
	}

	// Create new limiter for this endpoint
	limiter = rate.NewLimiter(rl.endpointRate, 1)
	rl.endpointLimiters[endpoint] = limiter
	return limiter
}
