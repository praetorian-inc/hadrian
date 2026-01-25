package runner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRateLimiter verifies constructor creates rate limiter with correct configuration
func TestNewRateLimiter(t *testing.T) {
	globalRate := 10.0
	endpointRate := 1.0

	rl := NewRateLimiter(globalRate, endpointRate)

	require.NotNil(t, rl, "NewRateLimiter should return non-nil instance")
	assert.NotNil(t, rl.globalLimiter, "global limiter should be initialized")
	assert.NotNil(t, rl.endpointLimiters, "endpoint limiters map should be initialized")
	assert.Empty(t, rl.endpointLimiters, "endpoint limiters map should start empty")
}

// TestRateLimiter_GlobalLimit verifies global rate limiting is enforced
func TestRateLimiter_GlobalLimit(t *testing.T) {
	globalRate := 10.0 // 10 req/s
	endpointRate := 100.0

	rl := NewRateLimiter(globalRate, endpointRate)
	ctx := context.Background()
	endpoint := "/api/test"

	// Consume burst allowance first (burst is 2x rate = 20 tokens)
	for i := 0; i < 20; i++ {
		err := rl.Wait(ctx, endpoint)
		require.NoError(t, err)
	}

	// Now measure time for next 10 requests (should be rate limited)
	start := time.Now()
	for i := 0; i < 10; i++ {
		err := rl.Wait(ctx, endpoint)
		require.NoError(t, err, "Wait should not return error")
	}
	elapsed := time.Since(start)

	// Global rate of 10 req/s means 10 requests should take >= 700ms
	// (allowing 300ms tolerance for test execution overhead and scheduler variance)
	assert.GreaterOrEqual(t, elapsed, 700*time.Millisecond, "global rate limit should enforce timing")
}

// TestRateLimiter_EndpointLimit verifies per-endpoint rate limiting
func TestRateLimiter_EndpointLimit(t *testing.T) {
	globalRate := 100.0 // High global limit (won't be hit)
	endpointRate := 2.0 // 2 req/s per endpoint

	rl := NewRateLimiter(globalRate, endpointRate)
	ctx := context.Background()
	endpoint := "/api/limited"

	// First request should be immediate
	start := time.Now()
	err := rl.Wait(ctx, endpoint)
	require.NoError(t, err)
	firstElapsed := time.Since(start)
	assert.Less(t, firstElapsed, 100*time.Millisecond, "first request should be immediate")

	// Second request should wait ~500ms (rate is 2 req/s)
	start = time.Now()
	err = rl.Wait(ctx, endpoint)
	require.NoError(t, err)
	secondElapsed := time.Since(start)
	assert.GreaterOrEqual(t, secondElapsed, 400*time.Millisecond, "second request should be rate limited")
}

// TestRateLimiter_ConcurrentEndpoints verifies multiple endpoints don't interfere
func TestRateLimiter_ConcurrentEndpoints(t *testing.T) {
	globalRate := 100.0 // High global limit
	endpointRate := 1.0 // 1 req/s per endpoint

	rl := NewRateLimiter(globalRate, endpointRate)
	ctx := context.Background()

	var wg sync.WaitGroup
	endpoints := []string{"/api/endpoint1", "/api/endpoint2", "/api/endpoint3"}

	// Each endpoint should have independent rate limiting
	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			for i := 0; i < 3; i++ {
				err := rl.Wait(ctx, ep)
				assert.NoError(t, err, "Wait should not error for endpoint %s", ep)
			}
		}(endpoint)
	}

	wg.Wait()

	// Verify all 3 endpoints have limiters
	rl.mu.RLock()
	assert.Len(t, rl.endpointLimiters, 3, "should create limiter for each endpoint")
	rl.mu.RUnlock()
}

// TestRateLimiter_ContextCancellation verifies context cancellation is respected
func TestRateLimiter_ContextCancellation(t *testing.T) {
	globalRate := 1.0 // Very slow rate to ensure we hit timeout
	endpointRate := 1.0

	rl := NewRateLimiter(globalRate, endpointRate)
	endpoint := "/api/test"

	// Consume burst allowance first (burst is 2x rate = 2 tokens)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		err := rl.Wait(ctx, endpoint)
		require.NoError(t, err)
	}

	// Create context with short timeout for next request
	ctxTimeout, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Next request should hit context timeout (rate is 1 req/s, so would wait 1s)
	err := rl.Wait(ctxTimeout, endpoint)
	assert.Error(t, err, "Wait should return error when context cancelled")
	assert.Contains(t, err.Error(), "context deadline", "error should indicate context timeout")
}

// TestGetEndpointLimiter_ThreadSafe verifies concurrent access to getEndpointLimiter is safe
func TestGetEndpointLimiter_ThreadSafe(t *testing.T) {
	globalRate := 100.0
	endpointRate := 10.0

	rl := NewRateLimiter(globalRate, endpointRate)
	endpoint := "/api/concurrent"

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent access to same endpoint - should create exactly one limiter
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limiter := rl.getEndpointLimiter(endpoint)
			assert.NotNil(t, limiter, "limiter should not be nil")
		}()
	}

	wg.Wait()

	// Verify only one limiter was created
	rl.mu.RLock()
	assert.Len(t, rl.endpointLimiters, 1, "only one limiter should be created despite concurrent access")
	rl.mu.RUnlock()
}

// TestRateLimiter_DoubleCheckLocking verifies race condition prevention in limiter creation
func TestRateLimiter_DoubleCheckLocking(t *testing.T) {
	globalRate := 100.0
	endpointRate := 10.0

	rl := NewRateLimiter(globalRate, endpointRate)
	endpoint := "/api/race"

	var wg sync.WaitGroup
	numGoroutines := 100

	// High concurrency test - double-check locking should prevent race
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			err := rl.Wait(ctx, endpoint)
			assert.NoError(t, err)
		}()
	}

	wg.Wait()

	// Verify exactly one limiter exists
	rl.mu.RLock()
	count := len(rl.endpointLimiters)
	rl.mu.RUnlock()

	assert.Equal(t, 1, count, "race condition in limiter creation - multiple limiters created")
}
