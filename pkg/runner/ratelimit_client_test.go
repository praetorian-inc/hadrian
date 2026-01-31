package runner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHTTPClient simulates an HTTP client for testing
type mockHTTPClient struct {
	responses []*http.Response
	errors    []error
	callCount int
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.callCount >= len(m.responses) {
		return nil, io.EOF
	}

	resp := m.responses[m.callCount]
	var err error
	if m.callCount < len(m.errors) {
		err = m.errors[m.callCount]
	}
	m.callCount++

	return resp, err
}

// makeResponse creates a test HTTP response
func makeResponse(statusCode int, body string, headers map[string]string) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	return resp
}

func TestRateLimitingClient_ProactiveRateLimiting(t *testing.T) {
	// Test that proactive rate limiting respects configured rate
	config := &RateLimitConfig{
		Rate:           10.0, // 10 req/s
		Enabled:        true,
		BackoffType:    "exponential",
		BackoffInitial: 100 * time.Millisecond,
		BackoffMax:     1 * time.Second,
		MaxRetries:     3,
		StatusCodes:    []int{429, 503},
	}

	limiter := NewRateLimiter(config.Rate, config.Rate)
	mockClient := &mockHTTPClient{
		responses: []*http.Response{
			makeResponse(200, "OK", nil),
			makeResponse(200, "OK", nil),
			makeResponse(200, "OK", nil),
		},
	}

	client := NewRateLimitingClient(mockClient, limiter, config)

	// Make requests and measure timing
	start := time.Now()
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		resp.Body.Close()
	}
	elapsed := time.Since(start)

	// With 10 req/s, 3 requests should take at least 200ms (spacing between requests)
	// Allow some tolerance for timing precision
	assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(150), "Rate limiting should delay requests")
}

func TestRateLimitingClient_ExponentialBackoff(t *testing.T) {
	config := &RateLimitConfig{
		Rate:           10.0,
		Enabled:        true,
		BackoffType:    "exponential",
		BackoffInitial: 100 * time.Millisecond,
		BackoffMax:     1 * time.Second,
		MaxRetries:     3,
		StatusCodes:    []int{429},
	}

	limiter := NewRateLimiter(config.Rate, config.Rate)
	mockClient := &mockHTTPClient{
		responses: []*http.Response{
			makeResponse(429, "Rate limited", nil),
			makeResponse(429, "Rate limited", nil),
			makeResponse(200, "OK", nil),
		},
	}

	client := NewRateLimitingClient(mockClient, limiter, config)

	start := time.Now()
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Exponential backoff: 100ms (attempt 0) + 200ms (attempt 1) = 300ms minimum
	assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(250), "Exponential backoff should double wait time")
	assert.Equal(t, 3, mockClient.callCount, "Should make 3 attempts")
}

func TestRateLimitingClient_FixedBackoff(t *testing.T) {
	config := &RateLimitConfig{
		Rate:           10.0,
		Enabled:        true,
		BackoffType:    "fixed",
		BackoffInitial: 100 * time.Millisecond,
		BackoffMax:     1 * time.Second,
		MaxRetries:     3,
		StatusCodes:    []int{429},
	}

	limiter := NewRateLimiter(config.Rate, config.Rate)
	mockClient := &mockHTTPClient{
		responses: []*http.Response{
			makeResponse(429, "Rate limited", nil),
			makeResponse(429, "Rate limited", nil),
			makeResponse(200, "OK", nil),
		},
	}

	client := NewRateLimitingClient(mockClient, limiter, config)

	start := time.Now()
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Fixed backoff: 100ms * 2 retries = 200ms minimum
	assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(150), "Fixed backoff should use constant wait time")
	assert.Equal(t, 3, mockClient.callCount, "Should make 3 attempts")
}

func TestRateLimitingClient_MaxRetriesExceeded(t *testing.T) {
	config := &RateLimitConfig{
		Rate:           10.0,
		Enabled:        true,
		BackoffType:    "exponential",
		BackoffInitial: 10 * time.Millisecond, // Short for fast test
		BackoffMax:     100 * time.Millisecond,
		MaxRetries:     2,
		StatusCodes:    []int{429},
	}

	limiter := NewRateLimiter(config.Rate, config.Rate)
	mockClient := &mockHTTPClient{
		responses: []*http.Response{
			makeResponse(429, "Rate limited", nil),
			makeResponse(429, "Rate limited", nil),
			makeResponse(429, "Rate limited", nil),
			makeResponse(200, "OK", nil), // Should not reach this
		},
	}

	client := NewRateLimitingClient(mockClient, limiter, config)

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	resp, err := client.Do(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "max retries")
	assert.Equal(t, 3, mockClient.callCount, "Should make MaxRetries+1 attempts")
}

func TestRateLimitingClient_RetryAfterHeader(t *testing.T) {
	config := &RateLimitConfig{
		Rate:           10.0,
		Enabled:        true,
		BackoffType:    "exponential",
		BackoffInitial: 100 * time.Millisecond,
		BackoffMax:     5 * time.Second,
		MaxRetries:     2,
		StatusCodes:    []int{429},
	}

	limiter := NewRateLimiter(config.Rate, config.Rate)

	t.Run("Retry-After as seconds", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			responses: []*http.Response{
				makeResponse(429, "Rate limited", map[string]string{"Retry-After": "1"}),
				makeResponse(200, "OK", nil),
			},
		}

		client := NewRateLimitingClient(mockClient, limiter, config)

		start := time.Now()
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		resp, err := client.Do(req)
		elapsed := time.Since(start)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()

		// Should respect Retry-After: 1 second
		assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(900), "Should honor Retry-After header")
	})
}

func TestRateLimitingClient_ContextCancellation(t *testing.T) {
	config := &RateLimitConfig{
		Rate:           10.0,
		Enabled:        true,
		BackoffType:    "exponential",
		BackoffInitial: 500 * time.Millisecond,
		BackoffMax:     5 * time.Second,
		MaxRetries:     5,
		StatusCodes:    []int{429},
	}

	limiter := NewRateLimiter(config.Rate, config.Rate)
	mockClient := &mockHTTPClient{
		responses: []*http.Response{
			makeResponse(429, "Rate limited", nil),
			makeResponse(429, "Rate limited", nil),
			makeResponse(200, "OK", nil),
		},
	}

	client := NewRateLimitingClient(mockClient, limiter, config)

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com/test", nil)
	resp, err := client.Do(req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestRateLimitingClient_MultipleStatusCodes(t *testing.T) {
	config := &RateLimitConfig{
		Rate:           10.0,
		Enabled:        true,
		BackoffType:    "fixed",
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     1 * time.Second,
		MaxRetries:     3,
		StatusCodes:    []int{429, 503}, // Both 429 and 503 should trigger retry
	}

	limiter := NewRateLimiter(config.Rate, config.Rate)

	t.Run("Status 429", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			responses: []*http.Response{
				makeResponse(429, "Too Many Requests", nil),
				makeResponse(200, "OK", nil),
			},
		}

		client := NewRateLimitingClient(mockClient, limiter, config)
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		resp, err := client.Do(req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("Status 503", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			responses: []*http.Response{
				makeResponse(503, "Service Unavailable", nil),
				makeResponse(200, "OK", nil),
			},
		}

		client := NewRateLimitingClient(mockClient, limiter, config)
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		resp, err := client.Do(req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestRateLimitingClient_DisabledRateLimiting(t *testing.T) {
	config := &RateLimitConfig{
		Rate:           10.0,
		Enabled:        false, // Rate limiting disabled
		BackoffType:    "exponential",
		BackoffInitial: 100 * time.Millisecond,
		BackoffMax:     1 * time.Second,
		MaxRetries:     3,
		StatusCodes:    []int{429},
	}

	limiter := NewRateLimiter(config.Rate, config.Rate)
	mockClient := &mockHTTPClient{
		responses: []*http.Response{
			makeResponse(429, "Rate limited", nil), // Should not retry when disabled
		},
	}

	client := NewRateLimitingClient(mockClient, limiter, config)

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	resp, err := client.Do(req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 429, resp.StatusCode) // Should return 429 without retrying
	resp.Body.Close()
	assert.Equal(t, 1, mockClient.callCount, "Should only make 1 attempt when disabled")
}

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()

	assert.Equal(t, 5.0, config.Rate)
	assert.True(t, config.Enabled)
	assert.Equal(t, "exponential", config.BackoffType)
	assert.Equal(t, 1*time.Second, config.BackoffInitial)
	assert.Equal(t, 60*time.Second, config.BackoffMax)
	assert.Equal(t, 5, config.MaxRetries)
	assert.Equal(t, []int{429, 503}, config.StatusCodes)
	assert.Empty(t, config.BodyPatterns)
}
