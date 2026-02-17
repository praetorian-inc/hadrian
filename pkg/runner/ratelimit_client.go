package runner

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// RateLimitingClient wraps an HTTPClient with rate limiting and reactive backoff
type RateLimitingClient struct {
	client  templates.HTTPClient
	limiter *RateLimiter
	config  *RateLimitConfig
}

// NewRateLimitingClient creates a new rate-limiting HTTP client wrapper
func NewRateLimitingClient(client templates.HTTPClient, limiter *RateLimiter, config *RateLimitConfig) *RateLimitingClient {
	if config == nil {
		config = DefaultRateLimitConfig()
	}
	return &RateLimitingClient{
		client:  client,
		limiter: limiter,
		config:  config,
	}
}

// Do executes an HTTP request with proactive rate limiting and reactive backoff
func (c *RateLimitingClient) Do(req *http.Request) (*http.Response, error) {
	if !c.config.Enabled {
		return c.client.Do(req)
	}

	endpoint := req.Method + " " + req.URL.Path

	if err := c.limiter.Wait(req.Context(), endpoint); err != nil {
		return nil, fmt.Errorf("rate limit wait failed: %w", err)
	}

	return c.retryWithBackoff(req, endpoint)
}

// retryWithBackoff executes a request with retry logic for rate limit responses
func (c *RateLimitingClient) retryWithBackoff(req *http.Request, endpoint string) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		resp, err = c.client.Do(req)
		if err != nil {
			return nil, err
		}

		if c.isRateLimited(resp) {
			_ = resp.Body.Close()

			if attempt < c.config.MaxRetries {
				backoff := c.calculateBackoff(attempt, resp)
				log.Debug("Rate limited on %s (attempt %d/%d), backing off for %v",
					endpoint, attempt+1, c.config.MaxRetries, backoff)

				select {
				case <-time.After(backoff):
					continue
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
			}

			// Defensive cleanup before returning error
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			return nil, fmt.Errorf("max retries (%d) exceeded for rate-limited endpoint: %s", c.config.MaxRetries, endpoint)
		}

		return resp, nil
	}

	return resp, nil
}

// isRateLimited checks if the response indicates rate limiting
func (c *RateLimitingClient) isRateLimited(resp *http.Response) bool {
	// Check status code
	for _, code := range c.config.StatusCodes {
		if resp.StatusCode == code {
			log.Debug("Rate limit detected: status code %d", resp.StatusCode)
			return true
		}
	}

	// TODO: Implement body pattern matching if needed
	// This would require reading the response body, which we want to avoid
	// unless absolutely necessary to preserve the body for caller

	return false
}

// calculateBackoff determines the wait time before retry
func (c *RateLimitingClient) calculateBackoff(attempt int, resp *http.Response) time.Duration {
	// Check for Retry-After header first
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		// Try parsing as seconds (integer)
		if seconds, err := strconv.Atoi(retryAfter); err == nil {
			duration := time.Duration(seconds) * time.Second
			// Cap at BackoffMax
			if duration > c.config.BackoffMax {
				return c.config.BackoffMax
			}
			log.Debug("Using Retry-After header: %v", duration)
			return duration
		}

		// Try parsing as HTTP date (RFC1123)
		if retryTime, err := time.Parse(time.RFC1123, retryAfter); err == nil {
			duration := time.Until(retryTime)
			if duration < 0 {
				duration = c.config.BackoffInitial
			}
			// Cap at BackoffMax
			if duration > c.config.BackoffMax {
				return c.config.BackoffMax
			}
			log.Debug("Using Retry-After header (date): %v", duration)
			return duration
		}
	}

	// Calculate backoff based on configuration
	var backoff time.Duration
	switch strings.ToLower(c.config.BackoffType) {
	case "fixed":
		backoff = c.config.BackoffInitial
	case "exponential":
		// Exponential: initial * 2^attempt
		backoff = time.Duration(float64(c.config.BackoffInitial) * math.Pow(2, float64(attempt)))
	default:
		// Default to exponential
		backoff = time.Duration(float64(c.config.BackoffInitial) * math.Pow(2, float64(attempt)))
	}

	// Cap at maximum
	if backoff > c.config.BackoffMax {
		backoff = c.config.BackoffMax
	}

	return backoff
}
