package runner

import (
	"fmt"
	"net/url"
	"os"
	"time"

	http "github.com/praetorian-inc/hadrian/internal/http"
)

// Validate checks configuration for errors and security issues
func (c *Config) Validate() error {
	// Validate required files exist
	if _, err := os.Stat(c.API); err != nil {
		return fmt.Errorf("API spec file not found: %s", c.API)
	}

	if _, err := os.Stat(c.Roles); err != nil {
		return fmt.Errorf("roles file not found: %s", c.Roles)
	}

	// Validate concurrency limits (HR-1: DoS prevention)
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be ≥1")
	}
	if c.Concurrency > 10 {
		return fmt.Errorf("concurrency limited to 10 (DoS prevention)")
	}

	// Validate proxy URL if provided
	if c.Proxy != "" {
		proxyURL, err := url.Parse(c.Proxy)
		if err != nil {
			return fmt.Errorf("invalid proxy URL: %w", err)
		}
		// Require valid scheme (http or https)
		if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
			return fmt.Errorf("invalid proxy URL: must use http:// or https:// scheme")
		}
	}

	// Validate output format
	validFormats := map[string]bool{"terminal": true, "json": true, "markdown": true}
	if !validFormats[c.Output] {
		return fmt.Errorf("invalid output format: %s (valid: terminal, json, markdown)", c.Output)
	}

	// Validate rate limit configuration
	if c.RateLimit <= 0 {
		return fmt.Errorf("rate limit must be > 0")
	}

	validBackoffTypes := map[string]bool{"exponential": true, "fixed": true}
	if !validBackoffTypes[c.RateLimitBackoff] {
		return fmt.Errorf("invalid rate limit backoff type: %s (valid: exponential, fixed)", c.RateLimitBackoff)
	}

	if c.RateLimitMaxWait <= 0 {
		return fmt.Errorf("rate limit max wait must be > 0")
	}

	if c.RateLimitMaxRetries < 0 {
		return fmt.Errorf("rate limit max retries must be >= 0")
	}

	if len(c.RateLimitStatusCodes) == 0 {
		return fmt.Errorf("rate limit status codes must not be empty")
	}

	return nil
}

// ToHTTPClientConfig converts to HTTP client configuration
func (c *Config) ToHTTPClientConfig() *http.Config {
	return &http.Config{
		Proxy:    c.Proxy,
		CACert:   c.CACert,
		Insecure: c.Insecure,
		Timeout:  time.Duration(c.Timeout) * time.Second,
	}
}
