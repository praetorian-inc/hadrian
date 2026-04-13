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
	c.setDefaults()

	// Validate required files exist
	if _, err := os.Stat(c.API); err != nil {
		return fmt.Errorf("API spec file not found: %s", c.API)
	}

	if _, err := os.Stat(c.Roles); err != nil {
		return fmt.Errorf("roles file not found: %s", c.Roles)
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

	// Validate planner flags
	if c.PlannerOnly && !c.PlannerEnabled {
		return fmt.Errorf("--planner-only requires --planner to be set")
	}

	// Validate custom headers format
	if len(c.Headers) > 0 {
		if _, err := ParseCustomHeaders(c.Headers); err != nil {
			return err
		}
	}
	return nil
}

// setDefaults fills zero-valued fields with sensible defaults for library usage.
// When hadrian is invoked via CLI, cobra flags provide these defaults; for
// direct library callers the fields may be unset.
func (c *Config) setDefaults() {
	if c.Output == "" {
		c.Output = "json"
	}
	if c.RateLimit <= 0 {
		c.RateLimit = 5.0
	}
	if c.RateLimitBackoff == "" {
		c.RateLimitBackoff = "exponential"
	}
	if c.RateLimitMaxWait <= 0 {
		c.RateLimitMaxWait = 60 * time.Second
	}
	if c.RateLimitMaxRetries <= 0 {
		c.RateLimitMaxRetries = 5
	}
	if len(c.RateLimitStatusCodes) == 0 {
		c.RateLimitStatusCodes = []int{429, 503}
	}
	if c.Timeout <= 0 {
		c.Timeout = 30
	}
	if c.PlannerTimeout <= 0 {
		c.PlannerTimeout = 120
	}
	if len(c.Categories) == 0 {
		c.Categories = []string{"owasp"}
	}
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
