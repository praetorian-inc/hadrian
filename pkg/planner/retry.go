package planner

import (
	"context"
	"errors"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/log"
)

// APIError wraps an HTTP error with a status code for retry classification.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return e.Message
}

// retryableStatusCodes are HTTP status codes worth retrying.
var retryableStatusCodes = map[int]bool{
	408: true, // Request Timeout
	429: true, // Too Many Requests
	500: true, // Internal Server Error
	502: true, // Bad Gateway
	503: true, // Service Unavailable
	504: true, // Gateway Timeout
}

// isRetryable returns true if the error is transient and worth retrying.
// Network errors (no status code) are retryable. Permanent HTTP errors (401, 403) are not.
func isRetryable(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return retryableStatusCodes[apiErr.StatusCode]
	}
	// Network errors (connection refused, timeout, DNS) — retryable
	return true
}

// retryBackoffs defines the wait times between retries (exponential: 2s, 8s, 30s).
var retryBackoffs = []time.Duration{2 * time.Second, 8 * time.Second, 30 * time.Second}

// RetryGenerate wraps an LLMClient.Generate call with retry logic.
// Only retries on transient errors (429, 5xx, network). Permanent errors (401, 403) fail immediately.
func RetryGenerate(ctx context.Context, client LLMClient, prompt string) (string, error) {
	var lastErr error
	for attempt := 0; attempt <= len(retryBackoffs); attempt++ {
		result, err := client.Generate(ctx, prompt)
		if err == nil {
			return result, nil
		}
		lastErr = err

		if ctx.Err() != nil {
			return "", lastErr
		}

		if !isRetryable(err) {
			return "", err
		}

		if attempt >= len(retryBackoffs) {
			break
		}

		log.Warn("LLM request failed (attempt %d/%d): %v — retrying in %s",
			attempt+1, len(retryBackoffs)+1, err, retryBackoffs[attempt])

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(retryBackoffs[attempt]):
		}
	}
	return "", lastErr
}
