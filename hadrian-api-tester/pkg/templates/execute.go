package templates

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/log"
)

// hasUnresolvedPlaceholders checks if a path contains unresolved {placeholder} patterns.
// Returns the first unresolved placeholder name if found, or empty string if all resolved.
func hasUnresolvedPlaceholders(path string) string {
	start := strings.Index(path, "{")
	if start == -1 {
		return ""
	}
	end := strings.Index(path[start:], "}")
	if end == -1 {
		return ""
	}
	return path[start+1 : start+end]
}

// HTTPClient interface for dependency injection
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Executor runs compiled templates against operations
type Executor struct {
	httpClient HTTPClient
	cache      *Cache
}

func NewExecutor(client HTTPClient) *Executor {
	return &Executor{
		httpClient: client,
		cache:      NewCache(1000), // Cache 1000 compiled templates
	}
}

// Execute runs template against operation
func (e *Executor) Execute(
	ctx context.Context,
	tmpl *CompiledTemplate,
	operation *model.Operation,
	authHeader string,
	variables map[string]string,
) (*ExecutionResult, error) {
	result := &ExecutionResult{
		TemplateID: tmpl.ID,
		Operation:  operation,
		Matched:    false,
		Findings:   []model.Finding{},
	}

	// Execute each HTTP test in template
	for _, test := range tmpl.HTTP {
		// Determine repeat count (default 1)
		repeatCount := 1
		if test.Repeat > 0 {
			repeatCount = test.Repeat
		}

		// Track rate limit responses for repeated requests
		rateLimitCount := 0
		backoffExhausted := false
		var lastResp *http.Response
		var lastBody string
		var lastBodyHash string
		var lastBodyBytes []byte

		// Get backoff settings from new Backoff struct
		backoffSecs := 5 // Default 5 second backoff
		maxRetries := 3  // Default max retries
		var backoffStatusCodes []int
		var backoffBodyPatterns []string

		if test.Backoff != nil {
			if test.Backoff.WaitSeconds > 0 {
				backoffSecs = test.Backoff.WaitSeconds
			}
			if test.Backoff.Limit > 0 {
				maxRetries = test.Backoff.Limit
			}
			backoffStatusCodes = test.Backoff.StatusCodes
			backoffBodyPatterns = test.Backoff.BodyPatterns
		}

		// Get rate limit settings from new RateLimit struct
		rateLimitThreshold := 1 // Default: any rate limit response means protected
		var rateLimitStatusCodes []int
		var rateLimitBodyPatterns []string

		if test.RateLimit != nil {
			if test.RateLimit.Threshold > 0 {
				rateLimitThreshold = test.RateLimit.Threshold
			}
			rateLimitStatusCodes = test.RateLimit.StatusCodes
			rateLimitBodyPatterns = test.RateLimit.BodyPatterns
		}

		// Default rate limit status codes if not specified
		if len(rateLimitStatusCodes) == 0 {
			rateLimitStatusCodes = []int{429} // Default to 429 Too Many Requests
		}

		for i := 0; i < repeatCount; i++ {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			// Retry loop for server overwhelm (backoff)
			var resp *http.Response
			var bodyBytes []byte
			var bodyStr string
			serverOverwhelmed := false

			for retry := 0; retry <= maxRetries; retry++ {
				// Build request (must rebuild for each attempt)
				req, err := buildRequest(ctx, test, operation, authHeader, variables)
				if err != nil {
					return nil, fmt.Errorf("failed to build request: %w", err)
				}

				// Execute HTTP request
				resp, err = e.httpClient.Do(req)
				if err != nil {
					return nil, fmt.Errorf("HTTP request failed: %w", err)
				}

				// Read response body
				bodyBytes, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					return nil, fmt.Errorf("failed to read response body: %w", err)
				}
				bodyStr = string(bodyBytes)

				// Check if server is overwhelmed using BACKOFF criteria (separate from rate limit)
				serverOverwhelmed = false
				if len(backoffStatusCodes) > 0 || len(backoffBodyPatterns) > 0 {
					// Check status code match for backoff
					statusMatch := false
					if len(backoffStatusCodes) > 0 {
						for _, code := range backoffStatusCodes {
							if resp.StatusCode == code {
								statusMatch = true
								break
							}
						}
					} else {
						// No status codes specified, only check body patterns
						statusMatch = true
					}

					// Check body pattern match for backoff
					bodyMatch := false
					if len(backoffBodyPatterns) > 0 {
						for _, pattern := range backoffBodyPatterns {
							if strings.Contains(bodyStr, pattern) {
								bodyMatch = true
								break
							}
						}
					} else {
						// No body patterns specified, only check status codes
						bodyMatch = true
					}

					// Server is overwhelmed if both status and body match (when specified)
					if statusMatch && bodyMatch {
						serverOverwhelmed = true
					}
				}

				if serverOverwhelmed && retry < maxRetries {
					// Server overwhelmed - backoff and retry
					log.Info("Backoff triggered (attempt %d/%d), waiting %d seconds...", retry+1, maxRetries, backoffSecs)
					time.Sleep(time.Duration(backoffSecs) * time.Second)
					continue
				}

				// Either not overwhelmed or max retries reached
				break
			}

			// If backoff limit was exhausted (still overwhelmed after all retries), stop the repeat loop
			if serverOverwhelmed {
				log.Info("Backoff limit reached (%d retries exhausted). Stopping requests for this test.", maxRetries)
				backoffExhausted = true
				// Store last response for result reporting
				lastResp = resp
				lastBody = bodyStr
				lastBodyBytes = bodyBytes
				hash := sha256.Sum256(bodyBytes)
				lastBodyHash = fmt.Sprintf("%x", hash)
				break // Stop the entire repeat loop
			}

			// After retries, check if this is a rate limit response (separate from backoff)
			isRateLimited := false
			for _, code := range rateLimitStatusCodes {
				if resp.StatusCode == code {
					// If body patterns specified for rate limit, must also match one of them
					if len(rateLimitBodyPatterns) > 0 {
						for _, pattern := range rateLimitBodyPatterns {
							if strings.Contains(bodyStr, pattern) {
								isRateLimited = true
								break
							}
						}
					} else {
						// No body patterns specified, just status code match
						isRateLimited = true
					}
					break
				}
			}

			if isRateLimited {
				rateLimitCount++
			}

			// Early termination if rate limit threshold reached
			if rateLimitCount >= rateLimitThreshold {
				log.Info("Rate limit detected after %d requests. Endpoint is protected.", i+1)
				// Store response before breaking for result reporting
				lastResp = resp
				lastBody = bodyStr
				lastBodyBytes = bodyBytes
				hash := sha256.Sum256(bodyBytes)
				lastBodyHash = fmt.Sprintf("%x", hash)
				break // Stop sending requests, rate limiting confirmed
			}

			// Store last response for matching
			lastResp = resp
			lastBody = bodyStr
			lastBodyBytes = bodyBytes
			hash := sha256.Sum256(bodyBytes)
			lastBodyHash = fmt.Sprintf("%x", hash)
		}

		// For rate limit tests: check if we hit rate limiting
		if test.Repeat > 0 {
			// Skip vulnerability marking if backoff was exhausted (test inconclusive)
			if backoffExhausted {
				log.Info("Test inconclusive due to server overwhelm. Not marking as vulnerable.")
				continue
			}
			// Vulnerable if we didn't hit rate limiting after N requests
			if rateLimitCount < rateLimitThreshold {
				result.Matched = true
				result.Response = model.HTTPResponse{
					StatusCode: lastResp.StatusCode,
					Headers:    flattenHeaders(lastResp.Header),
					Body:       fmt.Sprintf("Rate limit test: %d requests, %d rate-limited. Threshold: %d", repeatCount, rateLimitCount, rateLimitThreshold),
					BodyHash:   lastBodyHash,
					Size:       len(lastBodyBytes),
					Truncated:  false,
				}
				result.RateLimitInfo = &RateLimitInfo{
					RequestCount:   repeatCount,
					RateLimitCount: rateLimitCount,
					Threshold:      rateLimitThreshold,
				}
			}
		} else {
			// Standard matching for non-rate-limit tests
			matched := evaluateMatchers(tmpl.CompiledMatchers, lastResp, lastBody)

			if matched {
				result.Matched = true
				result.Response = model.HTTPResponse{
					StatusCode: lastResp.StatusCode,
					Headers:    flattenHeaders(lastResp.Header),
					Body:       lastBody,
					BodyHash:   lastBodyHash,
					Size:       len(lastBodyBytes),
					Truncated:  false,
				}
			}
		}
	}

	return result, nil
}

// buildRequest constructs HTTP request with variable substitution
func buildRequest(
	ctx context.Context,
	test HTTPTest,
	operation *model.Operation,
	authHeader string,
	variables map[string]string,
) (*http.Request, error) {
	// Substitute variables in path
	path := test.Path
	if path == "{{operation.path}}" || path == "" {
		path = operation.Path
	}

	// Substitute path parameters
	// Replace both {{key}} (template variables) and {key} (OpenAPI path params)
	if variables != nil {
		for key, value := range variables {
			path = strings.ReplaceAll(path, "{{"+key+"}}", value)
			path = strings.ReplaceAll(path, "{"+key+"}", value)
		}
	}

	// Check for unresolved placeholders - error if any remain
	if placeholder := hasUnresolvedPlaceholders(path); placeholder != "" {
		return nil, fmt.Errorf("unresolved placeholder {%s} in path %q - no variable provided", placeholder, test.Path)
	}

	// Build full URL - prepend baseURL if available
	url := path
	if baseURL, ok := variables["baseURL"]; ok && baseURL != "" && !strings.HasPrefix(path, "http") {
		url = strings.TrimSuffix(baseURL, "/") + path
	}

	// Determine method
	method := test.Method
	if method == "{{operation.method}}" {
		method = operation.Method
	}

	// Build request body
	var bodyReader io.Reader
	if test.Body != "" {
		bodyReader = bytes.NewReader([]byte(test.Body))
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	// Add headers
	for key, value := range test.Headers {
		if value == "Bearer {{attacker_token}}" && authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		} else {
			req.Header.Set(key, value)
		}
	}

	return req, nil
}

// evaluateMatchers runs all matchers and returns if any matched
func evaluateMatchers(matchers []*CompiledMatcher, resp *http.Response, body string) bool {
	for _, matcher := range matchers {
		matched := false

		switch matcher.Type {
		case "word":
			matched = evaluateWordMatcher(matcher, resp, body)
		case "regex":
			matched = evaluateRegexMatcher(matcher, resp, body)
		case "status":
			matched = evaluateStatusMatcher(matcher, resp)
		default:
			continue
		}

		if matched {
			return true
		}
	}

	return false
}

// evaluateWordMatcher checks if words match in response
func evaluateWordMatcher(matcher *CompiledMatcher, resp *http.Response, body string) bool {
	content := getContent(matcher.Part, resp, body)

	matchedCount := 0
	for _, word := range matcher.Words {
		if strings.Contains(content, word) {
			matchedCount++

			if matcher.Condition == "or" {
				return true // Short-circuit on first match
			}
		} else {
			if matcher.Condition == "and" {
				return false // Short-circuit on first non-match
			}
		}
	}

	// AND: all must match, OR: at least one must match
	if matcher.Condition == "and" {
		return matchedCount == len(matcher.Words)
	}
	return matchedCount > 0
}

// evaluateRegexMatcher checks if regex patterns match in response
func evaluateRegexMatcher(matcher *CompiledMatcher, resp *http.Response, body string) bool {
	content := getContent(matcher.Part, resp, body)

	matchedCount := 0
	for _, pattern := range matcher.CompiledRegex {
		if pattern.MatchString(content) {
			matchedCount++

			if matcher.Condition == "or" {
				return true // Short-circuit
			}
		} else {
			if matcher.Condition == "and" {
				return false // Short-circuit
			}
		}
	}

	if matcher.Condition == "and" {
		return matchedCount == len(matcher.CompiledRegex)
	}
	return matchedCount > 0
}

// evaluateStatusMatcher checks if status code matches
func evaluateStatusMatcher(matcher *CompiledMatcher, resp *http.Response) bool {
	for _, status := range matcher.Status {
		if resp.StatusCode == status {
			return true
		}
	}
	return false
}

// getContent extracts content from response based on part specification
func getContent(part string, resp *http.Response, body string) string {
	switch part {
	case "body":
		return body
	case "header":
		return buildHeaderString(resp)
	default: // "all"
		return body + "\n" + buildHeaderString(resp)
	}
}

// buildHeaderString constructs a string representation of HTTP headers
func buildHeaderString(resp *http.Response) string {
	var headers string
	for key, values := range resp.Header {
		headers += key + ": " + strings.Join(values, ", ") + "\n"
	}
	return headers
}

// flattenHeaders converts http.Header to map[string]string
func flattenHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		result[key] = strings.Join(values, ", ")
	}
	return result
}

// ExecutionResult contains the result of template execution
type ExecutionResult struct {
	TemplateID    string
	Operation     *model.Operation
	Matched       bool
	Response      model.HTTPResponse
	Findings      []model.Finding
	RateLimitInfo *RateLimitInfo
}

// RateLimitInfo contains results from rate limit testing
type RateLimitInfo struct {
	RequestCount   int
	RateLimitCount int
	Threshold      int
}
