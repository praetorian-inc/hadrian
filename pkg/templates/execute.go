package templates

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/oob"
	"github.com/praetorian-inc/hadrian/pkg/util"
)

// generateRequestID creates a random UUID-style request ID
func generateRequestID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to a simple hex string if crypto/rand fails
		return hex.EncodeToString(b)
	}

	// Format as UUID (8-4-4-4-12)
	return hex.EncodeToString(b[0:4]) + "-" +
		hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" +
		hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16])
}

// substituteInteractsh replaces {{interactsh}} placeholder with OOB URL
func substituteInteractsh(query string, oobURL string) string {
	if oobURL == "" {
		return query
	}
	return strings.ReplaceAll(query, "{{interactsh}}", oobURL)
}


// HTTPClient interface for dependency injection
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// AuthInfo contains authentication configuration for template execution
type AuthInfo struct {
	Method   string // bearer, api_key, basic
	Location string // header, query (for api_key)
	KeyName  string // Header name (e.g., X-API-Key) or query parameter name
	Value    string // The actual auth value (token, API key, or Basic credentials)
}

// Executor runs compiled templates against operations
type Executor struct {
	httpClient HTTPClient
	cache      *Cache
	requestIDs []string
	oobClient  *oob.Client // OOB detection client (optional)
	oobURL     string      // Cached interactsh URL for this session
}

// ExecutorOption configures Executor
type ExecutorOption func(*Executor)

// WithOOBClient enables OOB detection with interactsh client
func WithOOBClient(c *oob.Client) ExecutorOption {
	return func(e *Executor) {
		e.oobClient = c
		if c != nil {
			e.oobURL = c.GenerateURL()
		}
	}
}

// WithUserOOBURL sets a user-provided OOB callback URL (no interactsh client needed)
func WithUserOOBURL(url string) ExecutorOption {
	return func(e *Executor) {
		e.oobURL = url
		e.oobClient = nil // User handles callbacks themselves
	}
}

func NewExecutor(client HTTPClient, opts ...ExecutorOption) *Executor {
	e := &Executor{
		httpClient: client,
		cache:      NewCache(1000), // Cache 1000 compiled templates
		requestIDs: make([]string, 0),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// checkOOBIndicator polls for OOB callbacks and returns matched interactions
func (e *Executor) checkOOBIndicator(ctx context.Context, indicator Indicator) (bool, []model.OOBInteraction, error) {
	if e.oobClient == nil {
		return false, nil, nil
	}

	interactions, err := e.oobClient.Poll(ctx)
	if err != nil {
		return false, nil, err
	}

	// Collect matching interactions
	var matched []model.OOBInteraction
	for _, interaction := range interactions {
		if indicator.Protocol == "" || interaction.Protocol == indicator.Protocol {
			matched = append(matched, model.OOBInteraction{
				Protocol:  interaction.Protocol,
				URL:       interaction.URL,
				Timestamp: interaction.Timestamp,
				RemoteIP:  interaction.RemoteIP,
				RawData:   interaction.RawData,
			})
		}
	}

	return len(matched) > 0, matched, nil
}

// Execute runs template against operation
func (e *Executor) Execute(
	ctx context.Context,
	tmpl *CompiledTemplate,
	operation *model.Operation,
	authInfo *AuthInfo,
	variables map[string]string,
) (*ExecutionResult, error) {
	// Clear request IDs for this execution
	e.requestIDs = make([]string, 0)

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
				req, err := buildRequest(ctx, test, operation, authInfo, variables)
				if err != nil {
					return nil, fmt.Errorf("failed to build request: %w", err)
				}

				// Add request ID header and track it
				requestID := generateRequestID()
				req.Header.Set("X-Hadrian-Request-Id", requestID)
				e.requestIDs = append(e.requestIDs, requestID)

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
					log.Debug("Backoff triggered (attempt %d/%d), waiting %d seconds...", retry+1, maxRetries, backoffSecs)
					time.Sleep(time.Duration(backoffSecs) * time.Second)
					continue
				}

				// Either not overwhelmed or max retries reached
				break
			}

			// If backoff limit was exhausted (still overwhelmed after all retries), stop the repeat loop
			if serverOverwhelmed {
				log.Debug("Backoff limit reached (%d retries exhausted). Stopping requests for this test.", maxRetries)
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
				log.Debug("Rate limit detected after %d requests. Endpoint is protected.", i+1)
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
				log.Debug("Test inconclusive due to server overwhelm. Not marking as vulnerable.")
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

	// Check for OOB indicators if OOB client is configured
	if e.oobClient != nil && tmpl.Detection.SuccessIndicators != nil {
		for _, indicator := range tmpl.Detection.SuccessIndicators {
			if indicator.Type == "oob_callback" {
				matched, interactions, err := e.checkOOBIndicator(ctx, indicator)
				if err != nil {
					return nil, fmt.Errorf("OOB check failed: %w", err)
				}
				if matched {
					result.Matched = true
					result.OOBInteractions = append(result.OOBInteractions, interactions...)
				}
			}
		}
	}

	// Add tracked request IDs to result
	result.RequestIDs = e.requestIDs

	return result, nil
}

// ExecuteGraphQL runs GraphQL template tests against a GraphQL endpoint
func (e *Executor) ExecuteGraphQL(
	ctx context.Context,
	tmpl *CompiledTemplate,
	endpoint string,
	authInfos interface{}, // Can be *AuthInfo or map[string]*AuthInfo
	variables map[string]string,
) (*ExecutionResult, error) {
	// Clear request IDs for this execution
	e.requestIDs = make([]string, 0)

	result := &ExecutionResult{
		TemplateID: tmpl.ID,
		Matched:    false,
		Findings:   []model.Finding{},
	}

	// Storage for multi-phase tests
	storedFields := make(map[string]string)

	// Execute each GraphQL test in template
	for _, test := range tmpl.GraphQL {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Substitute variables in query
		query := test.Query

		// Substitute {{interactsh}} with OOB URL first
		query = substituteInteractsh(query, e.oobURL)

		if variables != nil {
			for key, value := range variables {
				query = strings.ReplaceAll(query, "{{"+key+"}}", value)
			}
		}

		// Substitute stored fields from previous phases
		for key, value := range storedFields {
			query = strings.ReplaceAll(query, "{{"+key+"}}", value)
		}

		// Build GraphQL request body
		reqBody := map[string]interface{}{
			"query": query,
		}

		// Handle Variables field (supports both old map[string]string and new arbitrary JSON)
		if test.Variables != nil {
			// Check if it's the old string map format for backwards compatibility
			if stringMap, ok := test.Variables.(map[string]string); ok {
				// Old behavior: substitute placeholders in string values
				testVariables := make(map[string]string)
				for key, value := range stringMap {
					substituted := value
					if variables != nil {
						for vKey, vValue := range variables {
							substituted = strings.ReplaceAll(substituted, "{{"+vKey+"}}", vValue)
						}
					}
					for sKey, sValue := range storedFields {
						substituted = strings.ReplaceAll(substituted, "{{"+sKey+"}}", sValue)
					}
					testVariables[key] = substituted
				}
				reqBody["variables"] = testVariables
			} else {
				// New behavior: use variables as-is (arbitrary JSON structure)
				reqBody["variables"] = test.Variables
			}
		}
		if test.OperationName != "" {
			reqBody["operationName"] = test.OperationName
		}

		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal GraphQL request body: %w", err)
		}

		// Create HTTP request
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create GraphQL request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")

		// Add request ID header and track it
		requestID := generateRequestID()
		req.Header.Set("X-Hadrian-Request-Id", requestID)
		e.requestIDs = append(e.requestIDs, requestID)

		// Determine which auth to use
		var authInfo *AuthInfo
		switch a := authInfos.(type) {
		case *AuthInfo:
			authInfo = a
		case map[string]*AuthInfo:
			if test.Auth != "" {
				authInfo = a[test.Auth]
			}
		}

		// Apply authentication
		if authInfo != nil && authInfo.Value != "" {
			switch authInfo.Method {
			case "bearer", "basic":
				req.Header.Set("Authorization", authInfo.Value)
			case "api_key":
				if authInfo.Location == "header" {
					req.Header.Set(authInfo.KeyName, authInfo.Value)
				} else if authInfo.Location == "query" {
					q := req.URL.Query()
					q.Set(authInfo.KeyName, authInfo.Value)
					req.URL.RawQuery = q.Encode()
				}
			}
		}

		// Execute HTTP request
		resp, err := e.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("GraphQL request failed: %w", err)
		}

		// Read response body
		bodyBytes, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read GraphQL response body: %w", err)
		}
		bodyStr := string(bodyBytes)

		// Store response fields if specified
		if len(test.StoreResponseFields) > 0 {
			var responseData map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &responseData); err == nil {
				for alias, jsonPath := range test.StoreResponseFields {
					value := extractJSONPath(responseData, jsonPath)
					if value != "" {
						storedFields[alias] = value
					}
				}
			}
		}

		// Evaluate matchers
		matched := evaluateMatchers(tmpl.CompiledMatchers, resp, bodyStr)

		if matched {
			result.Matched = true
			hash := sha256.Sum256(bodyBytes)
			result.Response = model.HTTPResponse{
				StatusCode: resp.StatusCode,
				Headers:    flattenHeaders(resp.Header),
				Body:       bodyStr,
				BodyHash:   fmt.Sprintf("%x", hash),
				Size:       len(bodyBytes),
				Truncated:  false,
			}
		}
	}

	// Check for OOB indicators if OOB client is configured
	if e.oobClient != nil && tmpl.Detection.SuccessIndicators != nil {
		for _, indicator := range tmpl.Detection.SuccessIndicators {
			if indicator.Type == "oob_callback" {
				matched, interactions, err := e.checkOOBIndicator(ctx, indicator)
				if err != nil {
					return nil, fmt.Errorf("OOB check failed: %w", err)
				}
				if matched {
					result.Matched = true
					result.OOBInteractions = append(result.OOBInteractions, interactions...)
				}
			}
		}
	}

	// Add tracked request IDs to result
	result.RequestIDs = e.requestIDs

	return result, nil
}

// buildRequest constructs HTTP request with variable substitution
func buildRequest(
	ctx context.Context,
	test HTTPTest,
	operation *model.Operation,
	authInfo *AuthInfo,
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
	if placeholder := util.HasUnresolvedPlaceholders(path); placeholder != "" {
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
		if value == "Bearer {{attacker_token}}" && authInfo != nil && authInfo.Value != "" {
			// Handle authentication based on method
			switch authInfo.Method {
			case "bearer", "basic":
				// Bearer and Basic both use Authorization header
				req.Header.Set("Authorization", authInfo.Value)
			case "api_key":
				// API key auth: check location
				if authInfo.Location == "header" {
					// Set custom header (e.g., X-API-Key)
					req.Header.Set(authInfo.KeyName, authInfo.Value)
				} else if authInfo.Location == "query" {
					// Add as query parameter
					q := req.URL.Query()
					q.Set(authInfo.KeyName, authInfo.Value)
					req.URL.RawQuery = q.Encode()
				}
			}
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
	RequestIDs    []string // X-Hadrian-Request-Id values from all requests
	OOBInteractions []model.OOBInteraction // OOB callbacks received
}

// RateLimitInfo contains results from rate limit testing
type RateLimitInfo struct {
	RequestCount   int
	RateLimitCount int
	Threshold      int
}

// extractJSONPath extracts a value from a JSON object using a dot-separated path
// Example: "data.user.id" extracts value from {"data":{"user":{"id":"123"}}}
func extractJSONPath(data map[string]interface{}, path string) string {
	parts := strings.Split(path, ".")
	current := interface{}(data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return ""
		}
	}

	// Convert final value to string
	switch v := current.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%v", v)
	case bool:
		return fmt.Sprintf("%v", v)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}
