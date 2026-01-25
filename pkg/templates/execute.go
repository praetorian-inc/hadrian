package templates

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

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
		// Build request
		req, err := buildRequest(ctx, test, operation, authHeader, variables)
		if err != nil {
			return nil, fmt.Errorf("failed to build request: %w", err)
		}

		// Execute HTTP request
		resp, err := e.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP request failed: %w", err)
		}
		defer resp.Body.Close()

		// Read response body
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		body := string(bodyBytes)

		// Compute body hash
		hash := sha256.Sum256(bodyBytes)
		bodyHash := fmt.Sprintf("%x", hash)

		// Run matchers
		matched := evaluateMatchers(tmpl.CompiledMatchers, resp, body)

		if matched {
			result.Matched = true
			result.Response = model.HTTPResponse{
				StatusCode: resp.StatusCode,
				Headers:    flattenHeaders(resp.Header),
				Body:       body,
				BodyHash:   bodyHash,
				Size:       len(bodyBytes),
				Truncated:  false,
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
	if variables != nil {
		for key, value := range variables {
			path = strings.ReplaceAll(path, "{{"+key+"}}", value)
		}
	}

	// Build full URL
	// Note: For now, if operation.Path contains full URL (from APISpec.BaseURL + path),
	// use it directly. Otherwise just use path as-is for the URL.
	url := path

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
	TemplateID string
	Operation  *model.Operation
	Matched    bool
	Response   model.HTTPResponse
	Findings   []model.Finding
}
