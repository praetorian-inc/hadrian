package graphql

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// MaxResponseBodySize is the maximum size of HTTP response bodies (10MB)
// This prevents memory exhaustion from malicious servers sending unbounded responses
const MaxResponseBodySize = 10 * 1024 * 1024

// Executor executes GraphQL queries
type Executor struct {
	httpClient HTTPClient
	endpoint   string
	mu         sync.Mutex
	requestIDs []string // Track all request IDs for this executor session
}

// NewExecutor creates a new GraphQL executor
func NewExecutor(client HTTPClient, endpoint string) *Executor {
	return &Executor{
		httpClient: client,
		endpoint:   endpoint,
		requestIDs: make([]string, 0),
	}
}

// GetRequestIDs returns all tracked request IDs
func (e *Executor) GetRequestIDs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	ids := make([]string, len(e.requestIDs))
	copy(ids, e.requestIDs)
	return ids
}

// ClearRequestIDs clears the tracked request IDs
func (e *Executor) ClearRequestIDs() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requestIDs = make([]string, 0)
}

// GraphQLRequest is the standard request format
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	OperationName string                 `json:"operationName,omitempty"`
}

// GraphQLResponse is the standard response format
type GraphQLResponse struct {
	Data   json.RawMessage `json:"data,omitempty"`
	Errors []GraphQLError  `json:"errors,omitempty"`
}

// ExecuteResult contains execution results
type ExecuteResult struct {
	Response   *http.Response
	Body       string
	StatusCode int
	Errors     []GraphQLError
	RequestID  string
}

// AuthInfo contains authentication information
type AuthInfo struct {
	Method   string // "bearer", "api_key"
	Value    string
	Location string // "header", "query"
	KeyName  string // Header name for api_key
}

// Execute runs a GraphQL query
func (e *Executor) Execute(
	ctx context.Context,
	query string,
	variables map[string]interface{},
	operationName string,
	authInfo *AuthInfo,
) (*ExecuteResult, error) {
	// Build request body
	reqBody := GraphQLRequest{
		Query:         query,
		Variables:     variables,
		OperationName: operationName,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", e.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add auth
	if authInfo != nil && authInfo.Value != "" {
		switch authInfo.Method {
		case "bearer":
			req.Header.Set("Authorization", authInfo.Value)
		case "api_key":
			if authInfo.Location == "header" {
				req.Header.Set(authInfo.KeyName, authInfo.Value)
			}
		}
	}

	// Generate request ID
	requestID := generateRequestID()
	req.Header.Set("X-Hadrian-Request-Id", requestID)

	// Track request ID
	e.mu.Lock()
	e.requestIDs = append(e.requestIDs, requestID)
	e.mu.Unlock()

	// Execute
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read body with size limit to prevent memory exhaustion
	limitedReader := io.LimitReader(resp.Body, MaxResponseBodySize)
	respBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check if response was truncated (more data available after limit)
	var buf [1]byte
	if n, _ := resp.Body.Read(buf[:]); n > 0 {
		return nil, fmt.Errorf("failed to read response: response body exceeds maximum size of %d bytes", MaxResponseBodySize)
	}

	result := &ExecuteResult{
		Response:   resp,
		Body:       string(respBody),
		StatusCode: resp.StatusCode,
		RequestID:  requestID,
	}

	// Parse GraphQL errors if present
	var gqlResp GraphQLResponse
	if err := json.Unmarshal(respBody, &gqlResp); err == nil {
		result.Errors = gqlResp.Errors
	}

	return result, nil
}

// HasErrors returns true if there are GraphQL errors
func (r *ExecuteResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// IsSuccess returns true if status code is 2xx and no GraphQL errors
func (r *ExecuteResult) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300 && !r.HasErrors()
}

func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate request ID: %v", err))
	}
	return hex.EncodeToString(b)
}
