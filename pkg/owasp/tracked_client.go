package owasp

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// TrackedHTTPClient wraps an HTTPClient to add request ID tracking
type TrackedHTTPClient struct {
	client     HTTPClient
	requestIDs []string
}

// NewTrackedHTTPClient creates a new tracked client wrapper
func NewTrackedHTTPClient(client HTTPClient) *TrackedHTTPClient {
	return &TrackedHTTPClient{
		client:     client,
		requestIDs: make([]string, 0),
	}
}

// Do executes the request with a unique request ID header
func (t *TrackedHTTPClient) Do(req *http.Request) (*http.Response, error) {
	requestID := generateRequestID()
	req.Header.Set("X-Hadrian-Request-Id", requestID)
	t.requestIDs = append(t.requestIDs, requestID)
	return t.client.Do(req)
}

// GetRequestIDs returns all tracked request IDs
func (t *TrackedHTTPClient) GetRequestIDs() []string {
	return t.requestIDs
}

// ClearRequestIDs clears the tracked request IDs
func (t *TrackedHTTPClient) ClearRequestIDs() {
	t.requestIDs = make([]string, 0)
}

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
