package owasp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrackedHTTPClient_AddsRequestIDHeader(t *testing.T) {
	// Setup mock server to capture headers
	var capturedRequestID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRequestID = r.Header.Get("X-Hadrian-Request-Id")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create tracked client
	client := NewTrackedHTTPClient(http.DefaultClient)

	// Make request
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Verify request ID was added
	assert.NotEmpty(t, capturedRequestID, "X-Hadrian-Request-Id header should be set")

	// Verify UUID format (8-4-4-4-12)
	parts := strings.Split(capturedRequestID, "-")
	assert.Len(t, parts, 5, "Request ID should have UUID format")
	assert.Len(t, parts[0], 8, "First segment should be 8 chars")
	assert.Len(t, parts[1], 4, "Second segment should be 4 chars")
	assert.Len(t, parts[2], 4, "Third segment should be 4 chars")
	assert.Len(t, parts[3], 4, "Fourth segment should be 4 chars")
	assert.Len(t, parts[4], 12, "Fifth segment should be 12 chars")
}

func TestTrackedHTTPClient_TracksMultipleRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewTrackedHTTPClient(http.DefaultClient)

	// Make 3 requests
	for i := 0; i < 3; i++ {
		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
	}

	// Verify all request IDs tracked
	requestIDs := client.GetRequestIDs()
	assert.Len(t, requestIDs, 3, "Should track all 3 requests")

	// Verify all IDs are unique
	seen := make(map[string]bool)
	for _, id := range requestIDs {
		assert.False(t, seen[id], "Request IDs should be unique")
		seen[id] = true
	}
}

func TestTrackedHTTPClient_ClearRequestIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewTrackedHTTPClient(http.DefaultClient)

	// Make request
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Len(t, client.GetRequestIDs(), 1, "Should have 1 request ID")

	// Clear
	client.ClearRequestIDs()
	assert.Len(t, client.GetRequestIDs(), 0, "Should have 0 request IDs after clear")
}

func TestGenerateRequestID_Format(t *testing.T) {
	// Generate multiple IDs
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateRequestID()

		// Verify format
		parts := strings.Split(id, "-")
		assert.Len(t, parts, 5, "Request ID should have UUID format")

		// Verify uniqueness
		assert.False(t, ids[id], "Request IDs should be unique")
		ids[id] = true
	}
}
