package http

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_DefaultConfig(t *testing.T) {
	// Test nil config uses default 30s timeout
	client, err := New(nil)

	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.NotNil(t, client.httpClient)
	assert.Equal(t, 30*time.Second, client.httpClient.Timeout)
}

func TestNew_CustomTimeout(t *testing.T) {
	// Test custom timeout configuration
	config := &Config{
		Timeout: 60 * time.Second,
	}

	client, err := New(config)

	require.NoError(t, err)
	assert.Equal(t, 60*time.Second, client.httpClient.Timeout)
}

func TestNew_TLS13Enforcement(t *testing.T) {
	// Test TLS 1.3 minimum version enforcement
	client, err := New(nil)

	require.NoError(t, err)
	transport, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok, "Transport should be *http.Transport")
	assert.Equal(t, uint16(tls.VersionTLS13), transport.TLSClientConfig.MinVersion)
}

func TestNew_ExplicitProxy(t *testing.T) {
	// Test explicit proxy configuration
	config := &Config{
		Proxy:   "http://localhost:8080",
		Timeout: 30 * time.Second,
	}

	client, err := New(config)

	require.NoError(t, err)
	transport, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok, "Transport should be *http.Transport")
	assert.NotNil(t, transport.Proxy)
}

func TestNew_InvalidProxy(t *testing.T) {
	// Test invalid proxy URL returns error
	config := &Config{
		Proxy:   "://invalid-url",
		Timeout: 30 * time.Second,
	}

	client, err := New(config)

	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "invalid proxy URL")
}

func TestNew_InvalidCACert(t *testing.T) {
	// Test invalid CA certificate path returns error
	config := &Config{
		CACert:  "/nonexistent/ca.crt",
		Timeout: 30 * time.Second,
	}

	client, err := New(config)

	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to load CA cert")
}

func TestNew_InsecureMode(t *testing.T) {
	// Test insecure mode disables TLS verification
	config := &Config{
		Insecure: true,
		Timeout:  30 * time.Second,
	}

	client, err := New(config)

	require.NoError(t, err)
	transport, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok, "Transport should be *http.Transport")
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestDo(t *testing.T) {
	// Test HTTP request execution with httptest server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/test", r.URL.Path)
		assert.Equal(t, "GET", r.Method)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()

	client, err := New(&Config{Timeout: 30 * time.Second})
	require.NoError(t, err)

	req, err := http.NewRequest("GET", server.URL+"/test", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "test response", string(body))
}

func TestNew_ProxyWithAuth(t *testing.T) {
	// Test proxy authentication from PROXY_USERNAME/PROXY_PASSWORD environment
	// Set environment variables
	os.Setenv("PROXY_USERNAME", "testuser")
	os.Setenv("PROXY_PASSWORD", "testpass")
	defer os.Unsetenv("PROXY_USERNAME")
	defer os.Unsetenv("PROXY_PASSWORD")

	config := &Config{
		Proxy:   "http://localhost:8080",
		Timeout: 30 * time.Second,
	}

	client, err := New(config)

	require.NoError(t, err)
	assert.NotNil(t, client)
	// Note: We can't easily test the actual proxy auth without a real proxy server
	// This test verifies that the client is created successfully with env vars set
}

func TestNew_ProxyFromEnvironment(t *testing.T) {
	// Test HTTP_PROXY environment variable is respected
	// Clear any explicit proxy config - should fall back to HTTP_PROXY env var
	config := &Config{
		Timeout: 30 * time.Second,
	}

	client, err := New(config)

	require.NoError(t, err)
	transport, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok, "Transport should be *http.Transport")
	assert.NotNil(t, transport.Proxy) // ProxyFromEnvironment is set
}

func TestNew_RequestIDEnabled(t *testing.T) {
	// Test RequestID wraps transport with requestIDTransport
	config := &Config{
		Timeout:   30 * time.Second,
		RequestID: true,
	}

	client, err := New(config)

	require.NoError(t, err)
	assert.NotNil(t, client)
	// Verify transport is wrapped (not *http.Transport directly)
	_, isHTTPTransport := client.httpClient.Transport.(*http.Transport)
	assert.False(t, isHTTPTransport, "Transport should be wrapped with requestIDTransport")
	_, isRequestIDTransport := client.httpClient.Transport.(*requestIDTransport)
	assert.True(t, isRequestIDTransport, "Transport should be *requestIDTransport")
}

func TestRequestIDTransport_AddsHeader(t *testing.T) {
	// Test that requestIDTransport adds X-Hadrian-Request-ID header
	var receivedHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Hadrian-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout:   30 * time.Second,
		RequestID: true,
	}

	client, err := New(config)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", server.URL+"/test", nil)
	require.NoError(t, err)

	_, err = client.Do(req)
	require.NoError(t, err)

	// Verify header was set
	assert.NotEmpty(t, receivedHeader, "X-Hadrian-Request-ID header should be set")
	// Verify it looks like a UUID (36 chars with dashes)
	assert.Len(t, receivedHeader, 36, "Request ID should be a UUID (36 characters)")
	assert.Contains(t, receivedHeader, "-", "Request ID should contain dashes (UUID format)")
}

func TestRequestIDTransport_UniquePerRequest(t *testing.T) {
	// Test that each request gets a unique ID
	var requestIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestIDs = append(requestIDs, r.Header.Get("X-Hadrian-Request-ID"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout:   30 * time.Second,
		RequestID: true,
	}

	client, err := New(config)
	require.NoError(t, err)

	// Make 3 requests
	for i := 0; i < 3; i++ {
		req, err := http.NewRequest("GET", server.URL+"/test", nil)
		require.NoError(t, err)
		_, err = client.Do(req)
		require.NoError(t, err)
	}

	// Verify all IDs are unique
	assert.Len(t, requestIDs, 3, "Should have 3 request IDs")
	assert.NotEqual(t, requestIDs[0], requestIDs[1], "Request IDs should be unique")
	assert.NotEqual(t, requestIDs[1], requestIDs[2], "Request IDs should be unique")
	assert.NotEqual(t, requestIDs[0], requestIDs[2], "Request IDs should be unique")
}

func TestRequestIDTransport_PreservesExistingHeaders(t *testing.T) {
	// Test that requestIDTransport preserves existing headers
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Timeout:   30 * time.Second,
		RequestID: true,
	}

	client, err := New(config)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", server.URL+"/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")

	_, err = client.Do(req)
	require.NoError(t, err)

	// Verify original headers are preserved
	assert.Equal(t, "Bearer test-token", receivedHeaders.Get("Authorization"))
	assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
	// And the request ID is added
	assert.NotEmpty(t, receivedHeaders.Get("X-Hadrian-Request-ID"))
}

// roundTripFunc is a helper type for creating mock RoundTrippers
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRequestIDTransport_DoesNotOverwriteExisting(t *testing.T) {
	existingID := "pre-set-request-id-12345"
	var capturedReq *http.Request

	baseTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		capturedReq = req
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})

	transport := &requestIDTransport{base: baseTransport}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Hadrian-Request-ID", existingID)

	_, err := transport.RoundTrip(req)
	require.NoError(t, err)

	assert.Equal(t, existingID, capturedReq.Header.Get("X-Hadrian-Request-ID"),
		"Transport should not overwrite existing X-Hadrian-Request-ID")
}
