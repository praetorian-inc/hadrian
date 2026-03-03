package http

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
		_, _ = w.Write([]byte("test response"))
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
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, "test response", string(body))
}

func TestNew_ProxyWithAuth(t *testing.T) {
	// Test proxy authentication from PROXY_USERNAME/PROXY_PASSWORD environment
	// Set environment variables
	_ = os.Setenv("PROXY_USERNAME", "testuser")
	_ = os.Setenv("PROXY_PASSWORD", "testpass")
	defer func() { _ = os.Unsetenv("PROXY_USERNAME") }()
	defer func() { _ = os.Unsetenv("PROXY_PASSWORD") }()

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
