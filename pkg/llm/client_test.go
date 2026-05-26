package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient_OllamaRunning(t *testing.T) {
	// Arrange - Mock Ollama server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	// Test IsOllamaRunningAt directly with mock server
	ctx := context.Background()
	running := IsOllamaRunningAt(ctx, server.URL)

	// Assert
	assert.True(t, running, "Mock Ollama server should be detected as running")
}

func TestNewClient_NoProvider(t *testing.T) {
	// Arrange — pin OLLAMA_HOST to a guaranteed-refused address so the
	// auto-detection in NewClient cannot reach a real local ollama on the
	// developer's machine. Without this guard the test fails on any host
	// where ollama happens to be running on the default port.
	t.Setenv("OLLAMA_HOST", "http://127.0.0.1:1")

	// Act
	client, err := NewClient(context.Background())

	// Assert — require.* on the first two so a regression fails the test
	// cleanly instead of panicking on the err.Error() dereference below.
	require.Error(t, err)
	require.Nil(t, client)
	assert.Contains(t, err.Error(), "no LLM provider available")
}

func TestIsOllamaRunning_ServerResponds(t *testing.T) {
	// Arrange - Mock Ollama server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	// Act - Use IsOllamaRunningAt with mock server URL
	ctx := context.Background()
	running := IsOllamaRunningAt(ctx, server.URL)

	// Assert
	assert.True(t, running)
}

func TestIsOllamaRunning_ServerNotResponding(t *testing.T) {
	// Arrange — pin OLLAMA_HOST to a guaranteed-refused address so this test
	// doesn't accidentally hit a real local ollama on the default port (same
	// flake class as LAB-3638).
	t.Setenv("OLLAMA_HOST", "http://127.0.0.1:1")

	// Act
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	running := IsOllamaRunning(ctx)

	// Assert
	assert.False(t, running)
}

func TestIsOllamaRunning_WithCustomHost(t *testing.T) {
	// Arrange - Mock Ollama server on custom port
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	_ = os.Setenv("OLLAMA_HOST", server.URL)
	defer func() { _ = os.Unsetenv("OLLAMA_HOST") }()

	// Act
	ctx := context.Background()
	running := IsOllamaRunning(ctx)

	// Assert
	assert.True(t, running, "IsOllamaRunning should check OLLAMA_HOST env var")
}

func TestIsOllamaRunning_WithCustomHostNotRunning(t *testing.T) {
	// Arrange - Set custom host that doesn't exist
	_ = os.Setenv("OLLAMA_HOST", "http://localhost:99999")
	defer func() { _ = os.Unsetenv("OLLAMA_HOST") }()

	// Act
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	running := IsOllamaRunning(ctx)

	// Assert
	assert.False(t, running, "IsOllamaRunning should return false when custom host not responding")
}

// TestNewClientWithConfig tests LLM client creation with explicit config
func TestNewClientWithConfig_WithOllamaHost(t *testing.T) {
	// Arrange - Mock Ollama server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	_ = os.Unsetenv("OLLAMA_HOST")

	// Act
	ctx := context.Background()
	client, err := NewClientWithConfig(ctx, server.URL, "llama3.2:latest", 180*time.Second, "")

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "ollama", client.Name())
}

func TestNewClientWithConfig_WithEmptyModel(t *testing.T) {
	// Arrange - Mock Ollama server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	_ = os.Unsetenv("OLLAMA_HOST")
	_ = os.Unsetenv("OLLAMA_MODEL")

	// Act
	ctx := context.Background()
	client, err := NewClientWithConfig(ctx, server.URL, "", 180*time.Second, "")

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "ollama", client.Name())
}

func TestNewClientWithConfig_OllamaNotReachable(t *testing.T) {
	// Arrange
	_ = os.Unsetenv("OLLAMA_HOST")

	// Act
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	client, err := NewClientWithConfig(ctx, "http://localhost:99999", "llama3.2:latest", 180*time.Second, "")

	// Assert — require.* on the first two so a regression fails the test
	// cleanly instead of panicking on the err.Error() dereference below.
	require.Error(t, err)
	require.Nil(t, client)
	assert.Contains(t, err.Error(), "not reachable")
}

func TestNewClientWithConfig_EmptyHostFallsBackToDefault(t *testing.T) {
	// Pin OLLAMA_HOST to a guaranteed-refused address so the empty-host
	// fallback in client.go:51 hits a refused destination instead of a real
	// local ollama on the developer's machine (same flake class as LAB-3638).
	t.Setenv("OLLAMA_HOST", "http://127.0.0.1:1")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	client, err := NewClientWithConfig(ctx, "", "", 180*time.Second, "")

	// Should fall back through host -> OLLAMA_HOST -> default and fail because
	// the pinned host is refused. require.* on the first two so a regression
	// fails cleanly instead of panicking on err.Error() below.
	require.Error(t, err)
	require.Nil(t, client)
	assert.Contains(t, err.Error(), "not reachable")
}

// TEST-002: NewClientWithProvider dispatch tests
func TestNewClientWithProvider_OpenAI(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	client, err := NewClientWithProvider(context.Background(), "openai", "", "", 60*time.Second, "")
	require.NoError(t, err)
	assert.IsType(t, &OpenAIClient{}, client)
}

func TestNewClientWithProvider_Anthropic(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	client, err := NewClientWithProvider(context.Background(), "anthropic", "", "", 60*time.Second, "")
	require.NoError(t, err)
	assert.IsType(t, &AnthropicClient{}, client)
}

func TestNewClientWithProvider_Ollama(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client, err := NewClientWithProvider(context.Background(), "ollama", server.URL, "", 60*time.Second, "")
	require.NoError(t, err)
	assert.Equal(t, "ollama", client.Name())
}

func TestNewClientWithProvider_EmptyDefaultsToOllama(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client, err := NewClientWithProvider(context.Background(), "", server.URL, "", 60*time.Second, "")
	require.NoError(t, err)
	assert.Equal(t, "ollama", client.Name())
}

func TestNewClientWithProvider_Unknown(t *testing.T) {
	_, err := NewClientWithProvider(context.Background(), "bogus", "", "", 60*time.Second, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown LLM provider")
	assert.Contains(t, err.Error(), "bogus")
}
