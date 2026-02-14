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

	_ = os.Unsetenv("ANTHROPIC_API_KEY")
	_ = os.Unsetenv("OPENAI_API_KEY")

	// Test IsOllamaRunningAt directly with mock server
	ctx := context.Background()
	running := IsOllamaRunningAt(ctx, server.URL)

	// Assert
	assert.True(t, running, "Mock Ollama server should be detected as running")
}

func TestNewClient_NoProvider(t *testing.T) {
	// Arrange
	// No Ollama running

	// Act
	client, err := NewClient(context.Background())

	// Assert
	assert.Error(t, err)
	assert.Nil(t, client)
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
	// Act - Try to connect to non-existent server
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

	t.Setenv("OLLAMA_HOST", server.URL)

	// Act
	ctx := context.Background()
	running := IsOllamaRunning(ctx)

	// Assert
	assert.True(t, running, "IsOllamaRunning should check OLLAMA_HOST env var")
}

func TestIsOllamaRunning_WithCustomHostNotRunning(t *testing.T) {
	// Arrange - Set custom host that doesn't exist
	t.Setenv("OLLAMA_HOST", "http://localhost:99999")

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

	_ = os.Unsetenv("ANTHROPIC_API_KEY")
	_ = os.Unsetenv("OPENAI_API_KEY")
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

	_ = os.Unsetenv("ANTHROPIC_API_KEY")
	_ = os.Unsetenv("OPENAI_API_KEY")
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
	_ = os.Unsetenv("ANTHROPIC_API_KEY")
	_ = os.Unsetenv("OPENAI_API_KEY")
	_ = os.Unsetenv("OLLAMA_HOST")

	// Act
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	client, err := NewClientWithConfig(ctx, "http://localhost:99999", "llama3.2:latest", 180*time.Second, "")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "not reachable")
}

func TestNewClientWithConfig_EmptyHostFallsBackToEnv(t *testing.T) {
	// Arrange
	_ = os.Unsetenv("ANTHROPIC_API_KEY")
	_ = os.Unsetenv("OPENAI_API_KEY")
	_ = os.Unsetenv("OLLAMA_HOST")

	// Act
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	client, err := NewClientWithConfig(ctx, "", "", 180*time.Second, "")

	// Assert - Should fall back to NewClient logic, which will fail with no env vars
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "no LLM provider available")
}
