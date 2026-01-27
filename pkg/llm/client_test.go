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

func TestNewClient_AnthropicKeySet(t *testing.T) {
	// Arrange
	os.Setenv("ANTHROPIC_API_KEY", "test-key-anthropic")
	defer os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")

	// Act
	client, err := NewClient(context.Background())

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "claude", client.Name())
}

func TestNewClient_OpenAIKeySet(t *testing.T) {
	// Arrange
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Setenv("OPENAI_API_KEY", "test-key-openai")
	defer os.Unsetenv("OPENAI_API_KEY")

	// Act
	client, err := NewClient(context.Background())

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "openai", client.Name())
}

func TestNewClient_OllamaRunning(t *testing.T) {
	// Arrange - Mock Ollama server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")

	// This test would need refactoring to inject the URL - skipping for now
	t.Skip("Ollama check uses hardcoded localhost:11434 - needs refactor for testing")
}

func TestNewClient_NoProvider(t *testing.T) {
	// Arrange
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")

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

	// This test requires refactoring IsOllamaRunning to accept a URL parameter
	t.Skip("IsOllamaRunning uses hardcoded localhost:11434 - needs refactor for testing")
}

func TestIsOllamaRunning_ServerNotResponding(t *testing.T) {
	// Act - Try to connect to non-existent server
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	running := IsOllamaRunning(ctx)

	// Assert
	assert.False(t, running)
}
