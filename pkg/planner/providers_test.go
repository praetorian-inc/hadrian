package planner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// === Constructor tests (TEST-001) ===

func TestNewOpenAIClient_Defaults(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	c, err := NewOpenAIClient("", "", 0)
	require.NoError(t, err)
	assert.Equal(t, "sk-test", c.apiKey)
	assert.Equal(t, "gpt-4o", c.model)
	assert.Equal(t, 120*time.Second, c.client.Timeout)
}

func TestNewOpenAIClient_ExplicitOverridesEnv(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "env-key")
	c, err := NewOpenAIClient("explicit-key", "gpt-3.5-turbo", 60*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "explicit-key", c.apiKey)
	assert.Equal(t, "gpt-3.5-turbo", c.model)
	assert.Equal(t, 60*time.Second, c.client.Timeout)
}

func TestNewOpenAIClient_MissingKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	_, err := NewOpenAIClient("", "", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OPENAI_API_KEY not set")
}

func TestNewAnthropicClient_Defaults(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	c, err := NewAnthropicClient("", "", 0)
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-test", c.apiKey)
	assert.Equal(t, "claude-sonnet-4-20250514", c.model)
	assert.Equal(t, 120*time.Second, c.client.Timeout)
}

func TestNewAnthropicClient_MissingKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	_, err := NewAnthropicClient("", "", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ANTHROPIC_API_KEY not set")
}

func TestNewOllamaClient_Defaults(t *testing.T) {
	t.Setenv("OLLAMA_HOST", "")
	t.Setenv("OLLAMA_MODEL", "")
	c := NewOllamaClient("", "", 0)
	assert.Equal(t, "http://localhost:11434", c.baseURL)
	assert.Equal(t, "llama3.2:latest", c.model)
	assert.Equal(t, 120*time.Second, c.client.Timeout)
}

func TestNewOllamaClient_EnvFallback(t *testing.T) {
	t.Setenv("OLLAMA_HOST", "http://custom:1234")
	t.Setenv("OLLAMA_MODEL", "mistral:latest")
	c := NewOllamaClient("", "", 0)
	assert.Equal(t, "http://custom:1234", c.baseURL)
	assert.Equal(t, "mistral:latest", c.model)
}

// === Generate() with httptest (TEST-002, QUAL-004) ===

func TestOpenAIClient_Generate_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		var req map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "gpt-4o", req["model"])
		assert.Equal(t, 0.2, req["temperature"])
		assert.NotNil(t, req["response_format"])

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": `{"steps":[]}`}},
			},
		}))
	}))
	defer server.Close()

	c := &OpenAIClient{apiKey: "test-key", model: "gpt-4o", endpoint: server.URL, client: server.Client()}
	result, err := c.Generate(context.Background(), "test prompt")
	require.NoError(t, err)
	assert.Equal(t, `{"steps":[]}`, result)
}

func TestOpenAIClient_Generate_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer server.Close()

	c := &OpenAIClient{apiKey: "test-key", model: "gpt-4o", endpoint: server.URL, client: server.Client()}
	_, err := c.Generate(context.Background(), "test")
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, 429, apiErr.StatusCode)
}

func TestOpenAIClient_Generate_ParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer server.Close()

	c := &OpenAIClient{apiKey: "test-key", model: "gpt-4o", endpoint: server.URL, client: server.Client()}
	_, err := c.Generate(context.Background(), "test")
	require.Error(t, err)
}

func TestAnthropicClient_Generate_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-key", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))

		var req map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, 0.2, req["temperature"])
		assert.Equal(t, float64(4096), req["max_tokens"])

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": `{"steps":[]}`},
			},
		}))
	}))
	defer server.Close()

	c := &AnthropicClient{apiKey: "test-key", model: "claude-sonnet-4-20250514", endpoint: server.URL, client: server.Client()}
	result, err := c.Generate(context.Background(), "test prompt")
	require.NoError(t, err)
	assert.Equal(t, `{"steps":[]}`, result)
}

func TestAnthropicClient_Generate_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"invalid key"}`))
	}))
	defer server.Close()

	c := &AnthropicClient{apiKey: "test-key", model: "test", endpoint: server.URL, client: server.Client()}
	_, err := c.Generate(context.Background(), "test")
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, 401, apiErr.StatusCode)
}

func TestAnthropicClient_Generate_NoTextBlock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"content": []map[string]interface{}{{"type": "image"}},
		}))
	}))
	defer server.Close()

	c := &AnthropicClient{apiKey: "test-key", model: "test", endpoint: server.URL, client: server.Client()}
	_, err := c.Generate(context.Background(), "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no text content")
}

func TestOllamaClient_Generate_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, false, req["stream"])
		assert.Equal(t, "json", req["format"])
		opts := req["options"].(map[string]interface{})
		assert.Equal(t, 0.2, opts["temperature"])

		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"response": `{"steps":[]}`,
		}))
	}))
	defer server.Close()

	c := NewOllamaClient(server.URL, "llama3.2:latest", 10*time.Second)
	result, err := c.Generate(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, `{"steps":[]}`, result)
}

// TEST-001: OpenAI empty choices
func TestOpenAIClient_Generate_NoChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{"choices": []interface{}{}}))
	}))
	defer server.Close()

	c := &OpenAIClient{apiKey: "test", model: "gpt-4o", endpoint: server.URL, client: server.Client()}
	_, err := c.Generate(context.Background(), "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no choices")
}

// TEST-005: Response size cap
func TestOpenAIClient_Generate_ResponseSizeCapped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Write more than maxResponseSize bytes
		w.Header().Set("Content-Type", "application/json")
		huge := make([]byte, maxResponseSize+1024)
		for i := range huge {
			huge[i] = 'x'
		}
		_, _ = w.Write(huge)
	}))
	defer server.Close()

	c := &OpenAIClient{apiKey: "test", model: "gpt-4o", endpoint: server.URL, client: server.Client()}
	_, err := c.Generate(context.Background(), "test")
	require.Error(t, err) // should fail to parse truncated body
}

func TestOllamaClient_Generate_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`internal error`))
	}))
	defer server.Close()

	c := NewOllamaClient(server.URL, "test", 10*time.Second)
	_, err := c.Generate(context.Background(), "test")
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, 500, apiErr.StatusCode)
}
