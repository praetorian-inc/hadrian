package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropicClient_Name(t *testing.T) {
	client := &AnthropicClient{}
	assert.Equal(t, "anthropic", client.Name())
}

func TestNewAnthropicClient_RequiresAPIKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	_, err := NewAnthropicClient("", "claude-sonnet-4-6", 120*time.Second, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ANTHROPIC_API_KEY not set")
}

func TestNewAnthropicClient_UsesEnvKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
	client, err := NewAnthropicClient("", "", 0, "")
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-test-123", client.apiKey)
	assert.Equal(t, "claude-sonnet-4-6", client.model)
}

func TestAnthropicClient_Triage_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "test-key", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": `{"is_vulnerability":true,"confidence":0.85,"reasoning":"BOLA detected","severity":"CRITICAL","recommendations":"Add authz"}`},
			},
		}))
	}))
	defer server.Close()

	client := &AnthropicClient{
		apiKey:   "test-key",
		model:    "claude-sonnet-4-6",
		endpoint: server.URL,
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}

	result, err := client.Triage(context.Background(), testTriageRequest())
	require.NoError(t, err)
	assert.True(t, result.IsVulnerability)
	assert.Equal(t, 0.85, result.Confidence)
	assert.Equal(t, "anthropic", result.Provider)
	assert.Equal(t, model.SeverityCritical, result.Severity)
}

func TestAnthropicClient_Triage_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"invalid key"}`))
	}))
	defer server.Close()

	client := &AnthropicClient{
		apiKey:   "test-key",
		model:    "claude-sonnet-4-6",
		endpoint: server.URL,
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}

	_, err := client.Triage(context.Background(), testTriageRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestAnthropicClient_Triage_NoTextContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "image", "text": "data"},
			},
		}))
	}))
	defer server.Close()

	client := &AnthropicClient{
		apiKey:   "test-key",
		model:    "claude-sonnet-4-6",
		endpoint: server.URL,
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}

	_, err := client.Triage(context.Background(), testTriageRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no text content")
}

func TestAnthropicClient_Triage_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{truncated`))
	}))
	defer server.Close()

	client := &AnthropicClient{
		apiKey:   "test-key",
		model:    "test",
		endpoint: server.URL,
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}

	_, err := client.Triage(context.Background(), testTriageRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse Anthropic response")
}
