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

func TestOpenAIClient_Name(t *testing.T) {
	client := &OpenAIClient{}
	assert.Equal(t, "openai", client.Name())
}

func TestNewOpenAIClient_RequiresAPIKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	_, err := NewOpenAIClient("", "gpt-4o", 120*time.Second, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OPENAI_API_KEY not set")
}

func TestNewOpenAIClient_UsesEnvKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test-123")
	client, err := NewOpenAIClient("", "", 0, "")
	require.NoError(t, err)
	assert.Equal(t, "sk-test-123", client.apiKey)
	assert.Equal(t, "gpt-4o", client.model)
}

func TestOpenAIClient_Triage_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		var req map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "gpt-4o", req["model"])
		assert.Equal(t, 0.2, req["temperature"])

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{
					"content": `{"is_vulnerability":true,"confidence":0.9,"reasoning":"BOLA","severity":"HIGH","recommendations":"Fix it"}`,
				}},
			},
		}))
	}))
	defer server.Close()

	client := &OpenAIClient{
		apiKey:   "test-key",
		model:    "gpt-4o",
		endpoint: server.URL,
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}

	result, err := client.Triage(context.Background(), testTriageRequest())
	require.NoError(t, err)
	assert.True(t, result.IsVulnerability)
	assert.Equal(t, 0.9, result.Confidence)
	assert.Equal(t, "openai", result.Provider)
	assert.Equal(t, model.SeverityHigh, result.Severity)
}

func TestOpenAIClient_Triage_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer server.Close()

	client := &OpenAIClient{
		apiKey:   "test-key",
		model:    "gpt-4o",
		endpoint: server.URL,
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}

	_, err := client.Triage(context.Background(), testTriageRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "429")
}

func TestOpenAIClient_Triage_ParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": "not json"}},
			},
		}))
	}))
	defer server.Close()

	client := &OpenAIClient{
		apiKey:   "test-key",
		model:    "gpt-4o",
		endpoint: server.URL,
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}

	_, err := client.Triage(context.Background(), testTriageRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse LLM JSON response")
}

func TestOpenAIClient_Triage_EmptyChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{},
		}))
	}))
	defer server.Close()

	client := &OpenAIClient{
		apiKey:   "test-key",
		model:    "gpt-4o",
		endpoint: server.URL,
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}

	_, err := client.Triage(context.Background(), testTriageRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no choices")
}

func TestOpenAIClient_Triage_MalformedEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{truncated`))
	}))
	defer server.Close()

	client := &OpenAIClient{
		apiKey:   "test-key",
		model:    "gpt-4o",
		endpoint: server.URL,
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 10 * time.Second},
	}

	_, err := client.Triage(context.Background(), testTriageRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse OpenAI response")
}
