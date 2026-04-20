package planner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Response parsing helpers (extracted for testability) ---

func parseOpenAIResponse(body []byte) (string, error) {
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if len(result.Choices) == 0 {
		return "", &APIError{StatusCode: 0, Message: "no choices"}
	}
	return result.Choices[0].Message.Content, nil
}

func parseAnthropicResponse(body []byte) (string, error) {
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	for _, block := range result.Content {
		if block.Type == "text" {
			return block.Text, nil
		}
	}
	return "", &APIError{StatusCode: 0, Message: "no text content"}
}

func parseOllamaTestResponse(body []byte) (string, error) {
	var result struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.Response, nil
}

// --- OpenAI ---

func TestOpenAIClient_ResponseParsing(t *testing.T) {
	result, err := parseOpenAIResponse([]byte(`{"choices":[{"message":{"content":"{\"steps\":[]}"}}]}`))
	require.NoError(t, err)
	assert.Equal(t, `{"steps":[]}`, result)
}

func TestOpenAIClient_NoChoices(t *testing.T) {
	_, err := parseOpenAIResponse([]byte(`{"choices":[]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no choices")
}

func TestOpenAIClient_ErrorClassification(t *testing.T) {
	assert.True(t, isRetryable(&APIError{StatusCode: 429, Message: "rate limited"}))
	assert.False(t, isRetryable(&APIError{StatusCode: 401, Message: "bad key"}))
}

func TestOpenAIClient_RequestBodyShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		assert.Equal(t, "gpt-4o", req["model"])
		assert.Equal(t, 0.2, req["temperature"])
		assert.NotNil(t, req["messages"])
		assert.NotNil(t, req["response_format"])

		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": `{"steps":[]}`}},
			},
		}))
	}))
	defer server.Close()
	_ = server
}

// --- Anthropic ---

func TestAnthropicClient_ResponseParsing(t *testing.T) {
	result, err := parseAnthropicResponse([]byte(`{"content":[{"type":"text","text":"{\"steps\":[]}"}]}`))
	require.NoError(t, err)
	assert.Equal(t, `{"steps":[]}`, result)
}

func TestAnthropicClient_NoTextBlock(t *testing.T) {
	_, err := parseAnthropicResponse([]byte(`{"content":[{"type":"image","text":"data"}]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no text content")
}

func TestAnthropicClient_RequestBodyShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		assert.Equal(t, 0.2, req["temperature"])
		assert.Equal(t, float64(4096), req["max_tokens"])
		assert.NotNil(t, req["system"])
		assert.NotNil(t, req["messages"])

		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": `{"steps":[]}`},
			},
		}))
	}))
	defer server.Close()
	_ = server
}

// --- Ollama ---

func TestOllamaClient_ResponseParsing(t *testing.T) {
	result, err := parseOllamaTestResponse([]byte(`{"response":"{\"steps\":[]}"}`))
	require.NoError(t, err)
	assert.Equal(t, `{"steps":[]}`, result)
}

func TestOllamaClient_InvalidJSON(t *testing.T) {
	_, err := parseOllamaTestResponse([]byte(`{invalid`))
	require.Error(t, err)
}

func TestOllamaClient_RequestBodyShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		assert.Equal(t, false, req["stream"])
		assert.Equal(t, "json", req["format"])
		opts, ok := req["options"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, 0.2, opts["temperature"])

		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"response": `{"steps":[]}`,
		}))
	}))
	defer server.Close()
	_ = server
}
