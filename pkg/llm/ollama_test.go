package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOllamaClient_Name(t *testing.T) {
	client := NewOllamaClient()
	assert.Equal(t, "ollama", client.Name())
}

func TestNewOllamaClient_UsesDefaultHost(t *testing.T) {
	// Arrange
	_ = os.Unsetenv("OLLAMA_HOST")

	// Act
	client := NewOllamaClient()

	// Assert
	assert.NotNil(t, client)
	assert.Equal(t, "http://localhost:11434", client.baseURL)
}

func TestNewOllamaClient_UsesCustomHost(t *testing.T) {
	// Arrange
	customHost := "http://localhost:11435"
	t.Setenv("OLLAMA_HOST", customHost)

	// Act
	client := NewOllamaClient()

	// Assert
	assert.NotNil(t, client)
	assert.Equal(t, customHost, client.baseURL)
}

func TestNewOllamaClientWithConfig_CustomHostAndModel(t *testing.T) {
	// Arrange
	customHost := "http://localhost:11435"
	customModel := "llama3.2:latest"
	_ = os.Unsetenv("OLLAMA_HOST")
	_ = os.Unsetenv("OLLAMA_MODEL")

	// Act
	client := NewOllamaClientWithConfig(customHost, customModel, 180*time.Second, "")

	// Assert
	assert.NotNil(t, client)
	assert.Equal(t, customHost, client.baseURL)
	assert.Equal(t, customModel, client.model)
	assert.Equal(t, 180*time.Second, client.client.Timeout)
}

func TestNewOllamaClientWithConfig_EmptyModelUsesEnvOrDefault(t *testing.T) {
	// Arrange
	customHost := "http://localhost:11435"
	_ = os.Unsetenv("OLLAMA_MODEL")

	// Act
	client := NewOllamaClientWithConfig(customHost, "", 180*time.Second, "")

	// Assert
	assert.NotNil(t, client)
	assert.Equal(t, customHost, client.baseURL)
	assert.Equal(t, "llama3.2:latest", client.model) // Should use default
	assert.Equal(t, 180*time.Second, client.client.Timeout)
}

func TestNewOllamaClientWithConfig_EmptyModelUsesEnv(t *testing.T) {
	// Arrange
	customHost := "http://localhost:11435"
	envModel := "custom-model:v1"
	t.Setenv("OLLAMA_MODEL", envModel)

	// Act
	client := NewOllamaClientWithConfig(customHost, "", 180*time.Second, "")

	// Assert
	assert.NotNil(t, client)
	assert.Equal(t, customHost, client.baseURL)
	assert.Equal(t, envModel, client.model) // Should use env var
	assert.Equal(t, 180*time.Second, client.client.Timeout)
}

func TestNewOllamaClientWithConfig_UsesCustomTimeout(t *testing.T) {
	// Arrange
	customHost := "http://localhost:11435"
	customModel := "llama3.2:latest"
	customTimeout := 300 * time.Second

	// Act
	client := NewOllamaClientWithConfig(customHost, customModel, customTimeout, "")

	// Assert
	assert.NotNil(t, client)
	assert.Equal(t, customHost, client.baseURL)
	assert.Equal(t, customModel, client.model)
	assert.Equal(t, customTimeout, client.client.Timeout)
}

func TestOllamaClient_Triage_Success(t *testing.T) {
	// Arrange - Mock Ollama server returning valid response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/generate", r.URL.Path)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify request body structure
		var req map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "llama3.2:latest", req["model"])
		assert.False(t, req["stream"].(bool))
		assert.Equal(t, "json", req["format"])

		// Return valid Ollama response
		resp := map[string]interface{}{
			"model": "llama3.2:latest",
			"response": `{
				"is_vulnerability": true,
				"confidence": 0.85,
				"reasoning": "The attacker role can access victim's private data",
				"severity": "HIGH",
				"recommendations": "Implement proper role-based authorization"
			}`,
			"done": true,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClientWithURL(server.URL)
	req := createTestTriageRequest()

	// Act
	result, err := client.Triage(context.Background(), req)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "ollama", result.Provider)
	assert.True(t, result.IsVulnerability)
	assert.Equal(t, 0.85, result.Confidence)
	assert.Contains(t, result.Reasoning, "attacker role")
	assert.Equal(t, model.SeverityHigh, result.Severity)
	assert.Contains(t, result.Recommendations, "authorization")
}

func TestOllamaClient_Triage_ParseError(t *testing.T) {
	// Arrange - Mock server returning invalid JSON in response field
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"model":    "llama3.2:latest",
			"response": `{invalid json`,
			"done":     true,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClientWithURL(server.URL)
	req := createTestTriageRequest()

	// Act
	result, err := client.Triage(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to parse LLM JSON response")
}

func TestOllamaClient_Triage_HTTPError(t *testing.T) {
	// Arrange - Mock server returning 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
	}))
	defer server.Close()

	client := NewOllamaClientWithURL(server.URL)
	req := createTestTriageRequest()

	// Act
	result, err := client.Triage(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "ollama API returned status 500")
}

func TestOllamaClient_BuildPrompt(t *testing.T) {
	// Arrange
	client := NewOllamaClient()
	req := &TriageRequest{
		Finding: &model.Finding{
			Category: "IDOR",
			Method:   "GET",
			Endpoint: "/api/users/123",
			Evidence: model.Evidence{
				Response: model.HTTPResponse{
					StatusCode: 200,
					Body:       `{"email":"user@example.com","ssn":"123-45-6789"}`,
				},
			},
		},
		AttackerRole: &roles.Role{
			Name:        "guest",
			Permissions: []roles.Permission{{Raw: "read:public"}},
		},
		VictimRole: &roles.Role{
			Name:        "admin",
			Permissions: []roles.Permission{{Raw: "read:all"}, {Raw: "write:all"}},
		},
	}

	// Act
	prompt := client.buildPrompt(req)

	// Assert - Verify structure
	assert.Contains(t, prompt, "You are a security expert")
	assert.Contains(t, prompt, "FINDING:")
	assert.Contains(t, prompt, "Category: IDOR")
	assert.Contains(t, prompt, "GET /api/users/123")
	assert.Contains(t, prompt, "Attacker Role: guest")
	assert.Contains(t, prompt, "Victim Role: admin")

	// Verify PII redaction happened
	assert.Contains(t, prompt, "RESPONSE (PII REDACTED)")
	// Email and SSN should be redacted
	assert.NotContains(t, prompt, "user@example.com")
	assert.NotContains(t, prompt, "123-45-6789")
}

func TestOllamaClient_MapSeverity(t *testing.T) {
	client := NewOllamaClient()

	tests := []struct {
		name     string
		input    string
		expected model.Severity
	}{
		{"critical uppercase", "CRITICAL", model.SeverityCritical},
		{"critical lowercase", "critical", model.SeverityCritical},
		{"high uppercase", "HIGH", model.SeverityHigh},
		{"high lowercase", "high", model.SeverityHigh},
		{"medium uppercase", "MEDIUM", model.SeverityMedium},
		{"medium lowercase", "medium", model.SeverityMedium},
		{"low uppercase", "LOW", model.SeverityLow},
		{"low lowercase", "low", model.SeverityLow},
		{"unknown defaults to medium", "unknown", model.SeverityMedium},
		{"empty defaults to medium", "", model.SeverityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.mapSeverity(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOllamaClient_ParseResponse_InvalidOllamaJSON(t *testing.T) {
	// Arrange
	client := NewOllamaClient()
	invalidJSON := `{invalid json`

	// Act
	result, err := client.parseResponse(strings.NewReader(invalidJSON))

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to decode Ollama response")
}

func TestParseStringOrArray(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "string value",
			input:    `"simple string"`,
			expected: "simple string",
		},
		{
			name:     "array with single item",
			input:    `["single item"]`,
			expected: "single item",
		},
		{
			name:     "array with multiple items",
			input:    `["item1", "item2", "item3"]`,
			expected: "item1; item2; item3",
		},
		{
			name:     "empty array",
			input:    `[]`,
			expected: "",
		},
		{
			name:     "empty string",
			input:    `""`,
			expected: "",
		},
		{
			name:     "null value",
			input:    `null`,
			expected: "",
		},
		{
			name:     "invalid JSON",
			input:    `{invalid`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseStringOrArray(json.RawMessage(tt.input))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOllamaClient_Triage_RecommendationsAsArray(t *testing.T) {
	// Arrange - Mock Ollama server returning recommendations as array
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return Ollama response with recommendations as array
		resp := map[string]interface{}{
			"model": "llama3.2:latest",
			"response": `{
				"is_vulnerability": true,
				"confidence": 0.85,
				"reasoning": "The attacker role can access victim's private data",
				"severity": "HIGH",
				"recommendations": ["Implement proper role-based authorization", "Add permission checks", "Validate user identity"]
			}`,
			"done": true,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClientWithURL(server.URL)
	req := createTestTriageRequest()

	// Act
	result, err := client.Triage(context.Background(), req)

	// Assert - Should handle array and join with "; "
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "ollama", result.Provider)
	assert.True(t, result.IsVulnerability)
	assert.Equal(t, 0.85, result.Confidence)
	assert.Contains(t, result.Reasoning, "attacker role")
	assert.Equal(t, model.SeverityHigh, result.Severity)
	assert.Equal(t, "Implement proper role-based authorization; Add permission checks; Validate user identity", result.Recommendations)
}

func TestOllamaClient_Triage_ReasoningAsArray(t *testing.T) {
	// Arrange - Mock Ollama server returning reasoning as array
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return Ollama response with reasoning as array
		resp := map[string]interface{}{
			"model": "llama3.2:latest",
			"response": `{
				"is_vulnerability": true,
				"confidence": 0.85,
				"reasoning": ["Attacker has insufficient permissions", "Response contains sensitive data", "No authorization check present"],
				"severity": "HIGH",
				"recommendations": "Implement proper role-based authorization"
			}`,
			"done": true,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClientWithURL(server.URL)
	req := createTestTriageRequest()

	// Act
	result, err := client.Triage(context.Background(), req)

	// Assert - Should handle array and join with "; "
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "ollama", result.Provider)
	assert.True(t, result.IsVulnerability)
	assert.Equal(t, 0.85, result.Confidence)
	assert.Equal(t, "Attacker has insufficient permissions; Response contains sensitive data; No authorization check present", result.Reasoning)
	assert.Equal(t, model.SeverityHigh, result.Severity)
	assert.Contains(t, result.Recommendations, "authorization")
}

func TestOllamaClient_Triage_BothFieldsAsArray(t *testing.T) {
	// Arrange - Mock Ollama server returning both fields as arrays
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return Ollama response with both reasoning and recommendations as arrays
		resp := map[string]interface{}{
			"model": "llama3.2:latest",
			"response": `{
				"is_vulnerability": true,
				"confidence": 0.85,
				"reasoning": ["Point 1", "Point 2"],
				"severity": "HIGH",
				"recommendations": ["Fix 1", "Fix 2"]
			}`,
			"done": true,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOllamaClientWithURL(server.URL)
	req := createTestTriageRequest()

	// Act
	result, err := client.Triage(context.Background(), req)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "Point 1; Point 2", result.Reasoning)
	assert.Equal(t, "Fix 1; Fix 2", result.Recommendations)
}

// Helper to create test triage request
func createTestTriageRequest() *TriageRequest {
	return &TriageRequest{
		Finding: &model.Finding{
			Category: "IDOR",
			Method:   "GET",
			Endpoint: "/api/users/123",
			Evidence: model.Evidence{
				Response: model.HTTPResponse{
					StatusCode: 200,
					Body:       `{"id":123,"name":"victim"}`,
				},
			},
		},
		AttackerRole: &roles.Role{
			Name:        "guest",
			Permissions: []roles.Permission{{Raw: "read:public"}},
		},
		VictimRole: &roles.Role{
			Name:        "admin",
			Permissions: []roles.Permission{{Raw: "read:all"}},
		},
	}
}
