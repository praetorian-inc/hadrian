package graphql

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutor_Execute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req GraphQLRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Contains(t, req.Query, "user")

		response := GraphQLResponse{
			Data: json.RawMessage(`{"user":{"id":"1","name":"Test"}}`),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	executor := NewExecutor(http.DefaultClient, server.URL, nil)
	result, err := executor.Execute(
		context.Background(),
		"{ user(id: 1) { id name } }",
		nil,
		"",
		nil,
	)

	require.NoError(t, err)
	assert.Equal(t, 200, result.StatusCode)
	assert.Contains(t, result.Body, "user")
	assert.NotEmpty(t, result.RequestID)
}

func TestExecutor_WithAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		response := GraphQLResponse{Data: json.RawMessage(`{}`)}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	executor := NewExecutor(http.DefaultClient, server.URL, nil)
	_, err := executor.Execute(
		context.Background(),
		"{ hello }",
		nil,
		"",
		&AuthInfo{Method: "bearer", Value: "Bearer test-token"},
	)

	require.NoError(t, err)
}

func TestExecutor_ErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := GraphQLResponse{
			Errors: []GraphQLError{
				{Message: "Field not found"},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	executor := NewExecutor(http.DefaultClient, server.URL, nil)
	result, err := executor.Execute(
		context.Background(),
		"{ unknownField }",
		nil,
		"",
		nil,
	)

	require.NoError(t, err)
	assert.True(t, result.HasErrors())
	assert.Equal(t, "Field not found", result.Errors[0].Message)
}

func TestExecuteResult_IsSuccess(t *testing.T) {
	// Success case
	result := &ExecuteResult{
		StatusCode: 200,
		Errors:     nil,
	}
	assert.True(t, result.IsSuccess())

	// Error status code
	result.StatusCode = 500
	assert.False(t, result.IsSuccess())

	// GraphQL errors
	result.StatusCode = 200
	result.Errors = []GraphQLError{{Message: "error"}}
	assert.False(t, result.IsSuccess())
}

func TestExecutor_ResponseSizeLimit(t *testing.T) {
	// Test that responses larger than 10MB are rejected
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Write exactly 10MB + 1 byte to exceed limit
		// First write the JSON structure opening
		_, _ = w.Write([]byte(`{"data":"`))

		// Write large data
		largeData := make([]byte, 11*1024*1024) // 11MB
		for i := range largeData {
			largeData[i] = 'x'
		}
		_, _ = w.Write(largeData)

		// Close JSON structure
		_, _ = w.Write([]byte(`"}`))
	}))
	defer server.Close()

	executor := NewExecutor(http.DefaultClient, server.URL, nil)
	_, err := executor.Execute(
		context.Background(),
		"{ test }",
		nil,
		"",
		nil,
	)

	// Should fail due to size limit
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}
