package owasp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecuteMutation_TracksRequestIDs verifies that request IDs are tracked per phase
func TestExecuteMutation_TracksRequestIDs(t *testing.T) {
	// Setup mock server that captures and verifies request IDs
	var setupRequestID, attackRequestID, verifyRequestID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Hadrian-Request-Id")
		assert.NotEmpty(t, requestID, "X-Hadrian-Request-Id header should be set")

		// Capture request IDs based on path
		switch r.URL.Path {
		case "/api/videos":
			setupRequestID = requestID
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id": "video123"}`))
		case "/api/videos/video123":
			if r.Header.Get("Authorization") == "Bearer attacker-token" {
				attackRequestID = requestID
				// Attack succeeds (BOLA vulnerability)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"id": "video123", "title": "Private Video"}`))
			} else {
				verifyRequestID = requestID
				// Verify succeeds
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"id": "video123", "title": "Private Video"}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create template with three phases
	tmpl := &templates.Template{
		ID: "bola-test",
		Info: templates.TemplateInfo{
			Name:     "BOLA Test",
			Category: "API1",
			Severity: "HIGH",
		},
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Operation:          "create",
					Path:               "/api/videos",
					Auth:               "victim",
					StoreResponseField: "id",
				},
			},
			Attack: &templates.Phase{
				Operation:      "read",
				Path:           "/api/videos/{id}",
				Auth:           "attacker",
				UseStoredField: "id",
				ExpectedStatus: http.StatusOK,
			},
			Verify: &templates.Phase{
				Operation:      "read",
				Path:           "/api/videos/{id}",
				Auth:           "victim",
				UseStoredField: "id",
				ExpectedStatus: http.StatusOK,
			},
		},
	}

	// Execute mutation test
	executor := NewMutationExecutor(http.DefaultClient)
	result, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"create",
		"attacker",
		"victim",
		makeAuthInfos("attacker-token", "victim-token"),
		server.URL,
	)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify vulnerability was detected
	assert.True(t, result.Matched, "BOLA vulnerability should be detected")

	// Verify request IDs were tracked for each phase
	require.NotNil(t, result.RequestIDs, "RequestIDs should not be nil")

	// Verify Setup phase has request IDs
	require.Len(t, result.RequestIDs.Setup, 1, "Setup phase should have 1 request ID")
	assert.NotEmpty(t, result.RequestIDs.Setup[0])
	assert.Equal(t, setupRequestID, result.RequestIDs.Setup[0], "Setup request ID should match")

	// Verify Attack phase has request IDs
	require.Len(t, result.RequestIDs.Attack, 1, "Attack phase should have 1 request ID")
	assert.NotEmpty(t, result.RequestIDs.Attack[0])
	assert.Equal(t, attackRequestID, result.RequestIDs.Attack[0], "Attack request ID should match")

	// Verify Verify phase has request IDs
	require.Len(t, result.RequestIDs.Verify, 1, "Verify phase should have 1 request ID")
	assert.NotEmpty(t, result.RequestIDs.Verify[0])
	assert.Equal(t, verifyRequestID, result.RequestIDs.Verify[0], "Verify request ID should match")

	// Verify all request IDs are unique
	allIDs := []string{
		result.RequestIDs.Setup[0],
		result.RequestIDs.Attack[0],
		result.RequestIDs.Verify[0],
	}
	seen := make(map[string]bool)
	for _, id := range allIDs {
		assert.False(t, seen[id], "Request IDs should be unique")
		seen[id] = true
	}

	// Verify UUID format for all request IDs
	for _, id := range allIDs {
		parts := strings.Split(id, "-")
		assert.Len(t, parts, 5, "Request ID should have UUID format (8-4-4-4-12)")
	}
}

// TestExecuteMutation_NoRequestIDsWhenNoPhases verifies behavior when no phases are executed
func TestExecuteMutation_NoRequestIDsWhenNoPhases(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Template with no phases
	tmpl := &templates.Template{
		ID: "test",
		Info: templates.TemplateInfo{
			Name:     "Test",
			Category: "API1",
			Severity: "LOW",
		},
		TestPhases: nil,
	}

	executor := NewMutationExecutor(http.DefaultClient)
	result, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"read",
		"attacker",
		"victim",
		makeAuthInfos("", ""),
		server.URL,
	)

	require.Error(t, err, "Should error when template has no phases")
	require.NotNil(t, result)
	require.NotNil(t, result.RequestIDs, "RequestIDs struct should be initialized even on error")
}
