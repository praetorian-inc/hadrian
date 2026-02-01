package owasp

import (
	"context"
	"net/http"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIKeyAuth_UsesCustomHeader verifies that API Key authentication
// uses the custom header specified in auth config (e.g., X-API-Key)
// instead of the hardcoded Authorization header.
func TestAPIKeyAuth_UsesCustomHeader(t *testing.T) {
	// Create mock HTTP client that captures requests
	mockClient := &MockHTTPClient{
		responses: []*http.Response{
			newMockResponse(200, `{"data": "success"}`),
		},
	}

	executor := NewMutationExecutor(mockClient)

	// Create auth infos with API Key using custom header
	authInfos := map[string]*auth.AuthInfo{
		"user": {
			Method:   "api_key",
			Location: "header",
			KeyName:  "X-API-Key",        // Custom header, not Authorization
			Value:    "test-api-key-12345",
		},
	}

	tmpl := &templates.Template{
		ID: "test-apikey",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:      "/api/v1/data",
					Operation: "read",
					Auth:      "user",
				},
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"read",
		"user@example.com",
		"user@example.com",
		authInfos,
		"http://localhost:8080",
	)

	require.NoError(t, err)
	require.Len(t, mockClient.requests, 1, "Should have made 1 HTTP request")

	// Verify the custom header was used
	req := mockClient.requests[0]
	assert.Equal(t, "test-api-key-12345", req.Header.Get("X-API-Key"),
		"Should use X-API-Key header from auth config")
	assert.Empty(t, req.Header.Get("Authorization"),
		"Should NOT use Authorization header for API Key auth")
}

// TestAPIKeyAuth_InQueryParameter verifies that API Key authentication
// can use query parameters instead of headers.
func TestAPIKeyAuth_InQueryParameter(t *testing.T) {
	// Create mock HTTP client that captures requests
	mockClient := &MockHTTPClient{
		responses: []*http.Response{
			newMockResponse(200, `{"data": "success"}`),
		},
	}

	executor := NewMutationExecutor(mockClient)

	// Create auth infos with API Key using query parameter
	authInfos := map[string]*auth.AuthInfo{
		"user": {
			Method:   "api_key",
			Location: "query",
			KeyName:  "api_key",     // Query parameter name
			Value:    "test-key-67890",
		},
	}

	tmpl := &templates.Template{
		ID: "test-apikey-query",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:      "/api/v1/data",
					Operation: "read",
					Auth:      "user",
				},
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"read",
		"user@example.com",
		"user@example.com",
		authInfos,
		"http://localhost:8080",
	)

	require.NoError(t, err)
	require.Len(t, mockClient.requests, 1, "Should have made 1 HTTP request")

	// Verify the query parameter was used
	req := mockClient.requests[0]
	assert.Equal(t, "test-key-67890", req.URL.Query().Get("api_key"),
		"Should use api_key query parameter from auth config")
	assert.Empty(t, req.Header.Get("Authorization"),
		"Should NOT use Authorization header for API Key auth with query param")
	assert.Empty(t, req.Header.Get("X-API-Key"),
		"Should NOT use X-API-Key header when using query parameter")
}

// TestBearerAuth_StillUsesAuthorizationHeader verifies that Bearer token
// authentication continues to use the Authorization header as expected.
func TestBearerAuth_StillUsesAuthorizationHeader(t *testing.T) {
	// Create mock HTTP client that captures requests
	mockClient := &MockHTTPClient{
		responses: []*http.Response{
			newMockResponse(200, `{"data": "success"}`),
		},
	}

	executor := NewMutationExecutor(mockClient)

	// Create auth infos with Bearer token
	authInfos := map[string]*auth.AuthInfo{
		"user": {
			Method: "bearer",
			Value:  "Bearer test-bearer-token",
		},
	}

	tmpl := &templates.Template{
		ID: "test-bearer",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:      "/api/v1/data",
					Operation: "read",
					Auth:      "user",
				},
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"read",
		"user@example.com",
		"user@example.com",
		authInfos,
		"http://localhost:8080",
	)

	require.NoError(t, err)
	require.Len(t, mockClient.requests, 1, "Should have made 1 HTTP request")

	// Verify Authorization header is used for Bearer
	req := mockClient.requests[0]
	assert.Equal(t, "Bearer test-bearer-token", req.Header.Get("Authorization"),
		"Should use Authorization header for Bearer token")
}

// TestBasicAuth_StillUsesAuthorizationHeader verifies that Basic authentication
// continues to use the Authorization header as expected.
func TestBasicAuth_StillUsesAuthorizationHeader(t *testing.T) {
	// Create mock HTTP client that captures requests
	mockClient := &MockHTTPClient{
		responses: []*http.Response{
			newMockResponse(200, `{"data": "success"}`),
		},
	}

	executor := NewMutationExecutor(mockClient)

	// Create auth infos with Basic auth
	authInfos := map[string]*auth.AuthInfo{
		"user": {
			Method: "basic",
			Value:  "Basic dGVzdDpwYXNzd29yZA==", // base64 of test:password
		},
	}

	tmpl := &templates.Template{
		ID: "test-basic",
		TestPhases: &templates.TestPhases{
			Setup: templates.SetupPhases{
				&templates.Phase{
					Path:      "/api/v1/data",
					Operation: "read",
					Auth:      "user",
				},
			},
		},
	}

	_, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"read",
		"user@example.com",
		"user@example.com",
		authInfos,
		"http://localhost:8080",
	)

	require.NoError(t, err)
	require.Len(t, mockClient.requests, 1, "Should have made 1 HTTP request")

	// Verify Authorization header is used for Basic
	req := mockClient.requests[0]
	assert.Equal(t, "Basic dGVzdDpwYXNzd29yZA==", req.Header.Get("Authorization"),
		"Should use Authorization header for Basic auth")
}

