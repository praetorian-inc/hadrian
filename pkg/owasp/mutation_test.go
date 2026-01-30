package owasp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// MockHTTPClient for testing
type MockHTTPClient struct {
	responses []*http.Response
	index     int
	requests  []*http.Request // Capture requests for verification
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)
	if m.index >= len(m.responses) {
		return nil, nil
	}
	resp := m.responses[m.index]
	m.index++
	return resp, nil
}

func newMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// Helper function to create bearer token auth infos for tests
func makeAuthInfos(attackerToken, victimToken string) map[string]*auth.AuthInfo {
	infos := make(map[string]*auth.AuthInfo)
	if attackerToken != "" {
		infos["attacker"] = &auth.AuthInfo{
			Method: "bearer",
			Value:  "Bearer " + attackerToken,
		}
	}
	if victimToken != "" {
		infos["victim"] = &auth.AuthInfo{
			Method: "bearer",
			Value:  "Bearer " + victimToken,
		}
	}
	return infos
}

func TestNewMutationExecutor(t *testing.T) {
	client := &MockHTTPClient{}
	executor := NewMutationExecutor(client)

	assert.NotNil(t, executor)
	assert.Equal(t, client, executor.httpClient)
	assert.NotNil(t, executor.tracker)
}

func TestExecuteMutation_Success(t *testing.T) {
	// Setup phase returns 201, creates resource
	// Attack phase with stored resource returns 200 (vulnerability)
	// Verify phase confirms resource still accessible
	setupResp := newMockResponse(201, `{"id": "resource123"}`)
	attackResp := newMockResponse(200, `{"data": "accessed"}`)
	verifyResp := newMockResponse(200, `{"data": "accessed"}`)

	client := &MockHTTPClient{
		responses: []*http.Response{setupResp, attackResp, verifyResp},
	}

	executor := NewMutationExecutor(client)

	tmpl := &templates.Template{
		ID: "api1-bola",
		TestPhases: &templates.TestPhases{
			Setup: &templates.Phase{
				Path:               "/api/v1/resources",
				Operation:          "create",
				Auth:               "victim",
				Data:               map[string]string{"name": "test"},
				StoreResponseField: "id",
			},
			Attack: &templates.Phase{
				Path:           "/api/v1/resources/{id}",
				Operation:      "read",
				Auth:           "attacker",
				UseStoredField: "id",
				ExpectedStatus: 200, // Success indicates vulnerability (attacker can read)
			},
			Verify: &templates.Phase{
				Path:           "/api/v1/resources/{id}",
				Operation:      "read",
				Auth:           "victim",
				UseStoredField: "id",
				ExpectedStatus: 200,
			},
		},
	}

	result, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"create",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "api1-bola", result.TemplateID)
	assert.True(t, result.Matched) // Status 200 on attack phase = vulnerability found
	assert.Equal(t, 200, result.AttackResponse.StatusCode)
}

func TestExecuteMutation_Secure(t *testing.T) {
	// Setup succeeds
	// Attack returns 403 (attacker denied)
	// Verify succeeds
	setupResp := newMockResponse(201, `{"id": "resource123"}`)
	attackResp := newMockResponse(403, `{"error": "forbidden"}`)
	verifyResp := newMockResponse(200, `{"data": "accessed"}`)

	client := &MockHTTPClient{
		responses: []*http.Response{setupResp, attackResp, verifyResp},
	}

	executor := NewMutationExecutor(client)

	tmpl := &templates.Template{
		ID: "api1-bola",
		TestPhases: &templates.TestPhases{
			Setup: &templates.Phase{
				Path:               "/api/v1/resources",
				Operation:          "create",
				Auth:               "victim",
				Data:               map[string]string{"name": "test"},
				StoreResponseField: "id",
			},
			Attack: &templates.Phase{
				Path:           "/api/v1/resources/{id}",
				Operation:      "read",
				Auth:           "attacker",
				UseStoredField: "id",
				ExpectedStatus: 200,
			},
			Verify: &templates.Phase{
				Path:           "/api/v1/resources/{id}",
				Operation:      "read",
				Auth:           "victim",
				UseStoredField: "id",
				ExpectedStatus: 200,
			},
		},
	}

	result, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"create",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Matched) // Status 403 on attack phase = secure
	assert.Equal(t, 403, result.AttackResponse.StatusCode)
}

func TestExtractField(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		fieldPath string
		expected  string
	}{
		{
			name:      "simple field",
			body:      `{"id": "resource123"}`,
			fieldPath: "id",
			expected:  "resource123",
		},
		{
			name:      "nested field",
			body:      `{"data": {"id": "nested123"}}`,
			fieldPath: "data.id",
			expected:  "nested123",
		},
		{
			name:      "field not found",
			body:      `{"id": "resource123"}`,
			fieldPath: "missing",
			expected:  "",
		},
		{
			name:      "array element",
			body:      `{"items": [{"id": "first"}, {"id": "second"}]}`,
			fieldPath: "items.0.id",
			expected:  "first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractField(tt.body, tt.fieldPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchesDetectionConditions(t *testing.T) {
	tests := []struct {
		name      string
		phase     *templates.Phase
		statusCode int
		body      string
		expected  bool
	}{
		{
			name: "status matches",
			phase: &templates.Phase{
				ExpectedStatus: 200,
			},
			statusCode: 200,
			body:       "",
			expected:   true,
		},
		{
			name: "status mismatch",
			phase: &templates.Phase{
				ExpectedStatus: 200,
			},
			statusCode: 403,
			body:       "",
			expected:   false,
		},
		{
			name: "field matches expected value",
			phase: &templates.Phase{
				CheckField:    "id",
				ExpectedValue: "resource123",
			},
			statusCode: 200,
			body:       `{"id": "resource123"}`,
			expected:   true,
		},
		{
			name: "field value mismatch",
			phase: &templates.Phase{
				CheckField:    "id",
				ExpectedValue: "resource123",
			},
			statusCode: 200,
			body:       `{"id": "different"}`,
			expected:   false,
		},
		{
			name: "status and field both match",
			phase: &templates.Phase{
				ExpectedStatus: 200,
				CheckField:     "id",
				ExpectedValue:  "resource123",
			},
			statusCode: 200,
			body:       `{"id": "resource123"}`,
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesDetectionConditions(tt.phase, tt.statusCode, tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClearTracker(t *testing.T) {
	client := &MockHTTPClient{}
	executor := NewMutationExecutor(client)

	// Store a resource
	executor.tracker.StoreResource("key1", "value1")
	assert.Equal(t, "value1", executor.tracker.GetResource("key1"))

	// Clear the tracker
	executor.ClearTracker()

	// Resource should be gone
	assert.Equal(t, "", executor.tracker.GetResource("key1"))
}

func TestExecuteMutation_StoresResourceID(t *testing.T) {
	setupResp := newMockResponse(201, `{"id": "resource123"}`)
	attackResp := newMockResponse(200, `{"data": "accessed"}`)
	verifyResp := newMockResponse(200, `{"data": "accessed"}`)

	client := &MockHTTPClient{
		responses: []*http.Response{setupResp, attackResp, verifyResp},
	}

	executor := NewMutationExecutor(client)

	tmpl := &templates.Template{
		ID: "api1-bola",
		TestPhases: &templates.TestPhases{
			Setup: &templates.Phase{
				Path:               "/api/v1/resources",
				Operation:          "create",
				Auth:               "victim",
				StoreResponseField: "id",
			},
			Attack: &templates.Phase{
				Path:           "/api/v1/resources/{id}",
				Operation:      "read",
				Auth:           "attacker",
				UseStoredField: "id",
				ExpectedStatus: 200,
			},
			Verify: &templates.Phase{
				Path:           "/api/v1/resources/{id}",
				Operation:      "read",
				Auth:           "victim",
				UseStoredField: "id",
				ExpectedStatus: 200,
			},
		},
	}

	result, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"create",
		"attacker@example.com",
		"victim@example.com",
		makeAuthInfos("attacker-token", "victim-token"),
		"http://localhost:8080",
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
	// Verify resource ID was extracted and stored
	assert.Equal(t, "resource123", result.ResourceID)
	// Verify it's also tracked by field name (StoreResponseField)
	assert.Equal(t, "resource123", executor.tracker.GetResource("id"))
}

func TestOperationToMethod(t *testing.T) {
	tests := []struct {
		operation string
		expected  string
	}{
		{"create", http.MethodPost},
		{"read", http.MethodGet},
		{"update", http.MethodPut},
		{"delete", http.MethodDelete},
		{"", http.MethodGet}, // Default to GET
		{"unknown", http.MethodGet},
		{"CREATE", http.MethodPost}, // Case insensitive
		{"Read", http.MethodGet},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			result := operationToMethod(tt.operation)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExecutePhase_UsesCustomPath(t *testing.T) {
	resp := newMockResponse(200, `{"data": "test"}`)
	client := &MockHTTPClient{
		responses: []*http.Response{resp},
	}

	executor := NewMutationExecutor(client)

	phase := &templates.Phase{
		Path:      "/api/v1/orders",
		Operation: "read",
		Auth:      "victim",
	}

	_, err := executor.executePhase(
		context.Background(),
		"http://localhost:8080",
		phase,
		"victim",
		makeAuthInfos("", "victim-token"),
	)

	require.NoError(t, err)
	require.Len(t, client.requests, 1)

	// Verify the request used the custom path
	assert.Equal(t, "http://localhost:8080/api/v1/orders", client.requests[0].URL.String())
	assert.Equal(t, http.MethodGet, client.requests[0].Method)
}

func TestExecutePhase_SubstitutesStoredValues(t *testing.T) {
	resp := newMockResponse(200, `{"data": "test"}`)
	client := &MockHTTPClient{
		responses: []*http.Response{resp},
	}

	executor := NewMutationExecutor(client)

	// Store a resource ID first
	executor.tracker.StoreResource("id", "resource123")

	phase := &templates.Phase{
		Path:           "/api/v1/orders/{id}",
		Operation:      "read",
		Auth:           "attacker",
		UseStoredField: "id",
	}

	_, err := executor.executePhase(
		context.Background(),
		"http://localhost:8080",
		phase,
		"attacker",
		makeAuthInfos("attacker-token", ""),
	)

	require.NoError(t, err)
	require.Len(t, client.requests, 1)

	// Verify stored value was substituted into path
	assert.Equal(t, "http://localhost:8080/api/v1/orders/resource123", client.requests[0].URL.String())
}

func TestExecutePhase_MapsOperationToHTTPMethod(t *testing.T) {
	tests := []struct {
		operation      string
		expectedMethod string
	}{
		{"create", http.MethodPost},
		{"read", http.MethodGet},
		{"update", http.MethodPut},
		{"delete", http.MethodDelete},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			resp := newMockResponse(200, `{}`)
			client := &MockHTTPClient{
				responses: []*http.Response{resp},
			}

			executor := NewMutationExecutor(client)

			phase := &templates.Phase{
				Path:      "/api/v1/resources",
				Operation: tt.operation,
				Auth:      "victim",
			}

			_, err := executor.executePhase(
				context.Background(),
				"http://localhost:8080",
				phase,
				"victim",
				makeAuthInfos("", "token"),
			)

			require.NoError(t, err)
			require.Len(t, client.requests, 1)
			assert.Equal(t, tt.expectedMethod, client.requests[0].Method)
		})
	}
}

func TestExecutePhase_UsesCorrectAuthToken(t *testing.T) {
	resp := newMockResponse(200, `{}`)
	client := &MockHTTPClient{
		responses: []*http.Response{resp},
	}

	executor := NewMutationExecutor(client)

	phase := &templates.Phase{
		Path:      "/api/v1/resources",
		Operation: "read",
		Auth:      "attacker",
	}

	authInfos := map[string]*auth.AuthInfo{
		"attacker": {
			Method: "bearer",
			Value:  "Bearer attacker-secret-token",
		},
		"victim": {
			Method: "bearer",
			Value:  "Bearer victim-secret-token",
		},
	}

	_, err := executor.executePhase(
		context.Background(),
		"http://localhost:8080",
		phase,
		"attacker", // This is the authUser parameter
		authInfos,
	)

	require.NoError(t, err)
	require.Len(t, client.requests, 1)

	// Verify the correct auth token was used (attacker's token)
	assert.Equal(t, "Bearer attacker-secret-token", client.requests[0].Header.Get("Authorization"))
}

func TestExecutePhase_ReturnsErrorForMissingPath(t *testing.T) {
	client := &MockHTTPClient{}
	executor := NewMutationExecutor(client)

	phase := &templates.Phase{
		Operation: "read",
		Auth:      "victim",
		// Path is missing
	}

	_, err := executor.executePhase(
		context.Background(),
		"http://localhost:8080",
		phase,
		"victim",
		makeAuthInfos("", "token"),
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "path is required")
}

func TestHasUnresolvedPlaceholders(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "no placeholders",
			path:     "/api/v1/resources",
			expected: "",
		},
		{
			name:     "single placeholder",
			path:     "/api/v1/resources/{id}",
			expected: "id",
		},
		{
			name:     "multiple placeholders returns first",
			path:     "/api/v1/resources/{id}/items/{item_id}",
			expected: "id",
		},
		{
			name:     "placeholder at start",
			path:     "{version}/resources",
			expected: "version",
		},
		{
			name:     "unclosed brace",
			path:     "/api/v1/resources/{id",
			expected: "",
		},
		{
			name:     "empty string",
			path:     "",
			expected: "",
		},
		{
			name:     "resolved placeholder",
			path:     "/api/v1/resources/resource123",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasUnresolvedPlaceholders(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExecutePhase_ReturnsErrorForUnresolvedPlaceholder(t *testing.T) {
	client := &MockHTTPClient{}
	executor := NewMutationExecutor(client)

	// Do NOT store the "id" resource - this simulates setup phase failing to return an ID

	phase := &templates.Phase{
		Path:           "/api/v1/resources/{id}",
		Operation:      "read",
		Auth:           "attacker",
		UseStoredField: "id", // This field was never stored
	}

	_, err := executor.executePhase(
		context.Background(),
		"http://localhost:8080",
		phase,
		"attacker",
		makeAuthInfos("token", ""),
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unresolved placeholder")
	assert.Contains(t, err.Error(), "id")
}

func TestExecutePhase_ReturnsErrorForUnresolvedVideoID(t *testing.T) {
	client := &MockHTTPClient{}
	executor := NewMutationExecutor(client)

	// Simulate the specific bug: video_id placeholder never stored

	phase := &templates.Phase{
		Path:           "/identity/api/v2/user/videos/{video_id}",
		Operation:      "read",
		Auth:           "attacker",
		UseStoredField: "video_id", // This field was never stored
	}

	_, err := executor.executePhase(
		context.Background(),
		"http://localhost:8080",
		phase,
		"attacker",
		makeAuthInfos("token", ""),
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unresolved placeholder")
	assert.Contains(t, err.Error(), "video_id")
}

func TestExecuteMutation_ThreePhaseWithDynamicPaths(t *testing.T) {
	// Full three-phase BOLA test with dynamic paths
	setupResp := newMockResponse(201, `{"id": "order-456"}`)
	attackResp := newMockResponse(200, `{"data": "victim order data"}`) // Vulnerability!
	verifyResp := newMockResponse(200, `{"data": "victim order data"}`)

	client := &MockHTTPClient{
		responses: []*http.Response{setupResp, attackResp, verifyResp},
	}

	executor := NewMutationExecutor(client)

	tmpl := &templates.Template{
		ID: "api1-bola-orders",
		TestPhases: &templates.TestPhases{
			Setup: &templates.Phase{
				Path:               "/api/v1/orders",
				Operation:          "create",
				Auth:               "victim",
				Data:               map[string]string{"item": "test-item"},
				StoreResponseField: "id",
			},
			Attack: &templates.Phase{
				Path:           "/api/v1/orders/{id}",
				Operation:      "read",
				Auth:           "attacker",
				UseStoredField: "id",
				ExpectedStatus: 200, // If attacker gets 200, it's a vulnerability
			},
			Verify: &templates.Phase{
				Path:           "/api/v1/orders/{id}",
				Operation:      "read",
				Auth:           "victim",
				UseStoredField: "id",
				ExpectedStatus: 200,
			},
		},
	}

	authInfos := map[string]*auth.AuthInfo{
		"attacker": {
			Method: "bearer",
			Value:  "Bearer attacker-token",
		},
		"victim": {
			Method: "bearer",
			Value:  "Bearer victim-token",
		},
	}

	result, err := executor.ExecuteMutation(
		context.Background(),
		tmpl,
		"create",
		"attacker@example.com",
		"victim@example.com",
		authInfos,
		"http://localhost:8080",
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Matched) // Vulnerability found
	assert.Equal(t, "order-456", result.ResourceID)

	// Verify requests used correct paths
	require.Len(t, client.requests, 3)

	// Setup: POST to /api/v1/orders
	assert.Equal(t, http.MethodPost, client.requests[0].Method)
	assert.Equal(t, "http://localhost:8080/api/v1/orders", client.requests[0].URL.String())
	assert.Equal(t, "Bearer victim-token", client.requests[0].Header.Get("Authorization"))

	// Attack: GET to /api/v1/orders/{id} with substituted ID
	assert.Equal(t, http.MethodGet, client.requests[1].Method)
	assert.Equal(t, "http://localhost:8080/api/v1/orders/order-456", client.requests[1].URL.String())
	assert.Equal(t, "Bearer attacker-token", client.requests[1].Header.Get("Authorization"))

	// Verify: GET to /api/v1/orders/{id} with substituted ID
	assert.Equal(t, http.MethodGet, client.requests[2].Method)
	assert.Equal(t, "http://localhost:8080/api/v1/orders/order-456", client.requests[2].URL.String())
	assert.Equal(t, "Bearer victim-token", client.requests[2].Header.Get("Authorization"))
}
