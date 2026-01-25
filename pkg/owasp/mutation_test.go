package owasp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// MockHTTPClient for testing
type MockHTTPClient struct {
	responses []*http.Response
	index     int
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
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
				Operation:          "create",
				Auth:               "victim",
				Data:               map[string]string{"name": "test"},
				StoreResponseField: "id",
			},
			Attack: &templates.Phase{
				Operation:      "read",
				Auth:           "attacker",
				UseStoredField: "id",
				ExpectedStatus: 200, // Success indicates vulnerability (attacker can read)
			},
			Verify: &templates.Phase{
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
		map[string]string{"auth": "token"},
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
				Operation:          "create",
				Auth:               "victim",
				Data:               map[string]string{"name": "test"},
				StoreResponseField: "id",
			},
			Attack: &templates.Phase{
				Operation:      "read",
				Auth:           "attacker",
				UseStoredField: "id",
				ExpectedStatus: 200,
			},
			Verify: &templates.Phase{
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
		map[string]string{"auth": "token"},
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
				Operation:          "create",
				Auth:               "victim",
				StoreResponseField: "id",
			},
			Attack: &templates.Phase{
				Operation:      "read",
				Auth:           "attacker",
				UseStoredField: "id",
				ExpectedStatus: 200,
			},
			Verify: &templates.Phase{
				Operation:      "read",
				Auth:           "victim",
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
		map[string]string{"auth": "token"},
		"http://localhost:8080",
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
	// Verify resource ID was extracted and stored
	assert.Equal(t, "resource123", result.ResourceID)
	// Verify it's also tracked
	assert.Equal(t, "resource123", executor.tracker.GetResource("api1-bola"))
}
