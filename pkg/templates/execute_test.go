package templates

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

// mockHTTPClient for testing
type mockHTTPClient struct {
	response *http.Response
	err      error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

func TestNewExecutor(t *testing.T) {
	client := &mockHTTPClient{}
	executor := NewExecutor(client)

	if executor == nil {
		t.Fatal("NewExecutor returned nil")
	}

	if executor.httpClient != client {
		t.Error("httpClient not set correctly")
	}

	if executor.cache == nil {
		t.Error("cache not initialized")
	}
}

func TestExecute_MatchedResponse(t *testing.T) {
	// Setup mock HTTP response
	respBody := `{"user": "admin", "role": "administrator"}`
	mockResp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(respBody)),
	}

	client := &mockHTTPClient{response: mockResp}
	executor := NewExecutor(client)

	// Create compiled template
	tmpl := &CompiledTemplate{
		Template: &Template{
			ID: "test-template",
			HTTP: []HTTPTest{
				{
					Method: "GET",
					Path:   "/api/users/1",
					Matchers: []Matcher{
						{
							Type:  "status",
							Status: []int{200},
						},
					},
				},
			},
		},
		CompiledMatchers: []*CompiledMatcher{
			{
				Type:   "status",
				Status: []int{200},
			},
		},
	}

	operation := &model.Operation{
		Method: "GET",
		Path:   "/api/users/1",
	}

	// Execute template
	result, err := executor.Execute(context.Background(), tmpl, operation, "", nil)

	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result.TemplateID != "test-template" {
		t.Errorf("TemplateID = %q, want %q", result.TemplateID, "test-template")
	}

	if !result.Matched {
		t.Error("Expected match but got no match")
	}

	if result.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.Response.StatusCode)
	}

	if result.Response.Body != respBody {
		t.Errorf("Body = %q, want %q", result.Response.Body, respBody)
	}

	// Verify body hash
	hash := sha256.Sum256([]byte(respBody))
	expectedHash := fmt.Sprintf("%x", hash)
	if result.Response.BodyHash != expectedHash {
		t.Errorf("BodyHash = %q, want %q", result.Response.BodyHash, expectedHash)
	}
}

func TestExecute_NoMatch(t *testing.T) {
	respBody := `{"error": "not found"}`
	mockResp := &http.Response{
		StatusCode: 404,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(respBody)),
	}

	client := &mockHTTPClient{response: mockResp}
	executor := NewExecutor(client)

	tmpl := &CompiledTemplate{
		Template: &Template{
			ID: "test-template",
			HTTP: []HTTPTest{
				{
					Method: "GET",
					Path:   "/api/users/1",
					Matchers: []Matcher{
						{
							Type:   "status",
							Status: []int{200},
						},
					},
				},
			},
		},
		CompiledMatchers: []*CompiledMatcher{
			{
				Type:   "status",
				Status: []int{200},
			},
		},
	}

	operation := &model.Operation{
		Method: "GET",
		Path:   "/api/users/1",
	}

	result, err := executor.Execute(context.Background(), tmpl, operation, "", nil)

	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result.Matched {
		t.Error("Expected no match but got match")
	}
}

func TestBuildRequest_VariableSubstitution(t *testing.T) {
	test := HTTPTest{
		Method: "GET",
		Path:   "/api/users/{{userId}}",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	operation := &model.Operation{
		Method: "GET",
		Path:   "/api/users/123",
	}

	variables := map[string]string{
		"userId": "999",
	}

	req, err := buildRequest(context.Background(), test, operation, "", variables)

	if err != nil {
		t.Fatalf("buildRequest failed: %v", err)
	}

	// Should substitute variable
	expectedPath := "/api/users/999"
	if !strings.HasSuffix(req.URL.Path, expectedPath) {
		t.Errorf("URL path = %q, want suffix %q", req.URL.Path, expectedPath)
	}
}

// TestBuildRequest_OpenAPIPathParameters tests that OpenAPI-style path parameters
// with single curly braces (e.g., {vehicleId}) are correctly substituted.
// This is a regression test for the bug where only {{key}} format was supported.
func TestBuildRequest_OpenAPIPathParameters(t *testing.T) {
	tests := []struct {
		name         string
		testPath     string
		variables    map[string]string
		expectedPath string
	}{
		{
			name:     "single OpenAPI path parameter",
			testPath: "/identity/api/v2/vehicle/{vehicleId}/location",
			variables: map[string]string{
				"vehicleId": "abc123",
			},
			expectedPath: "/identity/api/v2/vehicle/abc123/location",
		},
		{
			name:     "multiple OpenAPI path parameters",
			testPath: "/api/v1/users/{userId}/orders/{orderId}",
			variables: map[string]string{
				"userId":  "user456",
				"orderId": "order789",
			},
			expectedPath: "/api/v1/users/user456/orders/order789",
		},
		{
			name:     "mixed double and single brace parameters",
			testPath: "/api/{{version}}/users/{userId}",
			variables: map[string]string{
				"version": "v2",
				"userId":  "user123",
			},
			expectedPath: "/api/v2/users/user123",
		},
		{
			name:     "OpenAPI parameter at end of path",
			testPath: "/api/resources/{resourceId}",
			variables: map[string]string{
				"resourceId": "res-001",
			},
			expectedPath: "/api/resources/res-001",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			test := HTTPTest{
				Method: "GET",
				Path:   tc.testPath,
			}

			operation := &model.Operation{
				Method: "GET",
				Path:   tc.testPath, // Use the same path for operation
			}

			req, err := buildRequest(context.Background(), test, operation, "", tc.variables)
			if err != nil {
				t.Fatalf("buildRequest failed: %v", err)
			}

			// Verify path was substituted correctly
			if req.URL.Path != tc.expectedPath {
				t.Errorf("URL path = %q, want %q", req.URL.Path, tc.expectedPath)
			}
		})
	}
}

func TestBuildRequest_OperationPath(t *testing.T) {
	test := HTTPTest{
		Method: "{{operation.method}}",
		Path:   "{{operation.path}}",
	}

	operation := &model.Operation{
		Method: "POST",
		Path:   "/api/users",
	}

	req, err := buildRequest(context.Background(), test, operation, "", nil)

	if err != nil {
		t.Fatalf("buildRequest failed: %v", err)
	}

	if req.Method != "POST" {
		t.Errorf("Method = %q, want POST", req.Method)
	}

	if !strings.HasSuffix(req.URL.Path, "/api/users") {
		t.Errorf("URL path = %q, want suffix /api/users", req.URL.Path)
	}
}

func TestBuildRequest_OperationMethod(t *testing.T) {
	test := HTTPTest{
		Method: "{{operation.method}}",
		Path:   "/test",
	}

	operation := &model.Operation{
		Method: "DELETE",
		Path:   "/api/users/1",
	}

	req, err := buildRequest(context.Background(), test, operation, "", nil)

	if err != nil {
		t.Fatalf("buildRequest failed: %v", err)
	}

	if req.Method != "DELETE" {
		t.Errorf("Method = %q, want DELETE", req.Method)
	}
}

func TestBuildRequest_AuthHeader(t *testing.T) {
	test := HTTPTest{
		Method: "GET",
		Path:   "/api/users",
		Headers: map[string]string{
			"Authorization": "Bearer {{attacker_token}}",
		},
	}

	operation := &model.Operation{
		Method: "GET",
		Path:   "/api/users",
	}

	authHeader := "Bearer token123"

	req, err := buildRequest(context.Background(), test, operation, authHeader, nil)

	if err != nil {
		t.Fatalf("buildRequest failed: %v", err)
	}

	if req.Header.Get("Authorization") != authHeader {
		t.Errorf("Authorization header = %q, want %q", req.Header.Get("Authorization"), authHeader)
	}
}

func TestEvaluateMatchers_WordMatcher(t *testing.T) {
	body := `{"user": "admin", "role": "administrator"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}

	matchers := []*CompiledMatcher{
		{
			Type:      "word",
			Words:     []string{"admin", "administrator"},
			Part:      "body",
			Condition: "and",
		},
	}

	if !evaluateMatchers(matchers, resp, body) {
		t.Error("Expected word matcher to match")
	}
}

func TestEvaluateMatchers_RegexMatcher(t *testing.T) {
	body := `{"email": "user@example.com"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}

	pattern := regexp.MustCompile(`[a-z]+@[a-z]+\.[a-z]+`)
	matchers := []*CompiledMatcher{
		{
			Type:          "regex",
			CompiledRegex: []*regexp.Regexp{pattern},
			Part:          "body",
			Condition:     "or",
		},
	}

	if !evaluateMatchers(matchers, resp, body) {
		t.Error("Expected regex matcher to match")
	}
}

func TestEvaluateMatchers_StatusMatcher(t *testing.T) {
	resp := &http.Response{
		StatusCode: 403,
		Header:     http.Header{},
	}

	matchers := []*CompiledMatcher{
		{
			Type:   "status",
			Status: []int{401, 403},
		},
	}

	if !evaluateMatchers(matchers, resp, "") {
		t.Error("Expected status matcher to match")
	}
}

func TestFlattenHeaders(t *testing.T) {
	headers := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer token"},
		"X-Custom":      []string{"value1", "value2"},
	}

	flattened := flattenHeaders(headers)

	if flattened["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", flattened["Content-Type"])
	}

	if flattened["Authorization"] != "Bearer token" {
		t.Errorf("Authorization = %q, want 'Bearer token'", flattened["Authorization"])
	}

	if flattened["X-Custom"] != "value1, value2" {
		t.Errorf("X-Custom = %q, want 'value1, value2'", flattened["X-Custom"])
	}
}

func TestExecute_Integration_WithHTTPTest(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Method = %q, want GET", r.Method)
		}

		if r.URL.Path != "/api/test" {
			t.Errorf("Path = %q, want /api/test", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status": "success"}`))
	}))
	defer server.Close()

	// Use real HTTP client
	executor := NewExecutor(&http.Client{})

	// For integration test, template path should use the full server URL
	tmpl := &CompiledTemplate{
		Template: &Template{
			ID: "integration-test",
			HTTP: []HTTPTest{
				{
					Method: "GET",
					Path:   server.URL + "/api/test", // Use full URL in test path
					Matchers: []Matcher{
						{
							Type:   "status",
							Status: []int{200},
						},
					},
				},
			},
		},
		CompiledMatchers: []*CompiledMatcher{
			{
				Type:   "status",
				Status: []int{200},
			},
		},
	}

	// Operation path is just the relative path
	operation := &model.Operation{
		Method: "GET",
		Path:   "/api/test",
	}

	result, err := executor.Execute(context.Background(), tmpl, operation, "", nil)

	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if !result.Matched {
		t.Error("Expected match")
	}

	if result.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.Response.StatusCode)
	}
}
