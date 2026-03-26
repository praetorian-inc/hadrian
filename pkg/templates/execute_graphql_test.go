package templates

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// mockHTTPClient for testing
type mockGraphQLClient struct {
	responses []*http.Response
	requests  []*http.Request
	index     int
}

func (m *mockGraphQLClient) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)
	if m.index >= len(m.responses) {
		return m.responses[len(m.responses)-1], nil
	}
	resp := m.responses[m.index]
	m.index++
	return resp, nil
}

func TestExecutor_ExecuteGraphQL_SimpleQuery(t *testing.T) {
	// Arrange: Create mock response
	mockResp := &http.Response{
		StatusCode: 200,
		Body: io.NopCloser(bytes.NewBufferString(`{
			"data": {
				"user": {
					"id": "123",
					"email": "[email protected]"
				}
			}
		}`)),
		Header: http.Header{},
	}

	mockClient := &mockGraphQLClient{
		responses: []*http.Response{mockResp},
	}

	executor := NewExecutor(mockClient, nil)

	// Compile template
	tmpl := &Template{
		ID: "test-graphql",
		GraphQL: []GraphQLTest{
			{
				Query: `query GetUser { user(id: "123") { id email } }`,
				Matchers: []Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
					{
						Type:  "word",
						Words: []string{"data"},
						Part:  "body",
					},
				},
			},
		},
	}

	compiled, err := Compile(tmpl)
	require.NoError(t, err)

	// Act: Execute GraphQL template
	result, err := executor.ExecuteGraphQL(
		context.Background(),
		compiled,
		"http://localhost:8080/graphql",
		nil,
		nil,
	)

	// Assert
	require.NoError(t, err)
	assert.True(t, result.Matched, "GraphQL query should match")
	assert.Equal(t, 1, len(mockClient.requests), "Should have made 1 request")

	// Verify request structure
	req := mockClient.requests[0]
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))

	// Verify request body contains GraphQL query
	bodyBytes, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	bodyStr := string(bodyBytes)
	assert.Contains(t, bodyStr, "query GetUser")
	assert.Contains(t, bodyStr, "\"query\":")
}

func TestExecutor_ExecuteGraphQL_WithAuth(t *testing.T) {
	// Arrange
	mockResp := &http.Response{
		StatusCode: 200,
		Body: io.NopCloser(bytes.NewBufferString(`{
			"data": {
				"user": {
					"id": "victim123",
					"email": "[email protected]"
				}
			}
		}`)),
		Header: http.Header{},
	}

	mockClient := &mockGraphQLClient{
		responses: []*http.Response{mockResp},
	}

	executor := NewExecutor(mockClient, nil)

	tmpl := &Template{
		ID: "test-graphql-auth",
		GraphQL: []GraphQLTest{
			{
				Query: `query GetVictimData { user(id: "{{victim_id}}") { id email } }`,
				Variables: map[string]string{
					"victim_id": "{{victim_user_id}}",
				},
				Auth: "attacker",
				Matchers: []Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	compiled, err := Compile(tmpl)
	require.NoError(t, err)

	attackerAuth := &AuthInfo{
		Method: "bearer",
		Value:  "Bearer attacker-token-123",
	}

	variables := map[string]string{
		"victim_user_id": "victim123",
	}

	// Act
	result, err := executor.ExecuteGraphQL(
		context.Background(),
		compiled,
		"http://localhost:8080/graphql",
		attackerAuth,
		variables,
	)

	// Assert
	require.NoError(t, err)
	assert.True(t, result.Matched)

	// Verify auth header was set
	req := mockClient.requests[0]
	assert.Equal(t, "Bearer attacker-token-123", req.Header.Get("Authorization"))

	// Verify variable substitution in request body
	bodyBytes, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	bodyStr := string(bodyBytes)
	assert.Contains(t, bodyStr, "victim123")
}

func TestExecutor_ExecuteGraphQL_StoredFields(t *testing.T) {
	// Arrange: Multi-phase GraphQL test
	setupResp := &http.Response{
		StatusCode: 200,
		Body: io.NopCloser(bytes.NewBufferString(`{
			"data": {
				"user": {
					"id": "victim123",
					"video_id": "video456"
				}
			}
		}`)),
		Header: http.Header{},
	}

	attackResp := &http.Response{
		StatusCode: 200,
		Body: io.NopCloser(bytes.NewBufferString(`{
			"data": {
				"deleteVideo": {
					"success": true
				}
			}
		}`)),
		Header: http.Header{},
	}

	mockClient := &mockGraphQLClient{
		responses: []*http.Response{setupResp, attackResp},
	}

	executor := NewExecutor(mockClient, nil)

	tmpl := &Template{
		ID: "test-graphql-stored",
		GraphQL: []GraphQLTest{
			{
				Query: `query GetVictimData { user(id: "victim123") { id video_id } }`,
				Auth:  "victim",
				StoreResponseFields: map[string]string{
					"victim_video_id": "data.user.video_id",
				},
				Matchers: []Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
			{
				Query:          `mutation DeleteVideo { deleteVideo(id: "{{victim_video_id}}") { success } }`,
				Auth:           "attacker",
				UseStoredField: "victim_video_id",
				Matchers: []Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	compiled, err := Compile(tmpl)
	require.NoError(t, err)

	victimAuth := &AuthInfo{
		Method: "bearer",
		Value:  "Bearer victim-token",
	}

	attackerAuth := &AuthInfo{
		Method: "bearer",
		Value:  "Bearer attacker-token",
	}

	authInfos := map[string]*AuthInfo{
		"victim":   victimAuth,
		"attacker": attackerAuth,
	}

	// Act
	result, err := executor.ExecuteGraphQL(
		context.Background(),
		compiled,
		"http://localhost:8080/graphql",
		authInfos,
		nil,
	)

	// Assert
	require.NoError(t, err)
	assert.True(t, result.Matched)
	assert.Equal(t, 2, len(mockClient.requests), "Should have made 2 requests")

	// Verify second request used stored field
	req2BodyBytes, err := io.ReadAll(mockClient.requests[1].Body)
	require.NoError(t, err)
	req2BodyStr := string(req2BodyBytes)
	assert.Contains(t, req2BodyStr, "video456", "Should use stored video_id")
}

func TestExecutor_ExecuteGraphQL_ComplexVariables(t *testing.T) {
	// Arrange: Test with complex JSON variable structures (objects, arrays, numbers, booleans)
	mockResp := &http.Response{
		StatusCode: 200,
		Body: io.NopCloser(bytes.NewBufferString(`{
			"data": {
				"createUser": {
					"id": "123",
					"email": "[email protected]"
				}
			}
		}`)),
		Header: http.Header{},
	}

	mockClient := &mockGraphQLClient{
		responses: []*http.Response{mockResp},
	}

	executor := NewExecutor(mockClient, nil)

	// Template with complex variables (nested objects, arrays, numbers, booleans)
	tmpl := &Template{
		ID: "test-graphql-complex-vars",
		GraphQL: []GraphQLTest{
			{
				Query: `mutation CreateUser($input: UserInput!) {
					createUser(input: $input) { id email }
				}`,
				Variables: map[string]interface{}{
					"input": map[string]interface{}{
						"email":  "[email protected]",
						"age":    30,
						"active": true,
						"roles":  []string{"admin", "user"},
						"metadata": map[string]interface{}{
							"department": "engineering",
							"level":      5,
						},
					},
				},
				Matchers: []Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	compiled, err := Compile(tmpl)
	require.NoError(t, err)

	// Act
	result, err := executor.ExecuteGraphQL(
		context.Background(),
		compiled,
		"http://localhost:8080/graphql",
		nil,
		nil,
	)

	// Assert
	require.NoError(t, err)
	assert.True(t, result.Matched, "GraphQL mutation with complex variables should match")
	assert.Equal(t, 1, len(mockClient.requests), "Should have made 1 request")

	// Verify request body contains properly marshaled complex variables
	bodyBytes, err := io.ReadAll(mockClient.requests[0].Body)
	require.NoError(t, err)
	bodyStr := string(bodyBytes)

	// Verify the request contains the GraphQL query
	assert.Contains(t, bodyStr, "mutation CreateUser")
	assert.Contains(t, bodyStr, "\"variables\":")

	// Verify complex variable structures are present
	assert.Contains(t, bodyStr, "\"email\":\"[email protected]\"")
	assert.Contains(t, bodyStr, "\"age\":30")
	assert.Contains(t, bodyStr, "\"active\":true")
	assert.Contains(t, bodyStr, "\"roles\":")
	assert.Contains(t, bodyStr, "\"admin\"")
	assert.Contains(t, bodyStr, "\"metadata\":")
	assert.Contains(t, bodyStr, "\"department\":\"engineering\"")
	assert.Contains(t, bodyStr, "\"level\":5")
}

func TestGraphQLTest_ParseYAML_ComplexVariables(t *testing.T) {
	// Test that YAML with complex variable structures parses correctly
	yamlContent := `
id: test-complex-variables
info:
  name: Test Complex GraphQL Variables
  category: test
  severity: info
  author: test
  description: Test complex JSON in variables

endpoint_selector:
  methods: ["POST"]

role_selector:
  attacker_permission_level: all

graphql:
  - query: |
      mutation CreateUser($input: UserInput!) {
        createUser(input: $input) { id email }
      }
    variables:
      input:
        email: "[email protected]"
        age: 30
        active: true
        roles:
          - admin
          - user
        metadata:
          department: engineering
          level: 5
    matchers:
      - type: status
        status: [200]

detection:
  success_indicators:
    - type: status_code
      status_code: 200
  vulnerability_pattern: "test"
  conditions: []
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err, "YAML with complex variables should parse successfully")

	// Verify the template parsed correctly
	assert.Equal(t, "test-complex-variables", tmpl.ID)
	assert.Equal(t, 1, len(tmpl.GraphQL))

	// Verify variables is a map[string]interface{} (not map[string]string)
	require.NotNil(t, tmpl.GraphQL[0].Variables)
	vars, ok := tmpl.GraphQL[0].Variables.(map[string]interface{})
	require.True(t, ok, "Variables should be map[string]interface{}")

	// Verify nested structure
	input, ok := vars["input"].(map[string]interface{})
	require.True(t, ok, "input should be a map")

	assert.Equal(t, "[email protected]", input["email"])
	assert.Equal(t, 30, input["age"])
	assert.Equal(t, true, input["active"])

	// Verify array
	roles, ok := input["roles"].([]interface{})
	require.True(t, ok, "roles should be an array")
	assert.Equal(t, 2, len(roles))
	assert.Equal(t, "admin", roles[0])
	assert.Equal(t, "user", roles[1])

	// Verify nested map
	metadata, ok := input["metadata"].(map[string]interface{})
	require.True(t, ok, "metadata should be a map")
	assert.Equal(t, "engineering", metadata["department"])
	assert.Equal(t, 5, metadata["level"])
}
