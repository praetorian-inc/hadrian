package templates

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	executor := NewExecutor(mockClient)

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

	executor := NewExecutor(mockClient)

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

	executor := NewExecutor(mockClient)

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
