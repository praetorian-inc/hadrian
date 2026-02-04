package templates

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/oob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutor_SubstituteInteractsh(t *testing.T) {
	// Create OOB client
	oobClient, err := oob.NewClient(oob.DefaultConfig())
	require.NoError(t, err)
	defer oobClient.Close()

	// Create executor with OOB support
	executor := NewExecutor(nil, WithOOBClient(oobClient))

	// Verify OOB URL is available
	assert.NotEmpty(t, executor.oobURL)
	assert.Contains(t, executor.oobURL, ".")  // Has domain

	// Template with {{interactsh}} variable
	query := "mutation { importPaste(host: \"{{interactsh}}\") { result } }"

	// Use substituteInteractsh helper (we'll add this)
	result := substituteInteractsh(query, executor.oobURL)

	assert.NotContains(t, result, "{{interactsh}}")
	assert.Contains(t, result, executor.oobURL)
}

func TestExecutor_CheckOOBInteraction(t *testing.T) {
	oobClient, err := oob.NewClient(oob.DefaultConfig())
	require.NoError(t, err)
	defer oobClient.Close()

	executor := NewExecutor(nil, WithOOBClient(oobClient))

	// Indicator requiring OOB callback
	indicator := Indicator{
		Type:     "oob_callback",
		Protocol: "http",
	}

	// No interaction yet
	ctx := context.Background()
	matched, interactions, err := executor.checkOOBIndicator(ctx, indicator)
	require.NoError(t, err)
	assert.False(t, matched)  // No callbacks received
	assert.Empty(t, interactions)
}

func TestExecutor_ExecuteGraphQLWithOOBDetection(t *testing.T) {
	// Create mock HTTP client that returns success
	mockResp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{"data":{"result":"success"}}`)),
		Header:     http.Header{},
	}

	mockClient := &mockOOBHTTPClient{
		response: mockResp,
	}

	// Create real OOB client (no callbacks will be received in this test)
	realOOBClient, err := oob.NewClient(oob.DefaultConfig())
	require.NoError(t, err)
	defer realOOBClient.Close()

	executor := NewExecutor(mockClient, WithOOBClient(realOOBClient))

	// Create template with OOB indicator
	tmpl := &CompiledTemplate{
		Template: &Template{
			ID: "test-oob",
			GraphQL: []GraphQLTest{
				{
					Query: "mutation { test { result } }",
				},
			},
			Detection: Detection{
				SuccessIndicators: []Indicator{
					{
						Type:     "oob_callback",
						Protocol: "http",
					},
				},
			},
		},
		CompiledMatchers: []*CompiledMatcher{},
	}

	ctx := context.Background()
	result, err := executor.ExecuteGraphQL(ctx, tmpl, "http://example.com/graphql", nil, nil)

	require.NoError(t, err)
	// Currently will not match because:
	// 1. No matchers matched
	// 2. OOB checking is not integrated yet
	assert.False(t, result.Matched, "Should not match yet - OOB checking not integrated")

	// After fix, this would check for OOB callbacks and potentially set result.Matched = true
	// if callbacks were received (none in this test, but the integration path would exist)
}

// mockOOBHTTPClient for testing (simple single-response client)
type mockOOBHTTPClient struct {
	response *http.Response
	err      error
}

func (m *mockOOBHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

// mockOOBClient simulates OOB interactions for testing
type mockOOBClient struct {
	interactions []oob.Interaction
	pollCalled   int
}

func (m *mockOOBClient) Poll(ctx context.Context) ([]oob.Interaction, error) {
	m.pollCalled++
	return m.interactions, nil
}

func (m *mockOOBClient) GenerateURL() string {
	return "test.interactsh.com"
}

func (m *mockOOBClient) Close() error {
	return nil
}
