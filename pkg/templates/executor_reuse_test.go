package templates

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecutor_ReuseDoesNotClearRequestIDs tests that reusing an executor
// for multiple Execute() calls doesn't cause request IDs from previous calls
// to be cleared/lost due to slice sharing
func TestExecutor_ReuseDoesNotClearRequestIDs(t *testing.T) {
	// Create a single executor (mimicking real usage)
	client := &mockHTTPClient{
		response: &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"status": "ok"}`)),
		},
	}
	executor := NewExecutor(client)

	// Create two templates
	tmpl1 := &CompiledTemplate{
		Template: &Template{
			ID: "template-1",
			HTTP: []HTTPTest{
				{
					Method: "GET",
					Path:   "/api/test1",
					Matchers: []Matcher{
						{Type: "status", Status: []int{200}},
					},
				},
			},
		},
		CompiledMatchers: []*CompiledMatcher{
			{Type: "status", Status: []int{200}},
		},
	}

	tmpl2 := &CompiledTemplate{
		Template: &Template{
			ID: "template-2",
			HTTP: []HTTPTest{
				{
					Method: "GET",
					Path:   "/api/test2",
					Matchers: []Matcher{
						{Type: "status", Status: []int{200}},
					},
				},
			},
		},
		CompiledMatchers: []*CompiledMatcher{
			{Type: "status", Status: []int{200}},
		},
	}

	operation := &model.Operation{
		Method: "GET",
		Path:   "/api/test",
	}

	// Execute first template
	result1, err := executor.Execute(context.Background(), tmpl1, operation, "", nil)
	require.NoError(t, err)
	require.NotEmpty(t, result1.RequestIDs, "first execution should have request IDs")

	// Capture request IDs from first execution
	firstRequestIDs := make([]string, len(result1.RequestIDs))
	copy(firstRequestIDs, result1.RequestIDs)
	t.Logf("First execution request IDs: %v (ptr: %p)", result1.RequestIDs, &result1.RequestIDs[0])

	// Execute second template with SAME executor
	result2, err := executor.Execute(context.Background(), tmpl2, operation, "", nil)
	require.NoError(t, err)
	require.NotEmpty(t, result2.RequestIDs, "second execution should have request IDs")
	t.Logf("Second execution request IDs: %v (ptr: %p)", result2.RequestIDs, &result2.RequestIDs[0])
	t.Logf("First execution request IDs AFTER second call: %v", result1.RequestIDs)

	// CRITICAL TEST: First result should STILL have its request IDs
	// (they should not have been cleared when second Execute() was called)
	assert.NotEmpty(t, result1.RequestIDs,
		"first result's request IDs should not be cleared by second Execute() call")

	assert.Equal(t, firstRequestIDs, result1.RequestIDs,
		"first result's request IDs should match original captured values")

	// Second result should have DIFFERENT request IDs
	assert.NotEqual(t, result1.RequestIDs, result2.RequestIDs,
		"each execution should have unique request IDs")
}
