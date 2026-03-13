package rest_test

import (
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOperationOrdering verifies that operations are sorted deterministically
// by path (primary) and method (secondary) to ensure consistent vulnerability findings
// across different authentication methods (Bearer, Basic, API Key).
func TestOperationOrdering(t *testing.T) {
	// Create a spec with operations intentionally in wrong order
	spec := []byte(`
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users/{id}:
    delete:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '204':
          description: Deleted
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Get user
    put:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Update user
  /pets:
    post:
      responses:
        '201':
          description: Created
    get:
      responses:
        '200':
          description: List pets
  /orders/{orderId}:
    get:
      parameters:
        - name: orderId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Get order
`)

	plugin, _ := plugins.Get(plugins.ProtocolREST)
	result, err := plugin.Parse(spec)
	require.NoError(t, err)
	require.Len(t, result.Operations, 6, "Should have 6 operations")

	// Expected order: alphabetically by path, then by safe method order
	// (GET < POST < PUT < DELETE) to ensure reads before destructive ops
	expectedOrder := []struct {
		path   string
		method string
	}{
		{"/orders/{orderId}", "GET"},
		{"/pets", "GET"},
		{"/pets", "POST"},
		{"/users/{id}", "GET"},
		{"/users/{id}", "PUT"},
		{"/users/{id}", "DELETE"},
	}

	// Verify operations are in deterministic order
	for i, expected := range expectedOrder {
		actual := result.Operations[i]
		assert.Equal(t, expected.path, actual.Path,
			"Operation %d: expected path %s, got %s", i, expected.path, actual.Path)
		assert.Equal(t, expected.method, actual.Method,
			"Operation %d: expected method %s, got %s", i, expected.method, actual.Method)
	}
}

// TestOperationOrderingWithMultipleParseCalls verifies that parsing the same spec
// multiple times produces operations in the same order every time.
func TestOperationOrderingWithMultipleParseCalls(t *testing.T) {
	spec := []byte(`
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /z-last:
    post:
      responses:
        '201':
          description: Created
  /a-first:
    get:
      responses:
        '200':
          description: Success
  /m-middle:
    delete:
      responses:
        '204':
          description: Deleted
    put:
      responses:
        '200':
          description: Updated
`)

	plugin, _ := plugins.Get(plugins.ProtocolREST)

	// Parse the spec 3 times
	var results [][]string
	for i := 0; i < 3; i++ {
		result, err := plugin.Parse(spec)
		require.NoError(t, err)

		// Collect operation identifiers (path + method)
		var operations []string
		for _, op := range result.Operations {
			operations = append(operations, op.Path+" "+op.Method)
		}
		results = append(results, operations)
	}

	// Verify all three parses produced the same order
	assert.Equal(t, results[0], results[1], "First and second parse should have same operation order")
	assert.Equal(t, results[1], results[2], "Second and third parse should have same operation order")

	// Verify expected sorted order (safe method ordering: PUT before DELETE)
	expected := []string{
		"/a-first GET",
		"/m-middle PUT",
		"/m-middle DELETE",
		"/z-last POST",
	}
	assert.Equal(t, expected, results[0], "Operations should be sorted by path then safe method order")
}
