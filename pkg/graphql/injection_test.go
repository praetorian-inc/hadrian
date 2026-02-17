package graphql

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGraphQLInjection_SecurityScanner_CheckBOLA tests that victimID values with quotes
// don't break query structure in BOLA check
func TestGraphQLInjection_SecurityScanner_CheckBOLA(t *testing.T) {
	t.Run("prevents query injection via victimID with quotes", func(t *testing.T) {
		// Track received queries
		receivedQueries := []string{}

		// Create test server that logs queries
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			receivedQueries = append(receivedQueries, string(body))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			// Return victim ID with quotes to test injection
			// Both first and subsequent queries return the same response
			_, _ = w.Write([]byte(`{"data":{"user":{"id":"victim\"}{evil:__schema{types{name}}}"}}}`))
		}))
		defer server.Close()

		schema := &Schema{
			QueryType: "Query",
			Queries: []*FieldDef{
				{
					Name: "user",
					Type: &TypeRef{Name: "User", Kind: TypeKindObject},
					Args: []*ArgumentDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
					},
				},
			},
		}

		authConfigs := map[string]*AuthInfo{
			"victim":   {Method: "bearer", Value: "victim-token"},
			"attacker": {Method: "bearer", Value: "attacker-token"},
		}

		executor := NewExecutor(http.DefaultClient, server.URL)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{})

		ctx := context.Background()
		finding := scanner.CheckBOLA(ctx, authConfigs)

		// Test should complete without panic or syntax errors
		require.NotNil(t, finding)

		// Verify second query (attacker probe) is well-formed
		require.GreaterOrEqual(t, len(receivedQueries), 2, "Should have sent 2 queries")
		secondQuery := receivedQueries[1]

		// Query should not have injection - should use variables or escaped quotes
		// Either uses GraphQL variables: query($id: ID!) { user(id: $id) { id } }
		// Or escapes quotes: query { user(id: "victim\"")
		assert.True(t,
			strings.Contains(secondQuery, "$id: ID!") || strings.Contains(secondQuery, `\"`),
			"Query should use variables or escape quotes, got: %s", secondQuery)

		// Malicious injection should not appear unescaped
		assert.NotContains(t, secondQuery, `"){evil:__schema`,
			"Injection payload should not appear unescaped")
	})
}

// TestGraphQLInjection_AttackGenerator_BOLAProbeQuery tests that BOLAProbeQuery escapes quotes
func TestGraphQLInjection_AttackGenerator_BOLAProbeQuery(t *testing.T) {
	t.Run("escapes quotes in victimID", func(t *testing.T) {
		schema := &Schema{}
		gen := NewAttackGenerator(schema)

		// Test with victimID containing quotes
		maliciousID := `victim"}{evil:__schema{types{name}}}`
		query := gen.BOLAProbeQuery("user", "id", maliciousID)

		// Query should have escaped quotes
		assert.Contains(t, query, `\"`, "Should escape double quotes")
		assert.NotContains(t, query, `"){evil:`, "Injection should not break query structure")

		// Verify query structure is valid
		assert.Contains(t, query, `query BOLAProbe`, "Should start with query definition")
		assert.Contains(t, query, `user(id:`, "Should have field name and argument")
	})

	t.Run("handles normal victimID without modification", func(t *testing.T) {
		schema := &Schema{}
		gen := NewAttackGenerator(schema)

		normalID := "victim-123"
		query := gen.BOLAProbeQuery("user", "id", normalID)

		// Should work with normal IDs
		assert.Contains(t, query, `"victim-123"`, "Should preserve normal IDs")
		assert.Contains(t, query, `query BOLAProbe { user(id: "victim-123")`, "Should have correct structure")
	})
}

// TestGraphQLInjection_AttackGenerator_BFLAProbeQuery tests that BFLAProbeQuery escapes values
func TestGraphQLInjection_AttackGenerator_BFLAProbeQuery(t *testing.T) {
	t.Run("escapes quotes in argument values", func(t *testing.T) {
		schema := &Schema{}
		gen := NewAttackGenerator(schema)

		// Test with malicious argument values
		args := map[string]string{
			"id":   `test"}{evil:__schema{types{name}}}`,
			"name": `user"}{another:__typename}`,
		}

		query := gen.BFLAProbeQuery("deleteUser", args)

		// All values should have escaped quotes
		assert.Contains(t, query, `\"`, "Should escape double quotes in values")
		assert.NotContains(t, query, `"){evil:`, "Injection should not break query structure")
		assert.NotContains(t, query, `"){another:`, "Injection should not break query structure")

		// Verify query structure
		assert.Contains(t, query, `mutation BFLAProbe`, "Should start with mutation definition")
		assert.Contains(t, query, `deleteUser(`, "Should have mutation name")
	})

	t.Run("handles normal args without modification", func(t *testing.T) {
		schema := &Schema{}
		gen := NewAttackGenerator(schema)

		normalArgs := map[string]string{
			"id":   "test-123",
			"name": "normalUser",
		}

		query := gen.BFLAProbeQuery("deleteUser", normalArgs)

		// Should preserve normal values
		assert.Contains(t, query, `"test-123"`, "Should preserve normal ID")
		assert.Contains(t, query, `"normalUser"`, "Should preserve normal name")
	})

	t.Run("handles empty args", func(t *testing.T) {
		schema := &Schema{}
		gen := NewAttackGenerator(schema)

		query := gen.BFLAProbeQuery("deleteUser", map[string]string{})

		// Should work with empty args
		assert.Contains(t, query, `mutation BFLAProbe { deleteUser`, "Should have mutation name")
		assert.Contains(t, query, `{ success }`, "Should have field selection")
		assert.NotContains(t, query, `(`, "Should not have empty parentheses")
	})
}
