//go:build integration
// +build integration

package graphql

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/hadrian/pkg/graphql"
)

// =============================================================================
// In-process vulnerable GraphQL service (no Docker, no external DVGA target).
//
// Replaces the previous DVGA_ENDPOINT (Docker) dependency with an httptest
// server that answers GraphQL introspection and a small set of queries /
// mutations modeled on the Damn Vulnerable GraphQL Application (DVGA):
// `users` / `pastes` queries, a `createPaste` mutation, and a `systemHealth`
// query. Integration tests run real introspection + execution against it.
//
// SCOPE: these tests validate the GraphQL plumbing (schema introspection and
// query execution) against an in-process target. Detection-rate regression
// coverage for the templates/graphql/ detection templates is NOT exercised
// here — that is covered for REST in pkg/runner/integration_test.go
// (TestIntegration_NoRegression_AllTemplates). Running the GraphQL/gRPC
// detection templates in-process is tracked as separate follow-up work.
// =============================================================================

// newVulnerableGraphQLServer builds and starts the in-process GraphQL service.
func newVulnerableGraphQLServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(body, &req)

		w.Header().Set("Content-Type", "application/json")

		// Introspection request → return the schema.
		if strings.Contains(req.Query, "__schema") || strings.Contains(req.Query, "IntrospectionQuery") {
			_ = json.NewEncoder(w).Encode(introspectionResponse())
			return
		}

		// Regular queries → return canned data for the requested root field.
		// Routing is naive substring matching, which is sufficient ONLY because
		// the fixture's known queries use non-overlapping root-field tokens.
		// If you add a query whose text contains another branch's token as a
		// nested selection (e.g. `pastes { author { ... } }` containing "users"),
		// route on the GraphQL root field instead of a bare substring.
		data := map[string]interface{}{}
		switch {
		case strings.Contains(req.Query, "__typename"):
			data["__typename"] = "Query"
		case strings.Contains(req.Query, "systemHealth"):
			// Require the exact Authorization header that the bearer executor sets
			// (authInfo.Value is written verbatim: "Bearer test-admin-token").
			// This makes TestIntegration_AuthenticatedRequest meaningful: a request
			// with no auth or a wrong token will receive 401 instead of 200.
			if r.Header.Get("Authorization") != "Bearer test-admin-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			data["systemHealth"] = "ok"
		case strings.Contains(req.Query, "users"):
			data["users"] = []map[string]interface{}{{"id": "1", "username": "admin"}}
		default:
			data["ok"] = true
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
	}))
	t.Cleanup(server.Close)
	return server
}

// introspectionResponse returns a minimal-but-valid introspection result with
// the DVGA-style queries (`users`, `pastes`) and mutation (`createPaste`).
func introspectionResponse() graphql.IntrospectionResult {
	return graphql.IntrospectionResult{
		Data: graphql.IntrospectionData{
			Schema: graphql.IntrospectionSchema{
				QueryType:    &graphql.TypeNameRef{Name: "Query"},
				MutationType: &graphql.TypeNameRef{Name: "Mutation"},
				Types: []graphql.IntrospectionType{
					{
						Kind: "OBJECT",
						Name: "Query",
						Fields: []graphql.IntrospectionField{
							{Name: "users", Type: graphql.IntrospectionTypeRef{Kind: "LIST", OfType: &graphql.IntrospectionTypeRef{Kind: "OBJECT", Name: "UserObject"}}},
							{Name: "pastes", Type: graphql.IntrospectionTypeRef{Kind: "LIST", OfType: &graphql.IntrospectionTypeRef{Kind: "OBJECT", Name: "PasteObject"}}},
							{Name: "systemHealth", Type: graphql.IntrospectionTypeRef{Kind: "SCALAR", Name: "String"}},
						},
					},
					{
						Kind: "OBJECT",
						Name: "Mutation",
						Fields: []graphql.IntrospectionField{
							{
								Name: "createPaste",
								Type: graphql.IntrospectionTypeRef{Kind: "OBJECT", Name: "PasteObject"},
								Args: []graphql.IntrospectionInput{
									{Name: "title", Type: graphql.IntrospectionTypeRef{Kind: "SCALAR", Name: "String"}},
									{Name: "content", Type: graphql.IntrospectionTypeRef{Kind: "SCALAR", Name: "String"}},
								},
							},
						},
					},
					{
						Kind: "OBJECT",
						Name: "UserObject",
						Fields: []graphql.IntrospectionField{
							{Name: "id", Type: graphql.IntrospectionTypeRef{Kind: "SCALAR", Name: "ID"}},
							{Name: "username", Type: graphql.IntrospectionTypeRef{Kind: "SCALAR", Name: "String"}},
						},
					},
					{
						Kind: "OBJECT",
						Name: "PasteObject",
						Fields: []graphql.IntrospectionField{
							{Name: "id", Type: graphql.IntrospectionTypeRef{Kind: "SCALAR", Name: "ID"}},
							{Name: "content", Type: graphql.IntrospectionTypeRef{Kind: "SCALAR", Name: "String"}},
						},
					},
				},
			},
		},
	}
}

func TestIntegration_IntrospectionClient(t *testing.T) {
	server := newVulnerableGraphQLServer(t)

	client := graphql.NewIntrospectionClient(http.DefaultClient, server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	schema, err := client.FetchSchema(ctx)
	require.NoError(t, err)
	require.NotNil(t, schema)
	assert.Greater(t, len(schema.Queries), 0, "should have queries")
}

func TestIntegration_QueryExecution(t *testing.T) {
	server := newVulnerableGraphQLServer(t)

	executor := graphql.NewExecutor(http.DefaultClient, server.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := executor.Execute(ctx, "{ __typename }", nil, "", nil)
	require.NoError(t, err)
	assert.Equal(t, 200, result.StatusCode)

	// Assert on the decoded data envelope value, not just substring presence —
	// proves the executor returned the GraphQL `data` payload intact.
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.Body), &resp))
	assert.Equal(t, "Query", resp.Data["__typename"])
}

func TestIntegration_AuthenticatedRequest(t *testing.T) {
	server := newVulnerableGraphQLServer(t)

	executor := graphql.NewExecutor(http.DefaultClient, server.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authInfo := &graphql.AuthInfo{
		Method: "bearer",
		Value:  "Bearer test-admin-token",
	}

	result, err := executor.Execute(ctx, `query { systemHealth }`, nil, "", authInfo)
	require.NoError(t, err)
	assert.Equal(t, 200, result.StatusCode)

	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.Body), &resp))
	assert.Equal(t, "ok", resp.Data["systemHealth"])

	// Negative case: no auth should yield 401, confirming the server actually
	// enforces the auth gate and the test above is not a false positive.
	unauthResult, err := executor.Execute(ctx, `query { systemHealth }`, nil, "", nil)
	require.NoError(t, err)
	assert.Equal(t, 401, unauthResult.StatusCode, "systemHealth without auth should return 401")
}

func TestIntegration_SchemaDiscovery(t *testing.T) {
	server := newVulnerableGraphQLServer(t)

	client := graphql.NewIntrospectionClient(http.DefaultClient, server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	schema, err := client.FetchSchema(ctx)
	require.NoError(t, err)

	hasUsersQuery := false
	hasPastesQuery := false
	for _, q := range schema.Queries {
		if q.Name == "users" {
			hasUsersQuery = true
		}
		if q.Name == "pastes" {
			hasPastesQuery = true
		}
	}
	assert.True(t, hasUsersQuery, "should have users query")
	assert.True(t, hasPastesQuery, "should have pastes query")

	hasCreatePaste := false
	for _, m := range schema.Mutations {
		if m.Name == "createPaste" {
			hasCreatePaste = true
		}
	}
	assert.True(t, hasCreatePaste, "should have createPaste mutation")
}
