// pkg/graphql/introspection_test.go
package graphql

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectionClient_FetchSchema(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		response := IntrospectionResult{
			Data: IntrospectionData{
				Schema: IntrospectionSchema{
					QueryType:    &TypeNameRef{Name: "Query"},
					MutationType: &TypeNameRef{Name: "Mutation"},
					Types: []IntrospectionType{
						{
							Kind: "OBJECT",
							Name: "Query",
							Fields: []IntrospectionField{
								{
									Name: "user",
									Type: IntrospectionTypeRef{Kind: "OBJECT", Name: "User"},
									Args: []IntrospectionInput{
										{Name: "id", Type: IntrospectionTypeRef{Kind: "NON_NULL", OfType: &IntrospectionTypeRef{Kind: "SCALAR", Name: "ID"}}},
									},
								},
							},
						},
						{
							Kind: "OBJECT",
							Name: "User",
							Fields: []IntrospectionField{
								{Name: "id", Type: IntrospectionTypeRef{Kind: "NON_NULL", OfType: &IntrospectionTypeRef{Kind: "SCALAR", Name: "ID"}}},
								{Name: "email", Type: IntrospectionTypeRef{Kind: "SCALAR", Name: "String"}},
							},
						},
						{
							Kind: "OBJECT",
							Name: "Mutation",
							Fields: []IntrospectionField{
								{Name: "deleteUser", Type: IntrospectionTypeRef{Kind: "SCALAR", Name: "Boolean"}},
							},
						},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewIntrospectionClient(http.DefaultClient, server.URL)
	schema, err := client.FetchSchema(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "Query", schema.QueryType)
	assert.Equal(t, "Mutation", schema.MutationType)
	assert.Len(t, schema.Queries, 1)
	assert.Equal(t, "user", schema.Queries[0].Name)
	assert.Len(t, schema.Mutations, 1)
}

func TestIntrospectionClient_WithAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		response := IntrospectionResult{
			Data: IntrospectionData{
				Schema: IntrospectionSchema{
					QueryType: &TypeNameRef{Name: "Query"},
					Types:     []IntrospectionType{},
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewIntrospectionClient(http.DefaultClient, server.URL)
	client.SetHeader("Authorization", "Bearer test-token")

	_, err := client.FetchSchema(context.Background())
	require.NoError(t, err)
}

func TestIntrospectionClient_ErrorHandling(t *testing.T) {
	// Test introspection disabled
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := IntrospectionResult{
			Errors: []GraphQLError{
				{Message: "Introspection is disabled"},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewIntrospectionClient(http.DefaultClient, server.URL)
	_, err := client.FetchSchema(context.Background())

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Introspection is disabled")
}
