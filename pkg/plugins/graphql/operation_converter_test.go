// pkg/plugins/graphql/operation_converter_test.go
package graphql

import (
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/graphql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertSchemaToOperations(t *testing.T) {
	schema := &graphql.Schema{
		QueryType:    "Query",
		MutationType: "Mutation",
		Types: map[string]*graphql.TypeDef{
			"User": {
				Name: "User",
				Kind: graphql.TypeKindObject,
				Fields: []*graphql.FieldDef{
					{Name: "id", Type: &graphql.TypeRef{Name: "ID", Kind: graphql.TypeKindScalar}},
					{Name: "email", Type: &graphql.TypeRef{Name: "String", Kind: graphql.TypeKindScalar}},
				},
			},
		},
		Queries: []*graphql.FieldDef{
			{
				Name: "user",
				Type: &graphql.TypeRef{Name: "User", Kind: graphql.TypeKindObject},
				Args: []*graphql.ArgumentDef{
					{Name: "id", Type: &graphql.TypeRef{Kind: graphql.TypeKindNonNull, OfType: &graphql.TypeRef{Name: "ID"}}},
				},
			},
		},
		Mutations: []*graphql.FieldDef{
			{
				Name: "deleteUser",
				Type: &graphql.TypeRef{Name: "Boolean", Kind: graphql.TypeKindScalar},
				Args: []*graphql.ArgumentDef{
					{Name: "id", Type: &graphql.TypeRef{Kind: graphql.TypeKindNonNull, OfType: &graphql.TypeRef{Name: "ID"}}},
				},
			},
		},
	}

	operations, err := ConvertSchemaToOperations(schema, "http://example.com/graphql")
	require.NoError(t, err)

	assert.Len(t, operations, 2)

	// Check query operation
	queryOp := operations[0]
	assert.Equal(t, "query user", queryOp.Path)
	assert.Equal(t, "graphql", queryOp.Protocol)
	assert.Equal(t, "query", queryOp.GraphQLOperation)
	assert.Equal(t, "user", queryOp.GraphQLField)
	assert.Equal(t, "id", queryOp.OwnerField)

	// Check mutation operation
	mutationOp := operations[1]
	assert.Equal(t, "mutation deleteUser", mutationOp.Path)
	assert.Equal(t, "mutation", mutationOp.GraphQLOperation)
	assert.True(t, mutationOp.RequiresAuth) // Mutations default to requiring auth
}

func TestConvertSchemaToOperations_Empty(t *testing.T) {
	schema := &graphql.Schema{
		Types:     make(map[string]*graphql.TypeDef),
		Queries:   make([]*graphql.FieldDef, 0),
		Mutations: make([]*graphql.FieldDef, 0),
	}

	operations, err := ConvertSchemaToOperations(schema, "")
	require.NoError(t, err)
	assert.Empty(t, operations)
}

func TestConvertSchemaToOperations_AuthIndicator(t *testing.T) {
	schema := &graphql.Schema{
		Queries: []*graphql.FieldDef{
			{
				Name:        "privateData",
				Description: "Requires authentication to access",
				Type:        &graphql.TypeRef{Name: "Data", Kind: graphql.TypeKindObject},
			},
		},
	}

	operations, err := ConvertSchemaToOperations(schema, "")
	require.NoError(t, err)
	assert.Len(t, operations, 1)
	assert.True(t, operations[0].RequiresAuth)
}
