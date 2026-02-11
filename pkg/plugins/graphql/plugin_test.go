package graphql

import (
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGraphQLPlugin_Registration(t *testing.T) {
	// Plugin should be auto-registered via init()
	plugin, ok := plugins.Get(plugins.ProtocolGraphQL)
	require.True(t, ok, "GraphQL plugin should be registered")
	assert.Equal(t, "GraphQL Schema Parser", plugin.Name())
	assert.Equal(t, plugins.ProtocolGraphQL, plugin.Type())
}

func TestGraphQLPlugin_CanParse_SDL(t *testing.T) {
	plugin := &GraphQLPlugin{}

	tests := []struct {
		name     string
		input    string
		filename string
		want     bool
	}{
		{
			name:     "SDL by extension",
			input:    "anything",
			filename: "schema.graphql",
			want:     true,
		},
		{
			name:     "GQL extension",
			input:    "anything",
			filename: "schema.gql",
			want:     true,
		},
		{
			name:     "SDL by content - type Query",
			input:    "type Query { users: [User] }",
			filename: "schema.txt",
			want:     true,
		},
		{
			name:     "SDL by content - type Mutation",
			input:    "type Mutation { createUser(name: String!): User }",
			filename: "schema.txt",
			want:     true,
		},
		{
			name:     "SDL by content - schema block",
			input:    "schema { query: Query mutation: Mutation }",
			filename: "schema.txt",
			want:     true,
		},
		{
			name:     "Not GraphQL - OpenAPI",
			input:    `{"openapi": "3.0.0", "paths": {}}`,
			filename: "openapi.json",
			want:     false,
		},
		{
			name:     "Not GraphQL - random JSON",
			input:    `{"foo": "bar"}`,
			filename: "data.json",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := plugin.CanParse([]byte(tt.input), tt.filename)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGraphQLPlugin_CanParse_Introspection(t *testing.T) {
	plugin := &GraphQLPlugin{}

	introspectionJSON := `{
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": []
            }
        }
    }`

	assert.True(t, plugin.CanParse([]byte(introspectionJSON), "introspection.json"))
}

func TestGraphQLPlugin_Parse_SDL(t *testing.T) {
	plugin := &GraphQLPlugin{}

	sdl := `
		type Query {
			user(id: ID!): User
		}
		type Mutation {
			deleteUser(id: ID!): Boolean
		}
		type User {
			id: ID!
			email: String
		}
	`

	spec, err := plugin.Parse([]byte(sdl))
	require.NoError(t, err)
	require.NotNil(t, spec)

	assert.Equal(t, "GraphQL API", spec.Info.Title)
	assert.Len(t, spec.Operations, 2) // 1 query + 1 mutation

	// Find the query operation
	var queryOp *model.Operation
	for _, op := range spec.Operations {
		if op.GraphQLOperation == "query" {
			queryOp = op
			break
		}
	}
	require.NotNil(t, queryOp)
	assert.Equal(t, "user", queryOp.GraphQLField)
}

func TestGraphQLPlugin_Parse_Introspection(t *testing.T) {
	plugin := &GraphQLPlugin{}

	introspectionJSON := `{
		"data": {
			"__schema": {
				"queryType": {"name": "Query"},
				"mutationType": null,
				"types": [
					{
						"kind": "OBJECT",
						"name": "Query",
						"fields": [
							{
								"name": "hello",
								"type": {"kind": "SCALAR", "name": "String", "ofType": null},
								"args": []
							}
						]
					}
				]
			}
		}
	}`

	spec, err := plugin.Parse([]byte(introspectionJSON))
	require.NoError(t, err)
	require.NotNil(t, spec)

	assert.Len(t, spec.Operations, 1)
	assert.Equal(t, "hello", spec.Operations[0].GraphQLField)
}
