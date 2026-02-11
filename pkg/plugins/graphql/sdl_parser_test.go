// pkg/plugins/graphql/sdl_parser_test.go
package graphql

import (
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/graphql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSDL_BasicSchema(t *testing.T) {
	sdl := `
		type Query {
			user(id: ID!): User
			users: [User!]!
		}

		type Mutation {
			createUser(name: String!, email: String!): User
			deleteUser(id: ID!): Boolean
		}

		type User {
			id: ID!
			name: String!
			email: String
			role: Role!
		}

		enum Role {
			ADMIN
			USER
			GUEST
		}
	`

	schema, err := ParseSDL(sdl)
	require.NoError(t, err)

	// Check query fields
	assert.Len(t, schema.Queries, 2)
	assert.Equal(t, "user", schema.Queries[0].Name)
	assert.Equal(t, "users", schema.Queries[1].Name)

	// Check mutation fields
	assert.Len(t, schema.Mutations, 2)
	assert.Equal(t, "createUser", schema.Mutations[0].Name)

	// Check User type
	userType, ok := schema.GetType("User")
	require.True(t, ok)
	assert.Len(t, userType.Fields, 4)

	// Check Role enum
	roleType, ok := schema.GetType("Role")
	require.True(t, ok)
	assert.Equal(t, graphql.TypeKindEnum, roleType.Kind)
	assert.Contains(t, roleType.EnumValues, "ADMIN")
}

func TestParseSDL_Arguments(t *testing.T) {
	sdl := `
		type Query {
			search(query: String!, limit: Int = 10, offset: Int): [Result]
		}
		type Result {
			id: ID!
		}
	`

	schema, err := ParseSDL(sdl)
	require.NoError(t, err)

	searchField := schema.Queries[0]
	assert.Equal(t, "search", searchField.Name)
	assert.Len(t, searchField.Args, 3)

	// Check query argument is required (NonNull)
	queryArg := searchField.Args[0]
	assert.Equal(t, "query", queryArg.Name)
	assert.True(t, queryArg.Type.IsNonNull())

	// Check limit has default value
	limitArg := searchField.Args[1]
	assert.Equal(t, "limit", limitArg.Name)
	assert.Equal(t, "10", limitArg.DefaultValue)
}

func TestParseSDL_InvalidSDL(t *testing.T) {
	sdl := "not valid graphql {"

	_, err := ParseSDL(sdl)
	assert.Error(t, err)
}
