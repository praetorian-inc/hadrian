package graphql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQueryBuilder_BuildQuery(t *testing.T) {
	schema := &Schema{
		Types: map[string]*TypeDef{
			"User": {
				Name: "User",
				Kind: TypeKindObject,
				Fields: []*FieldDef{
					{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
					{Name: "name", Type: &TypeRef{Name: "String", Kind: TypeKindScalar}},
				},
			},
		},
		Queries: []*FieldDef{
			{
				Name: "user",
				Type: &TypeRef{Name: "User", Kind: TypeKindObject},
				Args: []*ArgumentDef{
					{Name: "id", Type: &TypeRef{Name: "ID"}},
				},
			},
		},
	}

	builder := NewQueryBuilder(schema)

	// Test with arguments
	query := builder.BuildQuery("user", map[string]interface{}{"id": "123"}, 1)
	assert.Contains(t, query, "user")
	assert.Contains(t, query, `id: "123"`)

	// Test without arguments
	query = builder.BuildQuery("user", nil, 1)
	assert.Contains(t, query, "user")
}

func TestQueryBuilder_BuildDepthAttackQuery(t *testing.T) {
	builder := NewQueryBuilder(nil)

	query := builder.BuildDepthAttackQuery([]string{"user", "friends"}, 5)

	// Should have nested structure
	assert.Contains(t, query, "user")
	assert.Contains(t, query, "friends")
	assert.Contains(t, query, "id")

	// Count opening braces
	openCount := countChar(query, '{')
	closeCount := countChar(query, '}')
	assert.Equal(t, openCount, closeCount)
}

func TestQueryBuilder_BuildBatchQuery(t *testing.T) {
	builder := NewQueryBuilder(nil)

	query := builder.BuildBatchQuery("user(id: 1) { id }", "getUser", 3)

	assert.Contains(t, query, "alias0:")
	assert.Contains(t, query, "alias1:")
	assert.Contains(t, query, "alias2:")
}

func countChar(s string, c rune) int {
	count := 0
	for _, char := range s {
		if char == c {
			count++
		}
	}
	return count
}
