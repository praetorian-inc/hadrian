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

func TestFormatValue_EscapesSpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "escapes double quotes in string",
			input:    `test"value`,
			expected: `"test\"value"`,
		},
		{
			name:     "escapes backslashes in string",
			input:    `test\value`,
			expected: `"test\\value"`,
		},
		{
			name:     "escapes newlines in string",
			input:    "test\nvalue",
			expected: `"test\nvalue"`,
		},
		{
			name:     "escapes carriage returns in string",
			input:    "test\rvalue",
			expected: `"test\rvalue"`,
		},
		{
			name:     "escapes tabs in string",
			input:    "test\tvalue",
			expected: `"test\tvalue"`,
		},
		{
			name:     "escapes GraphQL injection payload",
			input:    `victim"}{evil:__schema{types{name}}}`,
			expected: `"victim\"}{evil:__schema{types{name}}}"`,
		},
		{
			name:     "handles normal string",
			input:    "normalValue",
			expected: `"normalValue"`,
		},
		{
			name:     "handles integer",
			input:    123,
			expected: "123",
		},
		{
			name:     "handles boolean",
			input:    true,
			expected: "true",
		},
		{
			name:     "escapes special characters in default case",
			input:    struct{ Value string }{Value: `test"value`},
			expected: `"{test\"value}"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
