package graphql

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttackGenerator_IntrospectionProbeQuery(t *testing.T) {
	gen := NewAttackGenerator(nil)

	query := gen.IntrospectionProbeQuery()
	assert.Contains(t, query, "__schema")
	assert.Contains(t, query, "queryType")
}

func TestAttackGenerator_DepthAttackQuery(t *testing.T) {
	gen := NewAttackGenerator(nil)

	query := gen.DepthAttackQuery([]string{"user", "friends"}, 10)

	// Should have deep nesting
	assert.Contains(t, query, "user")
	assert.Contains(t, query, "friends")

	// Count braces to verify depth
	openCount := strings.Count(query, "{")
	closeCount := strings.Count(query, "}")
	assert.Equal(t, openCount, closeCount)
	assert.GreaterOrEqual(t, openCount, 10)
}

func TestAttackGenerator_BatchingAttackQuery(t *testing.T) {
	gen := NewAttackGenerator(nil)

	query := gen.BatchingAttackQuery("user(id: 1) { id }", 100)

	// Should have 100 aliases
	for i := 0; i < 100; i++ {
		assert.Contains(t, query, fmt.Sprintf("q%d:", i))
	}
}

func TestAttackGenerator_AliasBombQuery(t *testing.T) {
	gen := NewAttackGenerator(nil)

	query := gen.AliasBombQuery("__typename", 50)

	// Should have 50 aliases
	assert.Equal(t, 50, strings.Count(query, "__typename"))
}

func TestAttackGenerator_FieldSuggestionQuery(t *testing.T) {
	gen := NewAttackGenerator(nil)

	query := gen.FieldSuggestionQuery("User")
	assert.Contains(t, query, "__type")
	assert.Contains(t, query, `name: "User"`)
}

func TestAttackGenerator_BOLAProbeQuery(t *testing.T) {
	gen := NewAttackGenerator(nil)

	query := gen.BOLAProbeQuery("user", "id", "victim-123")
	assert.Contains(t, query, "user")
	assert.Contains(t, query, `id: "victim-123"`)
}

func TestAttackGenerator_BFLAProbeQuery(t *testing.T) {
	gen := NewAttackGenerator(nil)

	query := gen.BFLAProbeQuery("deleteUser", map[string]string{"id": "target-123"})
	assert.Contains(t, query, "mutation")
	assert.Contains(t, query, "deleteUser")
	assert.Contains(t, query, `id: "target-123"`)
}

func TestAttackGenerator_ComplexityAttackQuery(t *testing.T) {
	gen := NewAttackGenerator(nil)

	query := gen.ComplexityAttackQuery([]string{"id", "name"}, 3)

	// Should contain all fields
	assert.Contains(t, query, "id")
	assert.Contains(t, query, "name")
	assert.Contains(t, query, "node")
}

// Test helper to create a test schema with recursive relationships
func createPasteSchema() *Schema {
	// Define PasteObject type with owner field that returns UserObject
	pasteType := &TypeDef{
		Name: "PasteObject",
		Kind: TypeKindObject,
		Fields: []*FieldDef{
			{
				Name: "id",
				Type: &TypeRef{Name: "ID", Kind: TypeKindScalar},
			},
			{
				Name: "title",
				Type: &TypeRef{Name: "String", Kind: TypeKindScalar},
			},
			{
				Name: "owner",
				Type: &TypeRef{Name: "UserObject", Kind: TypeKindObject},
			},
		},
	}

	// Define UserObject type with pastes field that returns [PasteObject]
	userType := &TypeDef{
		Name: "UserObject",
		Kind: TypeKindObject,
		Fields: []*FieldDef{
			{
				Name: "id",
				Type: &TypeRef{Name: "ID", Kind: TypeKindScalar},
			},
			{
				Name: "username",
				Type: &TypeRef{Name: "String", Kind: TypeKindScalar},
			},
			{
				Name: "pastes",
				Type: &TypeRef{
					Kind:   TypeKindList,
					OfType: &TypeRef{Name: "PasteObject", Kind: TypeKindObject},
				},
			},
		},
	}

	// Query type with pastes field
	queryType := &TypeDef{
		Name: "Query",
		Kind: TypeKindObject,
		Fields: []*FieldDef{
			{
				Name: "pastes",
				Type: &TypeRef{
					Kind:   TypeKindList,
					OfType: &TypeRef{Name: "PasteObject", Kind: TypeKindObject},
				},
			},
		},
	}

	return &Schema{
		Types: map[string]*TypeDef{
			"PasteObject": pasteType,
			"UserObject":  userType,
			"Query":       queryType,
		},
		Queries:   queryType.Fields,
		QueryType: "Query",
	}
}

func TestDepthAttackQuery_WithValidRecursion(t *testing.T) {
	schema := createPasteSchema()
	gen := NewAttackGenerator(schema)

	// Generate a depth attack using actual recursive field relationships
	// Should create: pastes { owner { pastes { owner { ... } } } }
	query, err := gen.DepthAttackQueryWithSchema("pastes", 5)

	assert.NoError(t, err)
	assert.Contains(t, query, "pastes")
	assert.Contains(t, query, "owner")

	// Verify structure is valid - should have pastes and owner alternating
	assert.Contains(t, query, "pastes { owner")

	// Should end with a scalar field
	assert.Contains(t, query, "id")
}

func TestBatchingAttackQuery_WithObjectSelection(t *testing.T) {
	schema := createPasteSchema()
	gen := NewAttackGenerator(schema)

	// Generate batching attack for a field that returns an object type
	query, err := gen.BatchingAttackQueryWithSchema("pastes", 10)

	assert.NoError(t, err)

	// Should have 10 aliases
	for i := 0; i < 10; i++ {
		assert.Contains(t, query, fmt.Sprintf("q%d:", i))
	}

	// Each alias should have field selection since pastes returns object type
	assert.Contains(t, query, "q0: pastes { id }")

	// Should not have bare "q0: pastes" without selection
	assert.NotContains(t, query, "q0: pastes q1:")
}

func TestDepthAttackQuery_VerifyValidStructure(t *testing.T) {
	schema := createPasteSchema()
	gen := NewAttackGenerator(schema)

	query, err := gen.DepthAttackQueryWithSchema("pastes", 3)
	assert.NoError(t, err)

	// The generated query should follow actual field relationships
	// pastes -> PasteObject -> owner -> UserObject -> pastes -> PasteObject -> id
	// This should be: pastes { owner { pastes { id } } }

	// Verify it contains the recursive pattern
	assert.Contains(t, query, "query DepthAttack")
	assert.Contains(t, query, "pastes { owner { pastes")

	// Count the nesting depth - should have 3 levels
	openBraces := strings.Count(query, "{")
	closeBraces := strings.Count(query, "}")
	assert.Equal(t, openBraces, closeBraces, "Braces should be balanced")

	// Should end with a scalar field
	assert.Contains(t, query, "id")
}

func TestBatchingAttackQuery_WithNonObjectField(t *testing.T) {
	// Create a schema with a scalar query field
	schema := &Schema{
		Types: map[string]*TypeDef{
			"Query": {
				Name: "Query",
				Kind: TypeKindObject,
				Fields: []*FieldDef{
					{
						Name: "version",
						Type: &TypeRef{Name: "String", Kind: TypeKindScalar},
					},
				},
			},
		},
		Queries: []*FieldDef{
			{
				Name: "version",
				Type: &TypeRef{Name: "String", Kind: TypeKindScalar},
			},
		},
		QueryType: "Query",
	}

	gen := NewAttackGenerator(schema)
	query, err := gen.BatchingAttackQueryWithSchema("version", 5)

	assert.NoError(t, err)
	// Scalar fields should not have field selection
	assert.Contains(t, query, "q0: version q1:")
	assert.NotContains(t, query, "version { id }")
}

func TestDepthAttackQuery_ErrorCases(t *testing.T) {
	schema := createPasteSchema()
	gen := NewAttackGenerator(schema)

	t.Run("returns error for nil schema", func(t *testing.T) {
		genNoSchema := NewAttackGenerator(nil)
		_, err := genNoSchema.DepthAttackQueryWithSchema("pastes", 5)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "schema is required")
	})

	t.Run("returns error for non-existent field", func(t *testing.T) {
		_, err := gen.DepthAttackQueryWithSchema("nonExistentField", 5)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found in schema")
	})
}

func TestBatchingAttackQuery_ErrorCases(t *testing.T) {
	schema := createPasteSchema()
	gen := NewAttackGenerator(schema)

	t.Run("returns error for nil schema", func(t *testing.T) {
		genNoSchema := NewAttackGenerator(nil)
		_, err := genNoSchema.BatchingAttackQueryWithSchema("pastes", 10)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "schema is required")
	})

	t.Run("returns error for non-existent field", func(t *testing.T) {
		_, err := gen.BatchingAttackQueryWithSchema("nonExistentField", 10)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found in schema")
	})
}

func TestFieldSuggestionQuery_EscapesDoubleQuotes(t *testing.T) {
	gen := NewAttackGenerator(nil)

	// Test case with double quote injection attempt
	maliciousTypeName := `User") { fields { name } } } query Inject { __type(name: "Admin`
	query := gen.FieldSuggestionQuery(maliciousTypeName)

	// The query should escape the double quotes in the typeName
	// Expected: { __type(name: "User\") { fields { name } } } } query Inject { __type(name: \"Admin") { fields { name } } }
	assert.Contains(t, query, `\"`)
	// Should not contain unescaped double quotes that would break out of the string
	assert.NotContains(t, query, `name: "User") { fields`)
}
