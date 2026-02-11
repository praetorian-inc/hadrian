package graphql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTypeRef_UnwrapType(t *testing.T) {
	// Test [User!]! -> User
	typeRef := &TypeRef{
		Kind: TypeKindNonNull,
		OfType: &TypeRef{
			Kind: TypeKindList,
			OfType: &TypeRef{
				Kind: TypeKindNonNull,
				OfType: &TypeRef{
					Name: "User",
					Kind: TypeKindObject,
				},
			},
		},
	}

	unwrapped := typeRef.UnwrapType()
	assert.Equal(t, "User", unwrapped.Name)
	assert.Equal(t, TypeKindObject, unwrapped.Kind)
}

func TestTypeRef_GetTypeName(t *testing.T) {
	// Test nested type name extraction
	typeRef := &TypeRef{
		Kind:   TypeKindList,
		OfType: &TypeRef{Name: "String", Kind: TypeKindScalar},
	}
	assert.Equal(t, "String", typeRef.GetTypeName())
}

func TestSchema_GetType(t *testing.T) {
	schema := &Schema{
		Types: map[string]*TypeDef{
			"User": {Name: "User", Kind: TypeKindObject},
		},
	}

	userType, ok := schema.GetType("User")
	assert.True(t, ok)
	assert.Equal(t, "User", userType.Name)

	_, ok = schema.GetType("NotExists")
	assert.False(t, ok)
}
