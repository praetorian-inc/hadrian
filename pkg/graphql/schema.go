package graphql

// Schema represents a parsed GraphQL schema
type Schema struct {
	Types        map[string]*TypeDef
	Queries      []*FieldDef
	Mutations    []*FieldDef
	QueryType    string
	MutationType string
}

// TypeKind matches GraphQL __TypeKind enum
type TypeKind string

const (
	TypeKindScalar      TypeKind = "SCALAR"
	TypeKindObject      TypeKind = "OBJECT"
	TypeKindInterface   TypeKind = "INTERFACE"
	TypeKindUnion       TypeKind = "UNION"
	TypeKindEnum        TypeKind = "ENUM"
	TypeKindInputObject TypeKind = "INPUT_OBJECT"
	TypeKindList        TypeKind = "LIST"
	TypeKindNonNull     TypeKind = "NON_NULL"
)

// TypeDef represents a GraphQL type definition
type TypeDef struct {
	Name        string
	Kind        TypeKind
	Fields      []*FieldDef
	EnumValues  []string
	Interfaces  []string
	Description string
}

// FieldDef represents a field on a GraphQL type
type FieldDef struct {
	Name         string
	Type         *TypeRef
	Args         []*ArgumentDef
	Description  string
	IsDeprecated bool
}

// TypeRef references a type with support for List/NonNull wrappers
type TypeRef struct {
	Name   string // nil for List/NonNull
	Kind   TypeKind
	OfType *TypeRef // For List/NonNull wrapping
}

// ArgumentDef represents a field argument
type ArgumentDef struct {
	Name         string
	Type         *TypeRef
	DefaultValue string
	Description  string
}

// IsScalar returns true if this is a scalar type reference
func (t *TypeRef) IsScalar() bool {
	return t.Kind == TypeKindScalar ||
		(t.Name != "" && isBuiltinScalar(t.Name))
}

// IsNonNull returns true if this type is non-nullable
func (t *TypeRef) IsNonNull() bool {
	return t.Kind == TypeKindNonNull
}

// IsList returns true if this type is a list
func (t *TypeRef) IsList() bool {
	return t.Kind == TypeKindList
}

// UnwrapType returns the innermost type (unwrapping List/NonNull)
func (t *TypeRef) UnwrapType() *TypeRef {
	if t.OfType != nil {
		return t.OfType.UnwrapType()
	}
	return t
}

// GetTypeName returns the name of the base type
func (t *TypeRef) GetTypeName() string {
	if t.Name != "" {
		return t.Name
	}
	if t.OfType != nil {
		return t.OfType.GetTypeName()
	}
	return ""
}

func isBuiltinScalar(name string) bool {
	switch name {
	case "ID", "String", "Int", "Float", "Boolean":
		return true
	}
	return false
}

// GetQueryFields returns all top-level query fields
func (s *Schema) GetQueryFields() []*FieldDef {
	return s.Queries
}

// GetMutationFields returns all top-level mutation fields
func (s *Schema) GetMutationFields() []*FieldDef {
	return s.Mutations
}

// GetType returns a type by name
func (s *Schema) GetType(name string) (*TypeDef, bool) {
	t, ok := s.Types[name]
	return t, ok
}
