package graphql

import (
	"fmt"
	"os"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

// LoadSchemaFromFile loads a GraphQL schema from an SDL file
func LoadSchemaFromFile(filepath string) (*Schema, error) {
	// Read the SDL file
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema file: %w", err)
	}

	// Parse SDL
	schema, err := ParseSDL(string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SDL: %w", err)
	}

	return schema, nil
}

// ParseSDL parses a GraphQL SDL string into our Schema type
func ParseSDL(sdl string) (*Schema, error) {
	source := &ast.Source{Input: sdl}
	doc, err := gqlparser.LoadSchema(source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SDL: %w", err)
	}

	return convertASTSchema(doc), nil
}

func convertASTSchema(doc *ast.Schema) *Schema {
	schema := &Schema{
		Types:     make(map[string]*TypeDef),
		Queries:   make([]*FieldDef, 0),
		Mutations: make([]*FieldDef, 0),
	}

	// Convert types
	for name, def := range doc.Types {
		if isBuiltinType(name) {
			continue
		}
		schema.Types[name] = convertTypeDef(def)
	}

	// Extract query type fields
	if doc.Query != nil {
		schema.QueryType = doc.Query.Name
		for _, field := range doc.Query.Fields {
			// Skip introspection fields
			if len(field.Name) > 2 && field.Name[:2] == "__" {
				continue
			}
			schema.Queries = append(schema.Queries, convertFieldDef(field))
		}
	}

	// Extract mutation type fields
	if doc.Mutation != nil {
		schema.MutationType = doc.Mutation.Name
		for _, field := range doc.Mutation.Fields {
			// Skip introspection fields
			if len(field.Name) > 2 && field.Name[:2] == "__" {
				continue
			}
			schema.Mutations = append(schema.Mutations, convertFieldDef(field))
		}
	}

	return schema
}

func convertTypeDef(def *ast.Definition) *TypeDef {
	typeDef := &TypeDef{
		Name:        def.Name,
		Kind:        convertKind(def.Kind),
		Description: def.Description,
		Fields:      make([]*FieldDef, 0),
	}

	// Convert fields
	for _, field := range def.Fields {
		typeDef.Fields = append(typeDef.Fields, convertFieldDef(field))
	}

	// Convert enum values
	for _, val := range def.EnumValues {
		typeDef.EnumValues = append(typeDef.EnumValues, val.Name)
	}

	// Convert interfaces
	for _, iface := range def.Interfaces {
		typeDef.Interfaces = append(typeDef.Interfaces, iface)
	}

	return typeDef
}

func convertFieldDef(field *ast.FieldDefinition) *FieldDef {
	fieldDef := &FieldDef{
		Name:        field.Name,
		Type:        convertTypeRef(field.Type),
		Description: field.Description,
		Args:        make([]*ArgumentDef, 0),
	}

	// Check deprecation
	for _, directive := range field.Directives {
		if directive.Name == "deprecated" {
			fieldDef.IsDeprecated = true
			break
		}
	}

	// Convert arguments
	for _, arg := range field.Arguments {
		fieldDef.Args = append(fieldDef.Args, convertArgument(arg))
	}

	return fieldDef
}

func convertTypeRef(t *ast.Type) *TypeRef {
	if t == nil {
		return nil
	}

	typeRef := &TypeRef{}

	if t.NonNull {
		typeRef.Kind = TypeKindNonNull
		typeRef.OfType = convertTypeRef(&ast.Type{
			NamedType: t.NamedType,
			Elem:      t.Elem,
		})
		return typeRef
	}

	if t.Elem != nil {
		typeRef.Kind = TypeKindList
		typeRef.OfType = convertTypeRef(t.Elem)
		return typeRef
	}

	typeRef.Name = t.NamedType
	typeRef.Kind = TypeKindScalar // Default, will be corrected

	return typeRef
}

func convertArgument(arg *ast.ArgumentDefinition) *ArgumentDef {
	argDef := &ArgumentDef{
		Name:        arg.Name,
		Type:        convertTypeRef(arg.Type),
		Description: arg.Description,
	}

	if arg.DefaultValue != nil {
		argDef.DefaultValue = arg.DefaultValue.String()
	}

	return argDef
}

func convertKind(kind ast.DefinitionKind) TypeKind {
	switch kind {
	case ast.Scalar:
		return TypeKindScalar
	case ast.Object:
		return TypeKindObject
	case ast.Interface:
		return TypeKindInterface
	case ast.Union:
		return TypeKindUnion
	case ast.Enum:
		return TypeKindEnum
	case ast.InputObject:
		return TypeKindInputObject
	default:
		return TypeKindObject
	}
}

func isBuiltinType(name string) bool {
	switch name {
	case "ID", "String", "Int", "Float", "Boolean",
		"__Schema", "__Type", "__Field", "__InputValue",
		"__EnumValue", "__Directive", "__DirectiveLocation":
		return true
	}
	return false
}
