package graphql

import (
	"fmt"
	"strings"
)

// QueryBuilder constructs GraphQL queries
type QueryBuilder struct {
	schema *Schema
}

// NewQueryBuilder creates a new query builder
func NewQueryBuilder(schema *Schema) *QueryBuilder {
	return &QueryBuilder{schema: schema}
}

// BuildQuery creates a query for a field with all scalar subfields
func (b *QueryBuilder) BuildQuery(fieldName string, args map[string]interface{}, maxDepth int) string {
	// Find the field
	var field *FieldDef
	for _, f := range b.schema.Queries {
		if f.Name == fieldName {
			field = f
			break
		}
	}
	if field == nil {
		for _, f := range b.schema.Mutations {
			if f.Name == fieldName {
				field = f
				break
			}
		}
	}
	if field == nil {
		return ""
	}

	// Build argument string
	argStr := b.buildArgString(args)

	// Build selection set
	selection := b.buildSelectionSet(field.Type.GetTypeName(), maxDepth)

	return fmt.Sprintf("{ %s%s %s }", fieldName, argStr, selection)
}

// BuildDepthAttackQuery creates a deeply nested query
func (b *QueryBuilder) BuildDepthAttackQuery(fieldPath []string, depth int) string {
	var sb strings.Builder
	sb.WriteString("{ ")

	for i := 0; i < depth; i++ {
		fieldName := fieldPath[i%len(fieldPath)]
		sb.WriteString(fieldName)
		sb.WriteString(" { ")
	}

	sb.WriteString("id ")

	for i := 0; i < depth; i++ {
		sb.WriteString("} ")
	}

	sb.WriteString("}")
	return sb.String()
}

// BuildBatchQuery creates a query with N aliases for batching attack
func (b *QueryBuilder) BuildBatchQuery(baseQuery string, operationName string, count int) string {
	var sb strings.Builder
	sb.WriteString("{ ")

	for i := 0; i < count; i++ {
		sb.WriteString(fmt.Sprintf("alias%d: %s ", i, baseQuery))
	}

	sb.WriteString("}")
	return sb.String()
}

func (b *QueryBuilder) buildArgString(args map[string]interface{}) string {
	if len(args) == 0 {
		return ""
	}

	var parts []string
	for key, value := range args {
		parts = append(parts, fmt.Sprintf("%s: %s", key, formatValue(value)))
	}

	return fmt.Sprintf("(%s)", strings.Join(parts, ", "))
}

func (b *QueryBuilder) buildSelectionSet(typeName string, depth int) string {
	if depth <= 0 {
		return ""
	}

	typeDef, ok := b.schema.GetType(typeName)
	if !ok {
		return ""
	}

	var fields []string
	for _, field := range typeDef.Fields {
		if field.Type.IsScalar() {
			fields = append(fields, field.Name)
		} else if depth > 1 {
			nestedSelection := b.buildSelectionSet(field.Type.GetTypeName(), depth-1)
			if nestedSelection != "" {
				fields = append(fields, fmt.Sprintf("%s %s", field.Name, nestedSelection))
			}
		}
	}

	if len(fields) == 0 {
		return ""
	}

	return fmt.Sprintf("{ %s }", strings.Join(fields, " "))
}

func formatValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		escaped := strings.ReplaceAll(val, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		escaped = strings.ReplaceAll(escaped, "\n", `\n`)
		escaped = strings.ReplaceAll(escaped, "\r", `\r`)
		escaped = strings.ReplaceAll(escaped, "\t", `\t`)
		return fmt.Sprintf(`"%s"`, escaped)
	case int, int64, float64:
		return fmt.Sprintf("%v", val)
	case bool:
		return fmt.Sprintf("%t", val)
	default:
		// Convert to string first, then apply the same escaping
		str := fmt.Sprintf("%v", val)
		escaped := strings.ReplaceAll(str, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		escaped = strings.ReplaceAll(escaped, "\n", `\n`)
		escaped = strings.ReplaceAll(escaped, "\r", `\r`)
		escaped = strings.ReplaceAll(escaped, "\t", `\t`)
		return fmt.Sprintf(`"%s"`, escaped)
	}
}
