// pkg/plugins/graphql/operation_converter.go
package graphql

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/graphql"
	"github.com/praetorian-inc/hadrian/pkg/model"
)

// ConvertSchemaToOperations converts a GraphQL schema to API Operations
func ConvertSchemaToOperations(schema *graphql.Schema, baseURL string) ([]*model.Operation, error) {
	operations := make([]*model.Operation, 0)

	// Convert queries
	for _, field := range schema.Queries {
		op := convertFieldToOperation(field, "query", schema)
		operations = append(operations, op)
	}

	// Convert mutations
	for _, field := range schema.Mutations {
		op := convertFieldToOperation(field, "mutation", schema)
		operations = append(operations, op)
	}

	return operations, nil
}

func convertFieldToOperation(field *graphql.FieldDef, opType string, schema *graphql.Schema) *model.Operation {
	op := &model.Operation{
		Method:           "POST", // GraphQL always uses POST
		Path:             fmt.Sprintf("%s %s", opType, field.Name),
		Protocol:         "graphql",
		GraphQLOperation: opType,
		GraphQLField:     field.Name,
		RequiresAuth:     false,
		ResourceType:     field.Type.GetTypeName(),
		PathParams:       make([]model.Parameter, 0),
		QueryParams:      make([]model.Parameter, 0),
		HeaderParams:     make([]model.Parameter, 0),
		ResponseSchemas:  make(map[int]*model.Schema),
	}

	// Convert arguments to parameters
	for _, arg := range field.Args {
		param := model.Parameter{
			Name:     arg.Name,
			In:       "graphql_arg",
			Required: arg.Type.IsNonNull(),
			Type:     arg.Type.GetTypeName(),
		}
		op.PathParams = append(op.PathParams, param)
	}

	// Set owner field from common patterns
	for _, arg := range field.Args {
		if isIdentifierArg(arg.Name) {
			op.OwnerField = arg.Name
			break
		}
	}

	// Convert return type to response schema
	if returnType := field.Type.GetTypeName(); returnType != "" {
		if typeDef, ok := schema.GetType(returnType); ok {
			op.ResponseSchemas[200] = convertTypeDefToSchema(typeDef)
		}
	}

	// Check for auth directives (common patterns)
	if field.Description != "" && containsAuthIndicator(field.Description) {
		op.RequiresAuth = true
	}

	// Default mutations to requiring auth
	if opType == "mutation" {
		op.RequiresAuth = true
	}

	return op
}

func convertTypeDefToSchema(typeDef *graphql.TypeDef) *model.Schema {
	schema := &model.Schema{
		Type:       string(typeDef.Kind),
		Properties: make(map[string]*model.SchemaProperty),
		Required:   make([]string, 0),
	}

	for _, field := range typeDef.Fields {
		prop := &model.SchemaProperty{
			Type:   field.Type.GetTypeName(),
			Format: "",
		}
		schema.Properties[field.Name] = prop

		if field.Type.IsNonNull() {
			schema.Required = append(schema.Required, field.Name)
		}
	}

	return schema
}

func isIdentifierArg(name string) bool {
	switch name {
	case "id", "ID", "userId", "user_id", "objectId", "object_id":
		return true
	}
	return false
}

func containsAuthIndicator(description string) bool {
	indicators := []string{
		"authenticated", "auth required", "requires authentication",
		"logged in", "authorized", "private",
	}
	for _, indicator := range indicators {
		if containsIgnoreCase(description, indicator) {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	sLower := strings.ToLower(s)
	substrLower := strings.ToLower(substr)
	return strings.Contains(sLower, substrLower)
}
