package graphql

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/graphql"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/plugins"
)

// GraphQLPlugin parses GraphQL schemas (SDL or introspection)
type GraphQLPlugin struct{}

// init self-registers the plugin
func init() {
	plugins.Register(plugins.ProtocolGraphQL, &GraphQLPlugin{})
}

func (p *GraphQLPlugin) Name() string {
	return "GraphQL Schema Parser"
}

func (p *GraphQLPlugin) Type() plugins.Protocol {
	return plugins.ProtocolGraphQL
}

// CanParse checks if input is a GraphQL schema (SDL or introspection JSON)
func (p *GraphQLPlugin) CanParse(input []byte, filename string) bool {
	ext := filepath.Ext(filename)

	// Check for SDL file extension
	if ext == ".graphql" || ext == ".gql" {
		return true
	}

	// Check content for GraphQL markers
	content := string(input)

	// SDL markers
	if strings.Contains(content, "type Query") ||
		strings.Contains(content, "type Mutation") ||
		strings.Contains(content, "schema {") {
		return true
	}

	// Introspection JSON markers
	if strings.Contains(content, "__schema") &&
		strings.Contains(content, "queryType") {
		return true
	}

	return false
}

// Parse converts GraphQL schema to internal model
func (p *GraphQLPlugin) Parse(input []byte) (*model.APISpec, error) {
	content := string(input)

	var schema *graphql.Schema
	var err error

	// Detect input type and parse accordingly
	if isIntrospectionJSON(content) {
		schema, err = parseIntrospectionJSON(input)
	} else {
		schema, err = ParseSDL(content)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse GraphQL schema: %w", err)
	}

	// Convert to operations
	operations, err := ConvertSchemaToOperations(schema, "")
	if err != nil {
		return nil, fmt.Errorf("failed to convert schema: %w", err)
	}

	return &model.APISpec{
		Info: model.APIInfo{
			Title:   "GraphQL API",
			Version: "1.0.0",
		},
		Operations: operations,
	}, nil
}

func isIntrospectionJSON(content string) bool {
	return strings.Contains(content, `"__schema"`) ||
		(strings.Contains(content, `"data"`) && strings.Contains(content, `"queryType"`))
}

func parseIntrospectionJSON(input []byte) (*graphql.Schema, error) {
	var result graphql.IntrospectionResult
	if err := json.Unmarshal(input, &result); err != nil {
		return nil, fmt.Errorf("failed to parse introspection JSON: %w", err)
	}
	return graphql.ConvertIntrospectionResult(&result), nil
}
