// pkg/graphql/introspection.go
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// StandardIntrospectionQuery is the full introspection query
const StandardIntrospectionQuery = `
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
`

// HTTPClient interface for dependency injection
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// IntrospectionClient fetches schema via GraphQL introspection
type IntrospectionClient struct {
	httpClient HTTPClient
	endpoint   string
	headers    map[string]string
}

// NewIntrospectionClient creates a new introspection client
func NewIntrospectionClient(client HTTPClient, endpoint string) *IntrospectionClient {
	return &IntrospectionClient{
		httpClient: client,
		endpoint:   endpoint,
		headers:    make(map[string]string),
	}
}

// SetHeader adds a header to introspection requests
func (c *IntrospectionClient) SetHeader(key, value string) {
	c.headers[key] = value
}

// IntrospectionResult represents the introspection response
type IntrospectionResult struct {
	Data   IntrospectionData `json:"data"`
	Errors []GraphQLError    `json:"errors,omitempty"`
}

type IntrospectionData struct {
	Schema IntrospectionSchema `json:"__schema"`
}

type IntrospectionSchema struct {
	QueryType        *TypeNameRef        `json:"queryType"`
	MutationType     *TypeNameRef        `json:"mutationType"`
	SubscriptionType *TypeNameRef        `json:"subscriptionType"`
	Types            []IntrospectionType `json:"types"`
}

type TypeNameRef struct {
	Name string `json:"name"`
}

type IntrospectionType struct {
	Kind          string                 `json:"kind"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Fields        []IntrospectionField   `json:"fields"`
	InputFields   []IntrospectionInput   `json:"inputFields"`
	Interfaces    []IntrospectionTypeRef `json:"interfaces"`
	EnumValues    []IntrospectionEnum    `json:"enumValues"`
	PossibleTypes []IntrospectionTypeRef `json:"possibleTypes"`
}

type IntrospectionField struct {
	Name              string               `json:"name"`
	Description       string               `json:"description"`
	Args              []IntrospectionInput `json:"args"`
	Type              IntrospectionTypeRef `json:"type"`
	IsDeprecated      bool                 `json:"isDeprecated"`
	DeprecationReason string               `json:"deprecationReason"`
}

type IntrospectionInput struct {
	Name         string               `json:"name"`
	Description  string               `json:"description"`
	Type         IntrospectionTypeRef `json:"type"`
	DefaultValue *string              `json:"defaultValue"`
}

type IntrospectionTypeRef struct {
	Kind   string                `json:"kind"`
	Name   string                `json:"name"`
	OfType *IntrospectionTypeRef `json:"ofType"`
}

type IntrospectionEnum struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	IsDeprecated      bool   `json:"isDeprecated"`
	DeprecationReason string `json:"deprecationReason"`
}

type GraphQLError struct {
	Message   string `json:"message"`
	Locations []struct {
		Line   int `json:"line"`
		Column int `json:"column"`
	} `json:"locations"`
}

// FetchSchema performs introspection and returns parsed Schema
func (c *IntrospectionClient) FetchSchema(ctx context.Context) (*Schema, error) {
	// Build request
	reqBody := map[string]interface{}{
		"query": StandardIntrospectionQuery,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("introspection failed with status %d (body unreadable: %v)", resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("introspection failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result IntrospectionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("introspection returned errors: %v", result.Errors[0].Message)
	}

	return ConvertIntrospectionResult(&result), nil
}

// ConvertIntrospectionResult converts introspection JSON to our Schema type
func ConvertIntrospectionResult(result *IntrospectionResult) *Schema {
	schema := &Schema{
		Types:     make(map[string]*TypeDef),
		Queries:   make([]*FieldDef, 0),
		Mutations: make([]*FieldDef, 0),
	}

	if result.Data.Schema.QueryType != nil {
		schema.QueryType = result.Data.Schema.QueryType.Name
	}
	if result.Data.Schema.MutationType != nil {
		schema.MutationType = result.Data.Schema.MutationType.Name
	}

	// First pass: create all types
	for _, t := range result.Data.Schema.Types {
		if isIntrospectionType(t.Name) {
			continue
		}
		schema.Types[t.Name] = convertIntrospectionType(&t)
	}

	// Extract query fields
	if queryType, ok := schema.Types[schema.QueryType]; ok {
		schema.Queries = queryType.Fields
	}

	// Extract mutation fields
	if mutationType, ok := schema.Types[schema.MutationType]; ok {
		schema.Mutations = mutationType.Fields
	}

	return schema
}

func convertIntrospectionType(t *IntrospectionType) *TypeDef {
	typeDef := &TypeDef{
		Name:        t.Name,
		Kind:        TypeKind(t.Kind),
		Description: t.Description,
		Fields:      make([]*FieldDef, 0),
	}

	for _, f := range t.Fields {
		typeDef.Fields = append(typeDef.Fields, convertIntrospectionField(&f))
	}

	for _, e := range t.EnumValues {
		typeDef.EnumValues = append(typeDef.EnumValues, e.Name)
	}

	for _, i := range t.Interfaces {
		typeDef.Interfaces = append(typeDef.Interfaces, i.Name)
	}

	return typeDef
}

func convertIntrospectionField(f *IntrospectionField) *FieldDef {
	fieldDef := &FieldDef{
		Name:         f.Name,
		Type:         convertIntrospectionTypeRef(&f.Type),
		Description:  f.Description,
		IsDeprecated: f.IsDeprecated,
		Args:         make([]*ArgumentDef, 0),
	}

	for _, arg := range f.Args {
		argDef := &ArgumentDef{
			Name:        arg.Name,
			Type:        convertIntrospectionTypeRef(&arg.Type),
			Description: arg.Description,
		}
		if arg.DefaultValue != nil {
			argDef.DefaultValue = *arg.DefaultValue
		}
		fieldDef.Args = append(fieldDef.Args, argDef)
	}

	return fieldDef
}

func convertIntrospectionTypeRef(t *IntrospectionTypeRef) *TypeRef {
	if t == nil {
		return nil
	}

	typeRef := &TypeRef{
		Name:   t.Name,
		Kind:   TypeKind(t.Kind),
		OfType: convertIntrospectionTypeRef(t.OfType),
	}

	return typeRef
}

func isIntrospectionType(name string) bool {
	return len(name) > 2 && name[:2] == "__"
}
