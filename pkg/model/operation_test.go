package model

import (
	"testing"
)

func TestOperation(t *testing.T) {
	t.Run("initialize with all fields", func(t *testing.T) {
		op := &Operation{
			Method:             "GET",
			Path:               "/api/users/{id}",
			PathParams:         []Parameter{{Name: "id", In: "path", Required: true, Type: "string"}},
			QueryParams:        []Parameter{{Name: "filter", In: "query", Required: false, Type: "string"}},
			HeaderParams:       []Parameter{{Name: "Authorization", In: "header", Required: true, Type: "string"}},
			BodySchema:         &Schema{Type: "object"},
			ResponseSchemas:    map[int]*Schema{200: {Type: "object"}},
			RequiresAuth:       true,
			ResourceType:       "users",
			OwnerField:         "id",
			SuccessStatus:      200,
			UnauthorizedStatus: 403,
			Tags:               []string{"users", "read"},
		}

		if op.Method != "GET" {
			t.Errorf("expected Method=GET, got %s", op.Method)
		}
		if op.Path != "/api/users/{id}" {
			t.Errorf("expected Path=/api/users/{id}, got %s", op.Path)
		}
		if len(op.PathParams) != 1 {
			t.Errorf("expected 1 path param, got %d", len(op.PathParams))
		}
		if len(op.QueryParams) != 1 {
			t.Errorf("expected 1 query param, got %d", len(op.QueryParams))
		}
		if len(op.HeaderParams) != 1 {
			t.Errorf("expected 1 header param, got %d", len(op.HeaderParams))
		}
		if op.BodySchema == nil {
			t.Error("expected BodySchema to be set")
		}
		if len(op.ResponseSchemas) != 1 {
			t.Errorf("expected 1 response schema, got %d", len(op.ResponseSchemas))
		}
		if !op.RequiresAuth {
			t.Error("expected RequiresAuth=true")
		}
		if op.ResourceType != "users" {
			t.Errorf("expected ResourceType=users, got %s", op.ResourceType)
		}
		if op.OwnerField != "id" {
			t.Errorf("expected OwnerField=id, got %s", op.OwnerField)
		}
		if op.SuccessStatus != 200 {
			t.Errorf("expected SuccessStatus=200, got %d", op.SuccessStatus)
		}
		if op.UnauthorizedStatus != 403 {
			t.Errorf("expected UnauthorizedStatus=403, got %d", op.UnauthorizedStatus)
		}
		if len(op.Tags) != 2 {
			t.Errorf("expected 2 tags, got %d", len(op.Tags))
		}
	})

	t.Run("zero values are valid", func(t *testing.T) {
		op := &Operation{}
		if op.Method != "" {
			t.Errorf("expected empty Method, got %s", op.Method)
		}
		if op.PathParams != nil {
			t.Error("expected PathParams to be nil")
		}
		if op.ResponseSchemas != nil {
			t.Error("expected ResponseSchemas to be nil")
		}
	})
}

func TestParameter(t *testing.T) {
	t.Run("path parameter", func(t *testing.T) {
		param := Parameter{
			Name:     "id",
			In:       "path",
			Required: true,
			Type:     "string",
			Example:  "123",
		}

		if param.Name != "id" {
			t.Errorf("expected Name=id, got %s", param.Name)
		}
		if param.In != "path" {
			t.Errorf("expected In=path, got %s", param.In)
		}
		if !param.Required {
			t.Error("expected Required=true")
		}
		if param.Type != "string" {
			t.Errorf("expected Type=string, got %s", param.Type)
		}
		if param.Example != "123" {
			t.Errorf("expected Example=123, got %v", param.Example)
		}
	})

	t.Run("query parameter", func(t *testing.T) {
		param := Parameter{
			Name:     "filter",
			In:       "query",
			Required: false,
			Type:     "string",
		}

		if param.Name != "filter" {
			t.Errorf("expected Name=filter, got %s", param.Name)
		}
		if param.In != "query" {
			t.Errorf("expected In=query, got %s", param.In)
		}
		if param.Required {
			t.Error("expected Required=false")
		}
	})
}

func TestSchema(t *testing.T) {
	t.Run("with properties and required fields", func(t *testing.T) {
		schema := &Schema{
			Type: "object",
			Properties: map[string]*SchemaProperty{
				"name": {Type: "string", Format: "", Example: "John"},
				"age":  {Type: "integer", Format: "int32", Example: 30},
			},
			Required: []string{"name"},
		}

		if schema.Type != "object" {
			t.Errorf("expected Type=object, got %s", schema.Type)
		}
		if len(schema.Properties) != 2 {
			t.Errorf("expected 2 properties, got %d", len(schema.Properties))
		}
		if len(schema.Required) != 1 {
			t.Errorf("expected 1 required field, got %d", len(schema.Required))
		}

		nameProp := schema.Properties["name"]
		if nameProp == nil {
			t.Fatal("expected name property to exist")
		}
		if nameProp.Type != "string" {
			t.Errorf("expected name Type=string, got %s", nameProp.Type)
		}
	})
}

func TestAPISpec(t *testing.T) {
	t.Run("with operations and info", func(t *testing.T) {
		spec := &APISpec{
			BaseURL: "https://api.example.com",
			Operations: []*Operation{
				{Method: "GET", Path: "/users"},
				{Method: "POST", Path: "/users"},
			},
			Info: APIInfo{
				Title:       "Example API",
				Version:     "1.0.0",
				Description: "A test API",
			},
		}

		if spec.BaseURL != "https://api.example.com" {
			t.Errorf("expected BaseURL=https://api.example.com, got %s", spec.BaseURL)
		}
		if len(spec.Operations) != 2 {
			t.Errorf("expected 2 operations, got %d", len(spec.Operations))
		}
		if spec.Info.Title != "Example API" {
			t.Errorf("expected Title=Example API, got %s", spec.Info.Title)
		}
		if spec.Info.Version != "1.0.0" {
			t.Errorf("expected Version=1.0.0, got %s", spec.Info.Version)
		}
		if spec.Info.Description != "A test API" {
			t.Errorf("expected Description to match, got %s", spec.Info.Description)
		}
	})

	t.Run("empty spec is valid", func(t *testing.T) {
		spec := &APISpec{}
		if spec.BaseURL != "" {
			t.Errorf("expected empty BaseURL, got %s", spec.BaseURL)
		}
		if spec.Operations != nil {
			t.Error("expected Operations to be nil")
		}
	})
}

func TestAPIInfo(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		info := APIInfo{
			Title:       "My API",
			Version:     "2.0.0",
			Description: "API description",
		}

		if info.Title != "My API" {
			t.Errorf("expected Title=My API, got %s", info.Title)
		}
		if info.Version != "2.0.0" {
			t.Errorf("expected Version=2.0.0, got %s", info.Version)
		}
		if info.Description != "API description" {
			t.Errorf("expected Description to match, got %s", info.Description)
		}
	})
}
