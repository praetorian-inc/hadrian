package rest_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/plugins"
	_ "github.com/praetorian-inc/hadrian/pkg/plugins/rest" // Register plugin via init()
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRESTPluginRegistration(t *testing.T) {
	// Plugin should self-register via init()
	plugin, ok := plugins.Get(plugins.ProtocolREST)
	assert.True(t, ok, "REST plugin should be registered")
	assert.NotNil(t, plugin, "REST plugin should not be nil")
	assert.Equal(t, "REST/OpenAPI Parser", plugin.Name())
	assert.Equal(t, plugins.ProtocolREST, plugin.Type())
}

func TestCanParse_OpenAPIJSON(t *testing.T) {
	plugin, _ := plugins.Get(plugins.ProtocolREST)

	input := []byte(`{"openapi": "3.0.0", "info": {"title": "Test API"}}`)
	assert.True(t, plugin.CanParse(input, "api.json"), "Should detect OpenAPI JSON")
}

func TestCanParse_OpenAPIYAML(t *testing.T) {
	plugin, _ := plugins.Get(plugins.ProtocolREST)

	input := []byte(`openapi: 3.0.0
info:
  title: Test API`)
	assert.True(t, plugin.CanParse(input, "api.yaml"), "Should detect OpenAPI YAML")
}

func TestCanParse_SwaggerJSON(t *testing.T) {
	plugin, _ := plugins.Get(plugins.ProtocolREST)

	input := []byte(`{"swagger": "2.0", "info": {"title": "Test API"}}`)
	assert.True(t, plugin.CanParse(input, "api.json"), "Should detect Swagger JSON")
}

func TestCanParse_InvalidFormat(t *testing.T) {
	plugin, _ := plugins.Get(plugins.ProtocolREST)

	input := []byte(`{"random": "data"}`)
	assert.False(t, plugin.CanParse(input, "data.json"), "Should reject non-OpenAPI")

	input = []byte(`plain text`)
	assert.False(t, plugin.CanParse(input, "data.txt"), "Should reject plain text")
}

func TestParse_PetstoreSpec(t *testing.T) {
	plugin, _ := plugins.Get(plugins.ProtocolREST)

	// Read petstore spec
	input, err := os.ReadFile("testdata/petstore.yaml")
	require.NoError(t, err, "Should read petstore.yaml")

	// Parse spec
	spec, err := plugin.Parse(input)
	require.NoError(t, err, "Should parse petstore spec")
	require.NotNil(t, spec, "Spec should not be nil")

	// Verify basic info
	assert.Equal(t, "https://petstore.example.com/api/v1", spec.BaseURL)
	assert.Equal(t, "Petstore API", spec.Info.Title)
	assert.Equal(t, "1.0.0", spec.Info.Version)

	// Verify operations count (3 operations: GET /pets, POST /pets, GET /pets/{id})
	assert.Len(t, spec.Operations, 3, "Should have 3 operations")

	// Verify GET /pets
	var listPets *model.Operation
	for _, op := range spec.Operations {
		if op.Method == "GET" && op.Path == "/pets" {
			listPets = op
			break
		}
	}
	require.NotNil(t, listPets, "Should find GET /pets operation")
	assert.False(t, listPets.RequiresAuth, "GET /pets should not require auth")
	assert.Equal(t, "pets", listPets.ResourceType)
	assert.Equal(t, 200, listPets.SuccessStatus)
	assert.Equal(t, 403, listPets.UnauthorizedStatus)
	assert.Len(t, listPets.QueryParams, 1, "Should have 1 query param (limit)")
	assert.Equal(t, "limit", listPets.QueryParams[0].Name)

	// Verify POST /pets
	var createPet *model.Operation
	for _, op := range spec.Operations {
		if op.Method == "POST" && op.Path == "/pets" {
			createPet = op
			break
		}
	}
	require.NotNil(t, createPet, "Should find POST /pets operation")
	assert.True(t, createPet.RequiresAuth, "POST /pets should require auth")
	assert.Equal(t, "pets", createPet.ResourceType)
	assert.Equal(t, 201, createPet.SuccessStatus)
	assert.Equal(t, 401, createPet.UnauthorizedStatus)
	assert.NotNil(t, createPet.BodySchema, "Should have body schema")

	// Verify GET /pets/{id}
	var getPet *model.Operation
	for _, op := range spec.Operations {
		if op.Method == "GET" && op.Path == "/pets/{id}" {
			getPet = op
			break
		}
	}
	require.NotNil(t, getPet, "Should find GET /pets/{id} operation")
	assert.Equal(t, "pets", getPet.ResourceType)
	assert.Equal(t, "id", getPet.OwnerField, "Should extract id as owner field")
	assert.Len(t, getPet.PathParams, 1, "Should have 1 path param")
	assert.Equal(t, "id", getPet.PathParams[0].Name)
	assert.True(t, getPet.PathParams[0].Required)
}

func TestParse_InvalidSpec(t *testing.T) {
	plugin, _ := plugins.Get(plugins.ProtocolREST)

	input := []byte(`{"invalid": "spec"}`)
	_, err := plugin.Parse(input)
	assert.Error(t, err, "Should error on invalid spec")
}

func TestExtractResourceType(t *testing.T) {
	tests := []struct {
		path       string
		parameters string
		expected   string
	}{
		{"/api/users/{id}", `
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string`, "users"},
		{"/users", "", "users"},
		{"/pets/{petId}", `
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string`, "pets"},
		{"/api/v1/orders/{orderId}", `
      parameters:
        - name: orderId
          in: path
          required: true
          schema:
            type: string`, "v1"},
		{"/{id}", `
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			spec := []byte(fmt.Sprintf(`
openapi: 3.0.0
info:
  title: Test
  version: 1.0.0
paths:
  %s:
    get:%s
      responses:
        '200':
          description: OK
`, tt.path, tt.parameters))

			plugin, _ := plugins.Get(plugins.ProtocolREST)
			result, err := plugin.Parse(spec)
			require.NoError(t, err)
			require.Len(t, result.Operations, 1)
			assert.Equal(t, tt.expected, result.Operations[0].ResourceType)
		})
	}
}

func TestGuessOwnerField(t *testing.T) {
	tests := []struct {
		path       string
		parameters string
		expected   string
	}{
		{"/api/users/{id}", `
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string`, "id"},
		{"/pets/{petId}", `
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string`, "petId"},
		{"/orders/{order_id}", `
      parameters:
        - name: order_id
          in: path
          required: true
          schema:
            type: string`, "order_id"},
		{"/users", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			spec := []byte(fmt.Sprintf(`
openapi: 3.0.0
info:
  title: Test
  version: 1.0.0
paths:
  %s:
    get:%s
      responses:
        '200':
          description: OK
`, tt.path, tt.parameters))

			plugin, _ := plugins.Get(plugins.ProtocolREST)
			result, err := plugin.Parse(spec)
			require.NoError(t, err)
			require.Len(t, result.Operations, 1)
			assert.Equal(t, tt.expected, result.Operations[0].OwnerField)
		})
	}
}

func TestConvertOperation(t *testing.T) {
	// Test full operation conversion through Parse
	spec := []byte(`
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
        - name: filter
          in: query
          required: false
          schema:
            type: string
      responses:
        '200':
          description: Success
        '403':
          description: Forbidden
`)

	plugin, _ := plugins.Get(plugins.ProtocolREST)
	result, err := plugin.Parse(spec)
	require.NoError(t, err)
	require.Len(t, result.Operations, 1)

	op := result.Operations[0]
	assert.Equal(t, "GET", op.Method)
	assert.Equal(t, "/users/{id}", op.Path)
	assert.Len(t, op.PathParams, 1)
	assert.Equal(t, "id", op.PathParams[0].Name)
	assert.True(t, op.PathParams[0].Required)
	assert.Len(t, op.QueryParams, 1)
	assert.Equal(t, "filter", op.QueryParams[0].Name)
	assert.False(t, op.QueryParams[0].Required)
	assert.Equal(t, 200, op.SuccessStatus)
	assert.Equal(t, 403, op.UnauthorizedStatus)
}

func TestPathItemLevelParameters(t *testing.T) {
	// Test that path-item level parameters are correctly inherited by operations
	// This is the crAPI pattern where parameters are defined at path-item level
	spec := []byte(`
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /vehicle/{vehicleId}/location:
    get:
      operationId: get_location
      responses:
        '200':
          description: Success
    parameters:
      - name: vehicleId
        in: path
        required: true
        schema:
          type: string
          format: uuid
`)

	plugin, _ := plugins.Get(plugins.ProtocolREST)
	result, err := plugin.Parse(spec)
	require.NoError(t, err)
	require.Len(t, result.Operations, 1, "Should have 1 operation")

	op := result.Operations[0]
	assert.Equal(t, "GET", op.Method)
	assert.Equal(t, "/vehicle/{vehicleId}/location", op.Path)

	// This is the critical assertion: path-item level parameters should be inherited
	require.Len(t, op.PathParams, 1, "Should have 1 path param from path-item level")
	assert.Equal(t, "vehicleId", op.PathParams[0].Name)
	assert.True(t, op.PathParams[0].Required)
}

func TestPathItemAndOperationParametersMerge(t *testing.T) {
	// Test that path-item level and operation-level parameters are merged correctly
	// Operation-level parameters should override path-item level parameters with same name
	spec := []byte(`
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users/{userId}/posts/{postId}:
    get:
      parameters:
        - name: postId
          in: path
          required: true
          schema:
            type: integer
        - name: includeComments
          in: query
          required: false
          schema:
            type: boolean
      responses:
        '200':
          description: Success
    parameters:
      - name: userId
        in: path
        required: true
        schema:
          type: string
      - name: postId
        in: path
        required: true
        schema:
          type: string
`)

	plugin, _ := plugins.Get(plugins.ProtocolREST)
	result, err := plugin.Parse(spec)
	require.NoError(t, err)
	require.Len(t, result.Operations, 1, "Should have 1 operation")

	op := result.Operations[0]

	// Should have 2 path params: userId from path-item level, postId from operation level (overrides path-item)
	require.Len(t, op.PathParams, 2, "Should have 2 path params (userId from path-item, postId from operation)")

	// Find userId param (from path-item level)
	var userIdParam *model.Parameter
	var postIdParam *model.Parameter
	for i := range op.PathParams {
		if op.PathParams[i].Name == "userId" {
			userIdParam = &op.PathParams[i]
		}
		if op.PathParams[i].Name == "postId" {
			postIdParam = &op.PathParams[i]
		}
	}

	require.NotNil(t, userIdParam, "Should have userId param from path-item level")
	assert.True(t, userIdParam.Required)

	// postId should come from operation level (which overrides path-item level)
	require.NotNil(t, postIdParam, "Should have postId param")
	assert.True(t, postIdParam.Required, "postId should be required (from operation level, which overrides path-item)")
	// Verify the type came from operation level (integer) not path-item level (string)
	assert.Contains(t, postIdParam.Type, "integer", "postId type should be integer from operation level override")

	// Should have 1 query param from operation level
	require.Len(t, op.QueryParams, 1, "Should have 1 query param from operation level")
	assert.Equal(t, "includeComments", op.QueryParams[0].Name)
}

func TestMultipleOperationsInheritPathItemParams(t *testing.T) {
	// Test that multiple operations on the same path all inherit path-item parameters
	spec := []byte(`
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /orders/{orderId}:
    get:
      responses:
        '200':
          description: Get order
    put:
      responses:
        '200':
          description: Update order
    delete:
      responses:
        '200':
          description: Delete order
    parameters:
      - name: orderId
        in: path
        required: true
        schema:
          type: string
`)

	plugin, _ := plugins.Get(plugins.ProtocolREST)
	result, err := plugin.Parse(spec)
	require.NoError(t, err)
	require.Len(t, result.Operations, 3, "Should have 3 operations")

	// All operations should inherit the orderId path param
	for _, op := range result.Operations {
		require.Len(t, op.PathParams, 1, "Operation %s should have 1 path param", op.Method)
		assert.Equal(t, "orderId", op.PathParams[0].Name, "Operation %s should have orderId param", op.Method)
		assert.True(t, op.PathParams[0].Required, "orderId should be required for operation %s", op.Method)
	}
}
