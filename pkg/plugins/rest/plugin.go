package rest

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/plugins"
)

type RESTPlugin struct{}

func init() {
	// Self-register via init()
	plugins.Register(plugins.ProtocolREST, &RESTPlugin{})
}

func (p *RESTPlugin) Name() string {
	return "REST/OpenAPI Parser"
}

func (p *RESTPlugin) Type() plugins.Protocol {
	return plugins.ProtocolREST
}

func (p *RESTPlugin) CanParse(input []byte, filename string) bool {
	// Check file extension
	ext := filepath.Ext(filename)
	if ext != ".json" && ext != ".yaml" && ext != ".yml" {
		return false
	}

	// Check for OpenAPI/Swagger markers
	str := string(input)
	return strings.Contains(str, "openapi") ||
		strings.Contains(str, "swagger") ||
		strings.Contains(str, "\"paths\"")
}

func (p *RESTPlugin) Parse(input []byte) (*model.APISpec, error) {
	// Load OpenAPI spec
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI: %w", err)
	}

	// Validate spec
	if err := doc.Validate(loader.Context); err != nil {
		return nil, fmt.Errorf("invalid OpenAPI spec: %w", err)
	}

	// Convert to internal model
	spec := &model.APISpec{
		BaseURL: extractBaseURL(doc),
		Info: model.APIInfo{
			Title:       doc.Info.Title,
			Version:     doc.Info.Version,
			Description: doc.Info.Description,
		},
		Operations: make([]*model.Operation, 0),
	}

	// Convert paths to operations
	for path, pathItem := range doc.Paths.Map() {
		for method, operation := range pathItem.Operations() {
			op := convertOperation(path, method, operation, pathItem.Parameters, spec.BaseURL)
			spec.Operations = append(spec.Operations, op)
		}
	}

	// Sort operations by path (primary) and method (secondary) for deterministic ordering.
	// Path is primary sort - ensures operations for /api/documents come before /api/orders.
	// Method is secondary sort using safe ordering: read operations before writes,
	// destructive operations last. This prevents DELETE from destroying resources
	// before GET/PUT templates can test them.
	sort.Slice(spec.Operations, func(i, j int) bool {
		if spec.Operations[i].Path != spec.Operations[j].Path {
			return spec.Operations[i].Path < spec.Operations[j].Path
		}
		return methodOrder(spec.Operations[i].Method) < methodOrder(spec.Operations[j].Method)
	})

	return spec, nil
}

// methodOrder returns a sort key that orders HTTP methods safely:
// reads first, then writes, then destructive operations last.
func methodOrder(method string) int {
	switch strings.ToUpper(method) {
	case "GET":
		return 0
	case "HEAD":
		return 1
	case "OPTIONS":
		return 2
	case "POST":
		return 3
	case "PUT":
		return 4
	case "PATCH":
		return 5
	case "DELETE":
		return 6
	default:
		return 7
	}
}

func extractBaseURL(doc *openapi3.T) string {
	if len(doc.Servers) > 0 {
		return doc.Servers[0].URL
	}
	return ""
}

func convertOperation(path, method string, operation *openapi3.Operation, pathItemParams openapi3.Parameters, baseURL string) *model.Operation {
	// Merge path-item level parameters with operation-level parameters
	// Operation-level parameters override path-item level parameters with the same name
	mergedParams := mergeParameters(pathItemParams, operation.Parameters)

	op := &model.Operation{
		Method:             strings.ToUpper(method),
		Path:               path,
		PathParams:         extractParameters(mergedParams, "path"),
		QueryParams:        extractParameters(mergedParams, "query"),
		HeaderParams:       extractParameters(mergedParams, "header"),
		RequiresAuth:       hasSecurityRequirement(operation.Security),
		ResourceType:       extractResourceType(path),
		OwnerField:         guessOwnerField(path),
		SuccessStatus:      extractSuccessStatus(operation.Responses),
		UnauthorizedStatus: extractUnauthorizedStatus(operation.Responses),
		Tags:               operation.Tags,
		ResponseSchemas:    make(map[int]*model.Schema),
	}

	// Extract request body schema
	if operation.RequestBody != nil && operation.RequestBody.Value != nil {
		for _, content := range operation.RequestBody.Value.Content {
			if content.Schema != nil && content.Schema.Value != nil {
				op.BodySchema = convertSchema(content.Schema.Value)
				break
			}
		}
	}

	// Extract response schemas
	if operation.Responses != nil {
		for statusStr, response := range operation.Responses.Map() {
			if response.Value != nil {
				for _, content := range response.Value.Content {
					if content.Schema != nil && content.Schema.Value != nil {
						status := parseStatus(statusStr)
						op.ResponseSchemas[status] = convertSchema(content.Schema.Value)
						break
					}
				}
			}
		}
	}

	return op
}

// mergeParameters merges path-item level parameters with operation-level parameters.
// Operation-level parameters override path-item level parameters with the same name and location.
func mergeParameters(pathItemParams, operationParams openapi3.Parameters) openapi3.Parameters {
	if len(pathItemParams) == 0 {
		return operationParams
	}
	if len(operationParams) == 0 {
		return pathItemParams
	}

	// Build a map of operation-level params by name+in for quick lookup
	operationParamSet := make(map[string]bool)
	for _, param := range operationParams {
		if param.Value != nil {
			key := param.Value.Name + ":" + param.Value.In
			operationParamSet[key] = true
		}
	}

	// Start with operation params, then add path-item params that aren't overridden
	merged := make(openapi3.Parameters, 0, len(operationParams)+len(pathItemParams))
	merged = append(merged, operationParams...)

	for _, param := range pathItemParams {
		if param.Value != nil {
			key := param.Value.Name + ":" + param.Value.In
			if !operationParamSet[key] {
				// Path-item param not overridden, add it
				merged = append(merged, param)
			}
		}
	}

	return merged
}

func extractParameters(params openapi3.Parameters, in string) []model.Parameter {
	var result []model.Parameter
	for _, param := range params {
		if param.Value != nil && param.Value.In == in {
			p := model.Parameter{
				Name:     param.Value.Name,
				In:       param.Value.In,
				Required: param.Value.Required,
			}

			// Extract type from schema
			if param.Value.Schema != nil && param.Value.Schema.Value != nil {
				p.Type = schemaType(param.Value.Schema.Value.Type)
				if param.Value.Schema.Value.Example != nil {
					p.Example = param.Value.Schema.Value.Example
				}
			}

			result = append(result, p)
		}
	}
	return result
}

func hasSecurityRequirement(security *openapi3.SecurityRequirements) bool {
	if security == nil {
		return false
	}
	for _, req := range *security {
		if len(req) > 0 {
			return true
		}
	}
	return false
}

func extractResourceType(path string) string {
	// Extract from /api/users/{id} → "users"
	// Extract from /users → "users"
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for _, part := range parts {
		// Skip path parameters like {id}
		if !strings.HasPrefix(part, "{") && part != "" && part != "api" {
			return part
		}
	}
	return ""
}

func guessOwnerField(path string) string {
	// Extract from /api/users/{id} → "id"
	// Extract from /users/{userId} → "userId"
	// Extract from /pets/{pet_id} → "pet_id"
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			// Remove braces
			field := strings.Trim(part, "{}")
			return field
		}
	}
	return ""
}

func extractSuccessStatus(responses *openapi3.Responses) int {
	if responses == nil {
		return 0
	}

	// Find first 2xx status
	for statusStr := range responses.Map() {
		status := parseStatus(statusStr)
		if status >= 200 && status < 300 {
			return status
		}
	}

	return 0
}

func extractUnauthorizedStatus(responses *openapi3.Responses) int {
	if responses == nil {
		return 0
	}

	// Check for 401 or 403
	for statusStr := range responses.Map() {
		status := parseStatus(statusStr)
		if status == 401 || status == 403 {
			return status
		}
	}

	return 0
}

func convertSchema(schema *openapi3.Schema) *model.Schema {
	if schema == nil {
		return nil
	}

	result := &model.Schema{
		Type:       schemaType(schema.Type),
		Properties: make(map[string]*model.SchemaProperty),
		Required:   schema.Required,
	}

	// Convert properties
	for name, propRef := range schema.Properties {
		if propRef != nil && propRef.Value != nil {
			prop := &model.SchemaProperty{
				Type:   schemaType(propRef.Value.Type),
				Format: propRef.Value.Format,
			}
			if propRef.Value.Example != nil {
				prop.Example = propRef.Value.Example
			}
			result.Properties[name] = prop
		}
	}

	return result
}

func schemaType(t *openapi3.Types) string {
	if t != nil && len(*t) > 0 {
		return (*t)[0]
	}
	return ""
}

func parseStatus(statusStr string) int {
	// Handle "200", "2XX", "default"
	if statusStr == "default" {
		return 0
	}
	if strings.Contains(statusStr, "X") {
		// Extract first digit for wildcard patterns like "2XX"
		if len(statusStr) > 0 && statusStr[0] >= '0' && statusStr[0] <= '9' {
			return int(statusStr[0]-'0') * 100
		}
		return 0
	}
	status, err := strconv.Atoi(statusStr)
	if err != nil {
		log.Warn("Unexpected status code parse failure for %q: %v", statusStr, err)
	}
	return status
}
