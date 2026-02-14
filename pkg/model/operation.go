package model

// Protocol-agnostic API operation (extracted from OpenAPI/Swagger)
type Operation struct {
	Method             string      // GET, POST, PUT, DELETE
	Path               string      // /api/users/{id}
	PathParams         []Parameter // {id}, {userId}, etc.
	QueryParams        []Parameter
	HeaderParams       []Parameter
	BodySchema         *Schema
	ResponseSchemas    map[int]*Schema // 200 → success, 403 → forbidden
	RequiresAuth       bool
	ResourceType       string // "users" (extracted from path)
	OwnerField         string // "id", "user_id" (for ownership checks)
	SuccessStatus      int    // 200, 201, 204
	UnauthorizedStatus int    // 403, 401
	Tags               []string
}

type Parameter struct {
	Name     string
	In       string // path, query, header
	Required bool
	Type     string
	Example  interface{}
}

type Schema struct {
	Type       string
	Properties map[string]*SchemaProperty
	Required   []string
}

type SchemaProperty struct {
	Type    string
	Format  string
	Example interface{}
}

// APISpec represents a complete API specification
type APISpec struct {
	BaseURL    string
	Operations []*Operation
	Info       APIInfo
}

type APIInfo struct {
	Title       string
	Version     string
	Description string
}
