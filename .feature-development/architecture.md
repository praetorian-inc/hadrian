# GraphQL API Security Testing Module - Architecture Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Add comprehensive GraphQL API security testing to Hadrian by implementing a GraphQL plugin that integrates with the existing template-driven testing framework.

**Architecture:** Plugin-based extension that implements the existing `Plugin` interface, reuses the core runner/template/matcher infrastructure, and adds GraphQL-specific schema parsing, query construction, and attack patterns.

**Tech Stack:** Go 1.24, Cobra CLI, gopkg.in/yaml.v3, golang.org/x/time/rate, github.com/vektah/gqlparser/v2, stretchr/testify

---

## Part 1: Technical Architecture

### 1.1 Package Structure and Responsibilities

```
pkg/
├── plugins/
│   ├── plugin.go                    # Existing - Plugin interface (no changes)
│   ├── rest/                        # Existing - REST/OpenAPI plugin
│   │   └── plugin.go
│   └── graphql/                     # NEW - GraphQL plugin
│       ├── plugin.go                # Plugin registration, CanParse, Parse
│       ├── introspection.go         # Fetch schema via introspection query
│       ├── sdl_parser.go            # Parse SDL (.graphql) files
│       ├── operation_converter.go   # Schema types -> model.Operation[]
│       └── plugin_test.go           # Plugin unit tests
│
├── graphql/                         # NEW - GraphQL core package
│   ├── schema.go                    # Schema type definitions (Type, Field, etc.)
│   ├── query_builder.go             # Dynamic query construction
│   ├── executor.go                  # GraphQL query execution (HTTP POST)
│   ├── depth_analyzer.go            # Query depth/complexity analysis
│   └── schema_test.go               # Schema tests
│
├── model/
│   └── operation.go                 # Existing - Add Protocol field
│
├── templates/
│   └── template.go                  # Existing - Add GraphQLTest struct
│
└── runner/
    └── run.go                       # Existing - CLI in runner pattern

cmd/hadrian/
├── main.go                          # Existing - Thin main calling runner.Run()
└── (no changes - all CLI in pkg/runner)

templates/
├── owasp/                           # Existing - REST templates
└── graphql/                         # NEW - GraphQL templates
    ├── introspection-disclosure.yaml
    ├── depth-attack.yaml
    ├── complexity-attack.yaml
    ├── batching-attack.yaml
    ├── field-suggestion.yaml
    ├── bola-user-access.yaml
    └── bfla-mutation.yaml

testdata/
├── crapi/                           # Existing - REST test data
└── dvga/                            # NEW - GraphQL test data
    ├── docker-compose.yaml
    ├── dvga-schema.graphql
    ├── dvga-roles.yaml
    ├── dvga-auth.yaml
    └── README.md
```

### 1.2 Interface Definitions

#### 1.2.1 Plugin Interface (Existing - No Changes)

**Source:** `pkg/plugins/plugin.go` (lines 20-25)
```go
// Plugin parses protocol-specific API definitions to internal model
type Plugin interface {
    Name() string
    Type() Protocol
    CanParse(input []byte, filename string) bool
    Parse(input []byte) (*model.APISpec, error)
}
```

**GraphQL Implementation:**
```go
// pkg/plugins/graphql/plugin.go
type GraphQLPlugin struct {
    introspectionClient *IntrospectionClient
}

func (p *GraphQLPlugin) Name() string { return "GraphQL Schema Parser" }
func (p *GraphQLPlugin) Type() Protocol { return plugins.ProtocolGraphQL }
func (p *GraphQLPlugin) CanParse(input []byte, filename string) bool { ... }
func (p *GraphQLPlugin) Parse(input []byte) (*model.APISpec, error) { ... }
```

#### 1.2.2 Schema Types (New)

```go
// pkg/graphql/schema.go

// Schema represents a parsed GraphQL schema
type Schema struct {
    Types      map[string]*TypeDef
    Queries    []*FieldDef
    Mutations  []*FieldDef
    QueryType  string // Usually "Query"
    MutationType string // Usually "Mutation"
}

// TypeDef represents a GraphQL type (Object, Input, Enum, etc.)
type TypeDef struct {
    Name        string
    Kind        TypeKind // OBJECT, INPUT_OBJECT, ENUM, SCALAR, etc.
    Fields      []*FieldDef
    EnumValues  []string
    Interfaces  []string
    Description string
}

// TypeKind matches GraphQL introspection __TypeKind
type TypeKind string
const (
    TypeKindScalar      TypeKind = "SCALAR"
    TypeKindObject      TypeKind = "OBJECT"
    TypeKindInterface   TypeKind = "INTERFACE"
    TypeKindUnion       TypeKind = "UNION"
    TypeKindEnum        TypeKind = "ENUM"
    TypeKindInputObject TypeKind = "INPUT_OBJECT"
    TypeKindList        TypeKind = "LIST"
    TypeKindNonNull     TypeKind = "NON_NULL"
)

// FieldDef represents a field on a GraphQL type
type FieldDef struct {
    Name        string
    Type        *TypeRef
    Args        []*ArgumentDef
    Description string
    IsDeprecated bool
}

// TypeRef is a reference to a type (handles List, NonNull wrappers)
type TypeRef struct {
    Name   string   // Scalar/Object name (nil for List/NonNull)
    Kind   TypeKind
    OfType *TypeRef // For List/NonNull wrapping
}

// ArgumentDef represents a field argument
type ArgumentDef struct {
    Name         string
    Type         *TypeRef
    DefaultValue string
    Description  string
}
```

#### 1.2.3 Introspection Client (New)

```go
// pkg/graphql/introspection.go

// IntrospectionClient fetches schema via GraphQL introspection
type IntrospectionClient struct {
    httpClient HTTPClient
    endpoint   string
    authInfo   *templates.AuthInfo
}

// IntrospectionResult matches the __schema response structure
type IntrospectionResult struct {
    Data struct {
        Schema IntrospectionSchema `json:"__schema"`
    } `json:"data"`
    Errors []GraphQLError `json:"errors,omitempty"`
}

type IntrospectionSchema struct {
    QueryType        *TypeNameRef         `json:"queryType"`
    MutationType     *TypeNameRef         `json:"mutationType"`
    SubscriptionType *TypeNameRef         `json:"subscriptionType"`
    Types            []IntrospectionType  `json:"types"`
    Directives       []interface{}        `json:"directives"`
}

// FetchSchema performs introspection query and returns parsed Schema
func (c *IntrospectionClient) FetchSchema(ctx context.Context) (*Schema, error)
```

#### 1.2.4 Query Builder (New)

```go
// pkg/graphql/query_builder.go

// QueryBuilder constructs GraphQL queries dynamically
type QueryBuilder struct {
    schema *Schema
}

// BuildQuery creates a query string for an operation
func (b *QueryBuilder) BuildQuery(operationName string, maxDepth int) (string, error)

// BuildQueryWithVariables creates a query with variable substitution
func (b *QueryBuilder) BuildQueryWithVariables(
    operationName string,
    variables map[string]interface{},
    maxDepth int,
) (string, map[string]interface{}, error)

// BuildDepthAttackQuery creates a deeply nested query for DoS testing
func (b *QueryBuilder) BuildDepthAttackQuery(depth int, fieldPath []string) string

// BuildBatchQuery creates a query with aliased copies for batching attack
func (b *QueryBuilder) BuildBatchQuery(query string, count int) string
```

#### 1.2.5 Template Extensions (Modify Existing)

**Source:** `pkg/templates/template.go` (lines 8-26)
```go
// Template represents a parsed YAML test template
type Template struct {
    ID   string       `yaml:"id"`
    Info TemplateInfo `yaml:"info"`
    EndpointSelector EndpointSelector `yaml:"endpoint_selector"`
    RoleSelector RoleSelector `yaml:"role_selector"`
    TestPhases *TestPhases `yaml:"test_phases,omitempty"`
    HTTP []HTTPTest `yaml:"http,omitempty"`          // REST tests
    GraphQL []GraphQLTest `yaml:"graphql,omitempty"` // NEW: GraphQL tests
    Detection Detection `yaml:"detection"`
}
```

**New GraphQL Test Structure:**
```go
// GraphQLTest defines a GraphQL query/mutation test
type GraphQLTest struct {
    Query         string            `yaml:"query"`
    Variables     map[string]string `yaml:"variables,omitempty"`
    OperationName string            `yaml:"operation_name,omitempty"`

    // Matchers (same as HTTP)
    Matchers []Matcher `yaml:"matchers"`

    // For rate limit testing
    Repeat    int        `yaml:"repeat,omitempty"`
    RateLimit *RateLimit `yaml:"rate_limit,omitempty"`
    Backoff   *Backoff   `yaml:"backoff,omitempty"`
}
```

#### 1.2.6 Model Extensions (Modify Existing)

**Source:** `pkg/model/operation.go` (lines 4-18)
```go
// Protocol-agnostic API operation
type Operation struct {
    Method             string            // GET, POST, PUT, DELETE
    Path               string            // /api/users/{id}
    // ... existing fields ...
    Protocol           string            // NEW: "rest" or "graphql"
    GraphQLOperation   string            // NEW: "query" or "mutation"
    GraphQLType        string            // NEW: Type name (e.g., "User")
    GraphQLField       string            // NEW: Field name (e.g., "user")
}
```

### 1.3 Data Flow from CLI to Report

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. CLI Layer (pkg/runner/run.go)                                       │
│    hadrian test graphql --target URL --schema schema.graphql --roles...│
│    │                                                                   │
│    ▼                                                                   │
│    Config{Protocol: "graphql", Target: URL, Schema: "schema.graphql"}  │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. Plugin Selection (pkg/plugins/plugin.go)                            │
│    plugins.Get(ProtocolGraphQL) → *GraphQLPlugin                       │
│    OR plugins.AutoDetect(input, filename) based on content             │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. Schema Acquisition (pkg/plugins/graphql/)                           │
│    ┌─────────────────────────┐   ┌─────────────────────────────────┐   │
│    │ --schema flag provided? │   │ No schema flag?                 │   │
│    │        ▼                │   │        ▼                        │   │
│    │ sdl_parser.ParseSDL()   │   │ introspection.FetchSchema()     │   │
│    │ (parse .graphql file)   │   │ (query __schema from endpoint)  │   │
│    └─────────────┬───────────┘   └───────────────┬─────────────────┘   │
│                  │                               │                     │
│                  └───────────┬───────────────────┘                     │
│                              ▼                                         │
│                      *graphql.Schema                                   │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 4. Operation Conversion (pkg/plugins/graphql/operation_converter.go)   │
│    Schema.Queries → []*model.Operation (Protocol: "graphql")           │
│    Schema.Mutations → []*model.Operation (Protocol: "graphql")         │
│    │                                                                   │
│    ▼                                                                   │
│    model.APISpec{Operations: [...], BaseURL: target}                   │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 5. Template Loading (pkg/runner/run.go)                                │
│    loadTemplateFiles("templates/graphql/", categories)                 │
│    │                                                                   │
│    ▼                                                                   │
│    []*templates.CompiledTemplate (with GraphQL tests)                  │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 6. Test Execution Loop (pkg/runner/execution.go)                       │
│    for operation in spec.Operations:                                   │
│        for template in templates:                                      │
│            for role in roles:                                          │
│                │                                                       │
│                ▼ (check template type)                                 │
│    ┌───────────────────────┐  ┌────────────────────────────────────┐   │
│    │ template.HTTP != nil  │  │ template.GraphQL != nil            │   │
│    │        ▼              │  │        ▼                           │   │
│    │ existing HTTP exec    │  │ NEW: GraphQL executor              │   │
│    │ templates.Executor    │  │ graphql.Executor.Execute()         │   │
│    └───────────────────────┘  └────────────────────────────────────┘   │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 7. GraphQL Query Execution (pkg/graphql/executor.go)                   │
│    executor.Execute(ctx, graphqlTest, operation, authInfo, variables)  │
│    │                                                                   │
│    ▼                                                                   │
│    HTTP POST to /graphql with:                                         │
│    {                                                                   │
│      "query": "query GetUser($id: ID!) { user(id: $id) { ... } }",    │
│      "variables": {"id": "victim_id"},                                 │
│      "operationName": "GetUser"                                        │
│    }                                                                   │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 8. Response Matching (existing pkg/templates/execute.go)               │
│    evaluateMatchers(compiledMatchers, resp, body)                      │
│    │                                                                   │
│    ▼                                                                   │
│    matched: bool                                                       │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 9. Finding Creation (existing pattern)                                 │
│    if matched → model.Finding{                                         │
│        Category: "API1:2023",                                          │
│        Name: "GraphQL BOLA - Cross-User Access",                       │
│        Endpoint: "query user",                                         │
│        Evidence: {Request, Response},                                  │
│    }                                                                   │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 10. Report Generation (existing pkg/reporter/)                         │
│     reporter.GenerateReport(findings, stats)                           │
│     │                                                                  │
│     ▼                                                                  │
│     Terminal / JSON / Markdown output                                  │
└────────────────────────────────────────────────────────────────────────┘
```

### 1.4 Integration with Existing Runner

**Key Integration Points:**

1. **CLI Refactoring** (pkg/runner/run.go):
   - Change from single `test` command to `test rest` and `test graphql` subcommands
   - Add GraphQL-specific flags: `--target`, `--schema`, `--endpoint`, `--depth-limit`

2. **Protocol Detection** (pkg/runner/helpers.go):
   - Add `parseGraphQLSpec()` function parallel to `parseAPISpec()`
   - Support both introspection and SDL file input

3. **Template Routing** (pkg/runner/execution.go):
   - Detect `template.GraphQL != nil` vs `template.HTTP != nil`
   - Route to appropriate executor

4. **Executor Interface** (new abstraction needed):
```go
// ProtocolExecutor executes protocol-specific tests
type ProtocolExecutor interface {
    Execute(ctx context.Context, tmpl *templates.CompiledTemplate,
            op *model.Operation, authInfo *templates.AuthInfo,
            variables map[string]string) (*templates.ExecutionResult, error)
}
```

### 1.5 Pattern Choices with Rationale

| Pattern | Choice | Rationale |
|---------|--------|-----------|
| **Plugin Registration** | Self-register via `init()` | Matches existing REST plugin pattern |
| **Schema Parsing** | gqlparser/v2 library | Battle-tested, used by 99designs/gqlgen |
| **Introspection** | Standard introspection query | Works with all GraphQL servers |
| **Operation Mapping** | One Operation per Query/Mutation field | Aligns with REST plugin mapping |
| **Template Format** | YAML with `graphql:` block | Consistent with existing template system |
| **Query Execution** | HTTP POST to /graphql | GraphQL spec standard |
| **Variable Binding** | Safe JSON encoding | Prevents GraphQL injection |
| **CLI Structure** | Subcommands (`test rest`, `test graphql`) | Explicit, extensible, no auto-detect |
| **Permission Format** | `<action>:<Type.field>:<scope>` | Extends existing format for field-level |

---

## Part 2: Task Decomposition

### 2.1 Task Overview

| Task | Description | Files | Batch | Depends On |
|------|-------------|-------|-------|------------|
| T001 | Core GraphQL schema types | 2 | 1 | - |
| T002 | Plugin registration and CanParse | 2 | 1 | - |
| T003 | SDL parser using gqlparser | 2 | 2 | T001 |
| T004 | Introspection client | 2 | 2 | T001 |
| T005 | Schema to Operation converter | 2 | 3 | T003, T004 |
| T006 | Plugin Parse() implementation | 1 | 3 | T003, T004, T005 |
| T007 | Query builder | 2 | 4 | T001 |
| T008 | GraphQL executor | 2 | 4 | T007 |
| T009 | Depth/complexity analyzer | 2 | 5 | T001 |
| T010 | Attack pattern generators | 2 | 5 | T007, T009 |
| T011 | Template GraphQL extension | 2 | 6 | - |
| T012 | Model Operation extensions | 1 | 6 | - |
| T013 | CLI refactoring to subcommands | 2 | 6 | T006, T011 |
| T014 | GraphQL template: introspection | 1 | 6 | T011 |
| T015 | GraphQL template: depth attack | 1 | 6 | T011 |
| T016 | GraphQL template: batching | 1 | 6 | T011 |
| T017 | GraphQL template: BOLA | 1 | 6 | T011 |
| T018 | GraphQL template: BFLA | 1 | 6 | T011 |
| T019 | DVGA test setup | 4 | 7 | - |
| T020 | Integration tests | 2 | 7 | All |

### 2.2 Detailed Task Specifications

---

### Task T001: Core GraphQL Schema Types

**Batch:** 1 - Core Plugin Infrastructure
**Depends On:** None
**Estimated Time:** 15 minutes

**Files:**
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/graphql/schema.go`
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/graphql/schema_test.go`

**Description:**
Define the core GraphQL schema type structures that will be used throughout the plugin. These types represent GraphQL schema elements (types, fields, arguments) in Go.

**Implementation:**

```go
// pkg/graphql/schema.go
package graphql

// Schema represents a parsed GraphQL schema
type Schema struct {
    Types        map[string]*TypeDef
    Queries      []*FieldDef
    Mutations    []*FieldDef
    QueryType    string
    MutationType string
}

// TypeKind matches GraphQL __TypeKind enum
type TypeKind string

const (
    TypeKindScalar      TypeKind = "SCALAR"
    TypeKindObject      TypeKind = "OBJECT"
    TypeKindInterface   TypeKind = "INTERFACE"
    TypeKindUnion       TypeKind = "UNION"
    TypeKindEnum        TypeKind = "ENUM"
    TypeKindInputObject TypeKind = "INPUT_OBJECT"
    TypeKindList        TypeKind = "LIST"
    TypeKindNonNull     TypeKind = "NON_NULL"
)

// TypeDef represents a GraphQL type definition
type TypeDef struct {
    Name        string
    Kind        TypeKind
    Fields      []*FieldDef
    EnumValues  []string
    Interfaces  []string
    Description string
}

// FieldDef represents a field on a GraphQL type
type FieldDef struct {
    Name         string
    Type         *TypeRef
    Args         []*ArgumentDef
    Description  string
    IsDeprecated bool
}

// TypeRef references a type with support for List/NonNull wrappers
type TypeRef struct {
    Name   string   // nil for List/NonNull
    Kind   TypeKind
    OfType *TypeRef // For List/NonNull wrapping
}

// ArgumentDef represents a field argument
type ArgumentDef struct {
    Name         string
    Type         *TypeRef
    DefaultValue string
    Description  string
}

// IsScalar returns true if this is a scalar type reference
func (t *TypeRef) IsScalar() bool {
    return t.Kind == TypeKindScalar ||
        (t.Name != "" && isBuiltinScalar(t.Name))
}

// IsNonNull returns true if this type is non-nullable
func (t *TypeRef) IsNonNull() bool {
    return t.Kind == TypeKindNonNull
}

// IsList returns true if this type is a list
func (t *TypeRef) IsList() bool {
    return t.Kind == TypeKindList
}

// UnwrapType returns the innermost type (unwrapping List/NonNull)
func (t *TypeRef) UnwrapType() *TypeRef {
    if t.OfType != nil {
        return t.OfType.UnwrapType()
    }
    return t
}

// GetTypeName returns the name of the base type
func (t *TypeRef) GetTypeName() string {
    if t.Name != "" {
        return t.Name
    }
    if t.OfType != nil {
        return t.OfType.GetTypeName()
    }
    return ""
}

func isBuiltinScalar(name string) bool {
    switch name {
    case "ID", "String", "Int", "Float", "Boolean":
        return true
    }
    return false
}

// GetQueryFields returns all top-level query fields
func (s *Schema) GetQueryFields() []*FieldDef {
    return s.Queries
}

// GetMutationFields returns all top-level mutation fields
func (s *Schema) GetMutationFields() []*FieldDef {
    return s.Mutations
}

// GetType returns a type by name
func (s *Schema) GetType(name string) (*TypeDef, bool) {
    t, ok := s.Types[name]
    return t, ok
}
```

**Test Cases:**
```go
// pkg/graphql/schema_test.go
func TestTypeRef_UnwrapType(t *testing.T) {
    // Test [User!]! -> User
    typeRef := &TypeRef{
        Kind: TypeKindNonNull,
        OfType: &TypeRef{
            Kind: TypeKindList,
            OfType: &TypeRef{
                Kind: TypeKindNonNull,
                OfType: &TypeRef{
                    Name: "User",
                    Kind: TypeKindObject,
                },
            },
        },
    }

    unwrapped := typeRef.UnwrapType()
    assert.Equal(t, "User", unwrapped.Name)
    assert.Equal(t, TypeKindObject, unwrapped.Kind)
}

func TestTypeRef_GetTypeName(t *testing.T) {
    // Test nested type name extraction
    typeRef := &TypeRef{
        Kind: TypeKindList,
        OfType: &TypeRef{Name: "String", Kind: TypeKindScalar},
    }
    assert.Equal(t, "String", typeRef.GetTypeName())
}

func TestSchema_GetType(t *testing.T) {
    schema := &Schema{
        Types: map[string]*TypeDef{
            "User": {Name: "User", Kind: TypeKindObject},
        },
    }

    userType, ok := schema.GetType("User")
    assert.True(t, ok)
    assert.Equal(t, "User", userType.Name)

    _, ok = schema.GetType("NotExists")
    assert.False(t, ok)
}
```

**Exit Criteria:**
- [ ] `pkg/graphql/schema.go` created with all type definitions
- [ ] `pkg/graphql/schema_test.go` passes with 3 test functions
- [ ] `go test ./pkg/graphql/...` passes with 0 failures
- [ ] `go build ./...` succeeds with exit code 0

---

### Task T002: Plugin Registration and CanParse

**Batch:** 1 - Core Plugin Infrastructure
**Depends On:** None
**Estimated Time:** 15 minutes

**Files:**
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/plugins/graphql/plugin.go`
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/plugins/graphql/plugin_test.go`

**Description:**
Create the GraphQL plugin skeleton with self-registration via `init()` and implement `CanParse()` to detect GraphQL schemas (SDL files and introspection JSON).

**Implementation:**

```go
// pkg/plugins/graphql/plugin.go
package graphql

import (
    "path/filepath"
    "strings"

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
// Placeholder - will be implemented in T006
func (p *GraphQLPlugin) Parse(input []byte) (*model.APISpec, error) {
    // TODO: Implement in T006
    return nil, nil
}
```

**Test Cases:**
```go
// pkg/plugins/graphql/plugin_test.go
package graphql

import (
    "testing"

    "github.com/praetorian-inc/hadrian/pkg/plugins"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestGraphQLPlugin_Registration(t *testing.T) {
    // Plugin should be auto-registered via init()
    plugin, ok := plugins.Get(plugins.ProtocolGraphQL)
    require.True(t, ok, "GraphQL plugin should be registered")
    assert.Equal(t, "GraphQL Schema Parser", plugin.Name())
    assert.Equal(t, plugins.ProtocolGraphQL, plugin.Type())
}

func TestGraphQLPlugin_CanParse_SDL(t *testing.T) {
    plugin := &GraphQLPlugin{}

    tests := []struct {
        name     string
        input    string
        filename string
        want     bool
    }{
        {
            name:     "SDL by extension",
            input:    "anything",
            filename: "schema.graphql",
            want:     true,
        },
        {
            name:     "GQL extension",
            input:    "anything",
            filename: "schema.gql",
            want:     true,
        },
        {
            name:     "SDL by content - type Query",
            input:    "type Query { users: [User] }",
            filename: "schema.txt",
            want:     true,
        },
        {
            name:     "SDL by content - type Mutation",
            input:    "type Mutation { createUser(name: String!): User }",
            filename: "schema.txt",
            want:     true,
        },
        {
            name:     "SDL by content - schema block",
            input:    "schema { query: Query mutation: Mutation }",
            filename: "schema.txt",
            want:     true,
        },
        {
            name:     "Not GraphQL - OpenAPI",
            input:    `{"openapi": "3.0.0", "paths": {}}`,
            filename: "openapi.json",
            want:     false,
        },
        {
            name:     "Not GraphQL - random JSON",
            input:    `{"foo": "bar"}`,
            filename: "data.json",
            want:     false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := plugin.CanParse([]byte(tt.input), tt.filename)
            assert.Equal(t, tt.want, got)
        })
    }
}

func TestGraphQLPlugin_CanParse_Introspection(t *testing.T) {
    plugin := &GraphQLPlugin{}

    introspectionJSON := `{
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": []
            }
        }
    }`

    assert.True(t, plugin.CanParse([]byte(introspectionJSON), "introspection.json"))
}
```

**Exit Criteria:**
- [ ] `pkg/plugins/graphql/plugin.go` created with `Name()`, `Type()`, `CanParse()`
- [ ] `pkg/plugins/graphql/plugin_test.go` passes with all test cases
- [ ] GraphQL plugin appears in `plugins.All()` after import
- [ ] `go test ./pkg/plugins/graphql/...` passes with 0 failures

---

### Task T003: SDL Parser Using gqlparser

**Batch:** 2 - Schema Parsing
**Depends On:** T001
**Estimated Time:** 20 minutes

**Files:**
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/plugins/graphql/sdl_parser.go`
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/plugins/graphql/sdl_parser_test.go`
- Modify: `/workspaces/praetorian-dev/modules/hadrian/go.mod` (add gqlparser dependency)

**Description:**
Parse GraphQL SDL files using the gqlparser library and convert to our internal Schema type.

**Implementation:**

```go
// pkg/plugins/graphql/sdl_parser.go
package graphql

import (
    "fmt"

    "github.com/vektah/gqlparser/v2"
    "github.com/vektah/gqlparser/v2/ast"

    "github.com/praetorian-inc/hadrian/pkg/graphql"
)

// ParseSDL parses a GraphQL SDL string into our Schema type
func ParseSDL(sdl string) (*graphql.Schema, error) {
    source := &ast.Source{Input: sdl}
    doc, err := gqlparser.LoadSchema(source)
    if err != nil {
        return nil, fmt.Errorf("failed to parse SDL: %w", err)
    }

    return convertASTSchema(doc), nil
}

func convertASTSchema(doc *ast.Schema) *graphql.Schema {
    schema := &graphql.Schema{
        Types:    make(map[string]*graphql.TypeDef),
        Queries:  make([]*graphql.FieldDef, 0),
        Mutations: make([]*graphql.FieldDef, 0),
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
            schema.Queries = append(schema.Queries, convertFieldDef(field))
        }
    }

    // Extract mutation type fields
    if doc.Mutation != nil {
        schema.MutationType = doc.Mutation.Name
        for _, field := range doc.Mutation.Fields {
            schema.Mutations = append(schema.Mutations, convertFieldDef(field))
        }
    }

    return schema
}

func convertTypeDef(def *ast.Definition) *graphql.TypeDef {
    typeDef := &graphql.TypeDef{
        Name:        def.Name,
        Kind:        convertKind(def.Kind),
        Description: def.Description,
        Fields:      make([]*graphql.FieldDef, 0),
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

func convertFieldDef(field *ast.FieldDefinition) *graphql.FieldDef {
    fieldDef := &graphql.FieldDef{
        Name:         field.Name,
        Type:         convertTypeRef(field.Type),
        Description:  field.Description,
        Args:         make([]*graphql.ArgumentDef, 0),
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

func convertTypeRef(t *ast.Type) *graphql.TypeRef {
    if t == nil {
        return nil
    }

    typeRef := &graphql.TypeRef{}

    if t.NonNull {
        typeRef.Kind = graphql.TypeKindNonNull
        typeRef.OfType = convertTypeRef(&ast.Type{
            NamedType: t.NamedType,
            Elem:      t.Elem,
        })
        return typeRef
    }

    if t.Elem != nil {
        typeRef.Kind = graphql.TypeKindList
        typeRef.OfType = convertTypeRef(t.Elem)
        return typeRef
    }

    typeRef.Name = t.NamedType
    typeRef.Kind = graphql.TypeKindScalar // Default, will be corrected

    return typeRef
}

func convertArgument(arg *ast.ArgumentDefinition) *graphql.ArgumentDef {
    argDef := &graphql.ArgumentDef{
        Name:        arg.Name,
        Type:        convertTypeRef(arg.Type),
        Description: arg.Description,
    }

    if arg.DefaultValue != nil {
        argDef.DefaultValue = arg.DefaultValue.String()
    }

    return argDef
}

func convertKind(kind ast.DefinitionKind) graphql.TypeKind {
    switch kind {
    case ast.Scalar:
        return graphql.TypeKindScalar
    case ast.Object:
        return graphql.TypeKindObject
    case ast.Interface:
        return graphql.TypeKindInterface
    case ast.Union:
        return graphql.TypeKindUnion
    case ast.Enum:
        return graphql.TypeKindEnum
    case ast.InputObject:
        return graphql.TypeKindInputObject
    default:
        return graphql.TypeKindObject
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
```

**Test Cases:**
```go
// pkg/plugins/graphql/sdl_parser_test.go
package graphql

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestParseSDL_BasicSchema(t *testing.T) {
    sdl := `
        type Query {
            user(id: ID!): User
            users: [User!]!
        }

        type Mutation {
            createUser(name: String!, email: String!): User
            deleteUser(id: ID!): Boolean
        }

        type User {
            id: ID!
            name: String!
            email: String
            role: Role!
        }

        enum Role {
            ADMIN
            USER
            GUEST
        }
    `

    schema, err := ParseSDL(sdl)
    require.NoError(t, err)

    // Check query fields
    assert.Len(t, schema.Queries, 2)
    assert.Equal(t, "user", schema.Queries[0].Name)
    assert.Equal(t, "users", schema.Queries[1].Name)

    // Check mutation fields
    assert.Len(t, schema.Mutations, 2)
    assert.Equal(t, "createUser", schema.Mutations[0].Name)

    // Check User type
    userType, ok := schema.GetType("User")
    require.True(t, ok)
    assert.Len(t, userType.Fields, 4)

    // Check Role enum
    roleType, ok := schema.GetType("Role")
    require.True(t, ok)
    assert.Equal(t, graphql.TypeKindEnum, roleType.Kind)
    assert.Contains(t, roleType.EnumValues, "ADMIN")
}

func TestParseSDL_Arguments(t *testing.T) {
    sdl := `
        type Query {
            search(query: String!, limit: Int = 10, offset: Int): [Result]
        }
        type Result {
            id: ID!
        }
    `

    schema, err := ParseSDL(sdl)
    require.NoError(t, err)

    searchField := schema.Queries[0]
    assert.Equal(t, "search", searchField.Name)
    assert.Len(t, searchField.Args, 3)

    // Check query argument is required (NonNull)
    queryArg := searchField.Args[0]
    assert.Equal(t, "query", queryArg.Name)
    assert.True(t, queryArg.Type.IsNonNull())

    // Check limit has default value
    limitArg := searchField.Args[1]
    assert.Equal(t, "limit", limitArg.Name)
    assert.Equal(t, "10", limitArg.DefaultValue)
}

func TestParseSDL_InvalidSDL(t *testing.T) {
    sdl := "not valid graphql {"

    _, err := ParseSDL(sdl)
    assert.Error(t, err)
}
```

**Exit Criteria:**
- [ ] `go get github.com/vektah/gqlparser/v2` added to go.mod
- [ ] `pkg/plugins/graphql/sdl_parser.go` created with `ParseSDL()` function
- [ ] `pkg/plugins/graphql/sdl_parser_test.go` passes with 3 test functions
- [ ] `go test ./pkg/plugins/graphql/...` passes with 0 failures

---

### Task T004: Introspection Client

**Batch:** 2 - Schema Parsing
**Depends On:** T001
**Estimated Time:** 20 minutes

**Files:**
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/graphql/introspection.go`
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/graphql/introspection_test.go`

**Description:**
Implement an introspection client that fetches the GraphQL schema from a live endpoint using the standard introspection query.

**Implementation:**

```go
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
    QueryType        *TypeNameRef          `json:"queryType"`
    MutationType     *TypeNameRef          `json:"mutationType"`
    SubscriptionType *TypeNameRef          `json:"subscriptionType"`
    Types            []IntrospectionType   `json:"types"`
}

type TypeNameRef struct {
    Name string `json:"name"`
}

type IntrospectionType struct {
    Kind          string                  `json:"kind"`
    Name          string                  `json:"name"`
    Description   string                  `json:"description"`
    Fields        []IntrospectionField    `json:"fields"`
    InputFields   []IntrospectionInput    `json:"inputFields"`
    Interfaces    []IntrospectionTypeRef  `json:"interfaces"`
    EnumValues    []IntrospectionEnum     `json:"enumValues"`
    PossibleTypes []IntrospectionTypeRef  `json:"possibleTypes"`
}

type IntrospectionField struct {
    Name              string                 `json:"name"`
    Description       string                 `json:"description"`
    Args              []IntrospectionInput   `json:"args"`
    Type              IntrospectionTypeRef   `json:"type"`
    IsDeprecated      bool                   `json:"isDeprecated"`
    DeprecationReason string                 `json:"deprecationReason"`
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
        body, _ := io.ReadAll(resp.Body)
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

    return convertIntrospectionResult(&result), nil
}

// convertIntrospectionResult converts introspection JSON to our Schema type
func convertIntrospectionResult(result *IntrospectionResult) *Schema {
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
```

**Test Cases:**
```go
// pkg/graphql/introspection_test.go
package graphql

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestIntrospectionClient_FetchSchema(t *testing.T) {
    // Create mock server
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "POST", r.Method)
        assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

        response := IntrospectionResult{
            Data: IntrospectionData{
                Schema: IntrospectionSchema{
                    QueryType:    &TypeNameRef{Name: "Query"},
                    MutationType: &TypeNameRef{Name: "Mutation"},
                    Types: []IntrospectionType{
                        {
                            Kind: "OBJECT",
                            Name: "Query",
                            Fields: []IntrospectionField{
                                {
                                    Name: "user",
                                    Type: IntrospectionTypeRef{Kind: "OBJECT", Name: "User"},
                                    Args: []IntrospectionInput{
                                        {Name: "id", Type: IntrospectionTypeRef{Kind: "NON_NULL", OfType: &IntrospectionTypeRef{Kind: "SCALAR", Name: "ID"}}},
                                    },
                                },
                            },
                        },
                        {
                            Kind: "OBJECT",
                            Name: "User",
                            Fields: []IntrospectionField{
                                {Name: "id", Type: IntrospectionTypeRef{Kind: "NON_NULL", OfType: &IntrospectionTypeRef{Kind: "SCALAR", Name: "ID"}}},
                                {Name: "email", Type: IntrospectionTypeRef{Kind: "SCALAR", Name: "String"}},
                            },
                        },
                        {
                            Kind: "OBJECT",
                            Name: "Mutation",
                            Fields: []IntrospectionField{
                                {Name: "deleteUser", Type: IntrospectionTypeRef{Kind: "SCALAR", Name: "Boolean"}},
                            },
                        },
                    },
                },
            },
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }))
    defer server.Close()

    client := NewIntrospectionClient(http.DefaultClient, server.URL)
    schema, err := client.FetchSchema(context.Background())

    require.NoError(t, err)
    assert.Equal(t, "Query", schema.QueryType)
    assert.Equal(t, "Mutation", schema.MutationType)
    assert.Len(t, schema.Queries, 1)
    assert.Equal(t, "user", schema.Queries[0].Name)
    assert.Len(t, schema.Mutations, 1)
}

func TestIntrospectionClient_WithAuth(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

        response := IntrospectionResult{
            Data: IntrospectionData{
                Schema: IntrospectionSchema{
                    QueryType: &TypeNameRef{Name: "Query"},
                    Types:     []IntrospectionType{},
                },
            },
        }
        json.NewEncoder(w).Encode(response)
    }))
    defer server.Close()

    client := NewIntrospectionClient(http.DefaultClient, server.URL)
    client.SetHeader("Authorization", "Bearer test-token")

    _, err := client.FetchSchema(context.Background())
    require.NoError(t, err)
}

func TestIntrospectionClient_ErrorHandling(t *testing.T) {
    // Test introspection disabled
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        response := IntrospectionResult{
            Errors: []GraphQLError{
                {Message: "Introspection is disabled"},
            },
        }
        json.NewEncoder(w).Encode(response)
    }))
    defer server.Close()

    client := NewIntrospectionClient(http.DefaultClient, server.URL)
    _, err := client.FetchSchema(context.Background())

    assert.Error(t, err)
    assert.Contains(t, err.Error(), "Introspection is disabled")
}
```

**Exit Criteria:**
- [ ] `pkg/graphql/introspection.go` created with `FetchSchema()` method
- [ ] `pkg/graphql/introspection_test.go` passes with 3 test functions
- [ ] `go test ./pkg/graphql/...` passes with 0 failures

---

### Task T005: Schema to Operation Converter

**Batch:** 3 - Operation Conversion
**Depends On:** T003, T004
**Estimated Time:** 20 minutes

**Files:**
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/plugins/graphql/operation_converter.go`
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/plugins/graphql/operation_converter_test.go`

**Description:**
Convert GraphQL schema types to `model.Operation` structures that the existing runner can process.

**Implementation:**

```go
// pkg/plugins/graphql/operation_converter.go
package graphql

import (
    "fmt"

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
        Method:           "POST",                    // GraphQL always uses POST
        Path:             fmt.Sprintf("%s %s", opType, field.Name),
        Protocol:         "graphql",
        GraphQLOperation: opType,
        GraphQLField:     field.Name,
        RequiresAuth:     false,                     // Will be set based on schema analysis
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
    if field.Description != "" &&
       (containsAuthIndicator(field.Description)) {
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
    // Simple case-insensitive contains
    sLower := strings.ToLower(s)
    substrLower := strings.ToLower(substr)
    return strings.Contains(sLower, substrLower)
}
```

**Test Cases:**
```go
// pkg/plugins/graphql/operation_converter_test.go
func TestConvertSchemaToOperations(t *testing.T) {
    schema := &graphql.Schema{
        QueryType:    "Query",
        MutationType: "Mutation",
        Types: map[string]*graphql.TypeDef{
            "User": {
                Name: "User",
                Kind: graphql.TypeKindObject,
                Fields: []*graphql.FieldDef{
                    {Name: "id", Type: &graphql.TypeRef{Name: "ID", Kind: graphql.TypeKindScalar}},
                    {Name: "email", Type: &graphql.TypeRef{Name: "String", Kind: graphql.TypeKindScalar}},
                },
            },
        },
        Queries: []*graphql.FieldDef{
            {
                Name: "user",
                Type: &graphql.TypeRef{Name: "User", Kind: graphql.TypeKindObject},
                Args: []*graphql.ArgumentDef{
                    {Name: "id", Type: &graphql.TypeRef{Kind: graphql.TypeKindNonNull, OfType: &graphql.TypeRef{Name: "ID"}}},
                },
            },
        },
        Mutations: []*graphql.FieldDef{
            {
                Name: "deleteUser",
                Type: &graphql.TypeRef{Name: "Boolean", Kind: graphql.TypeKindScalar},
                Args: []*graphql.ArgumentDef{
                    {Name: "id", Type: &graphql.TypeRef{Kind: graphql.TypeKindNonNull, OfType: &graphql.TypeRef{Name: "ID"}}},
                },
            },
        },
    }

    operations, err := ConvertSchemaToOperations(schema, "http://example.com/graphql")
    require.NoError(t, err)

    assert.Len(t, operations, 2)

    // Check query operation
    queryOp := operations[0]
    assert.Equal(t, "query user", queryOp.Path)
    assert.Equal(t, "graphql", queryOp.Protocol)
    assert.Equal(t, "query", queryOp.GraphQLOperation)
    assert.Equal(t, "user", queryOp.GraphQLField)
    assert.Equal(t, "id", queryOp.OwnerField)

    // Check mutation operation
    mutationOp := operations[1]
    assert.Equal(t, "mutation deleteUser", mutationOp.Path)
    assert.Equal(t, "mutation", mutationOp.GraphQLOperation)
    assert.True(t, mutationOp.RequiresAuth) // Mutations default to requiring auth
}
```

**Exit Criteria:**
- [ ] `pkg/plugins/graphql/operation_converter.go` created
- [ ] `pkg/plugins/graphql/operation_converter_test.go` passes
- [ ] Operations include Protocol, GraphQLOperation, GraphQLField fields
- [ ] `go test ./pkg/plugins/graphql/...` passes with 0 failures

---

### Task T006: Plugin Parse() Implementation

**Batch:** 3 - Operation Conversion
**Depends On:** T003, T004, T005
**Estimated Time:** 15 minutes

**Files:**
- Modify: `/workspaces/praetorian-dev/modules/hadrian/pkg/plugins/graphql/plugin.go`

**Description:**
Complete the Plugin `Parse()` method to detect input type (SDL vs introspection JSON) and convert to APISpec.

**Implementation:**

Update `plugin.go` to add:

```go
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
           strings.Contains(content, `"data"`)
}

func parseIntrospectionJSON(input []byte) (*graphql.Schema, error) {
    var result graphql.IntrospectionResult
    if err := json.Unmarshal(input, &result); err != nil {
        return nil, fmt.Errorf("failed to parse introspection JSON: %w", err)
    }
    return graphql.ConvertIntrospectionResult(&result), nil
}
```

**Exit Criteria:**
- [ ] `plugin.go` updated with complete `Parse()` method
- [ ] SDL files parse correctly
- [ ] Introspection JSON parses correctly
- [ ] All existing tests still pass

---

### Task T007: Query Builder

**Batch:** 4 - Query Construction & Execution
**Depends On:** T001
**Estimated Time:** 20 minutes

**Files:**
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/graphql/query_builder.go`
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/graphql/query_builder_test.go`

**Description:**
Build GraphQL queries dynamically for testing, including depth attacks and batch queries.

**Implementation:**

```go
// pkg/graphql/query_builder.go
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
        return fmt.Sprintf(`"%s"`, val)
    case int, int64, float64:
        return fmt.Sprintf("%v", val)
    case bool:
        return fmt.Sprintf("%t", val)
    default:
        return fmt.Sprintf(`"%v"`, val)
    }
}
```

**Exit Criteria:**
- [ ] `pkg/graphql/query_builder.go` created
- [ ] `BuildQuery()` generates valid GraphQL queries
- [ ] `BuildDepthAttackQuery()` generates nested queries
- [ ] `BuildBatchQuery()` generates aliased queries
- [ ] Tests pass

---

### Task T008: GraphQL Executor

**Batch:** 4 - Query Construction & Execution
**Depends On:** T007
**Estimated Time:** 20 minutes

**Files:**
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/graphql/executor.go`
- Create: `/workspaces/praetorian-dev/modules/hadrian/pkg/graphql/executor_test.go`

**Description:**
Execute GraphQL queries and return results compatible with existing matcher system.

**Implementation:**

```go
// pkg/graphql/executor.go
package graphql

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"

    "github.com/praetorian-inc/hadrian/pkg/model"
    "github.com/praetorian-inc/hadrian/pkg/templates"
)

// Executor executes GraphQL queries
type Executor struct {
    httpClient templates.HTTPClient
    endpoint   string
}

// NewExecutor creates a new GraphQL executor
func NewExecutor(client templates.HTTPClient, endpoint string) *Executor {
    return &Executor{
        httpClient: client,
        endpoint:   endpoint,
    }
}

// GraphQLRequest is the standard request format
type GraphQLRequest struct {
    Query         string                 `json:"query"`
    Variables     map[string]interface{} `json:"variables,omitempty"`
    OperationName string                 `json:"operationName,omitempty"`
}

// GraphQLResponse is the standard response format
type GraphQLResponse struct {
    Data   json.RawMessage `json:"data,omitempty"`
    Errors []GraphQLError  `json:"errors,omitempty"`
}

// ExecuteResult contains execution results
type ExecuteResult struct {
    Response   *http.Response
    Body       string
    StatusCode int
    Errors     []GraphQLError
    RequestID  string
}

// Execute runs a GraphQL query
func (e *Executor) Execute(
    ctx context.Context,
    query string,
    variables map[string]interface{},
    operationName string,
    authInfo *templates.AuthInfo,
) (*ExecuteResult, error) {
    // Build request body
    reqBody := GraphQLRequest{
        Query:         query,
        Variables:     variables,
        OperationName: operationName,
    }

    bodyBytes, err := json.Marshal(reqBody)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, "POST", e.endpoint, bytes.NewReader(bodyBytes))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Content-Type", "application/json")

    // Add auth
    if authInfo != nil && authInfo.Value != "" {
        switch authInfo.Method {
        case "bearer":
            req.Header.Set("Authorization", authInfo.Value)
        case "api_key":
            if authInfo.Location == "header" {
                req.Header.Set(authInfo.KeyName, authInfo.Value)
            }
        }
    }

    // Generate request ID
    requestID := generateRequestID()
    req.Header.Set("X-Hadrian-Request-Id", requestID)

    // Execute
    resp, err := e.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    // Read body
    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response: %w", err)
    }

    result := &ExecuteResult{
        Response:   resp,
        Body:       string(respBody),
        StatusCode: resp.StatusCode,
        RequestID:  requestID,
    }

    // Parse GraphQL errors if present
    var gqlResp GraphQLResponse
    if err := json.Unmarshal(respBody, &gqlResp); err == nil {
        result.Errors = gqlResp.Errors
    }

    return result, nil
}

// ToHTTPResponse converts result to model.HTTPResponse
func (r *ExecuteResult) ToHTTPResponse() model.HTTPResponse {
    return model.HTTPResponse{
        StatusCode: r.StatusCode,
        Body:       r.Body,
        Headers:    flattenHeaders(r.Response.Header),
    }
}

func flattenHeaders(h http.Header) map[string]string {
    result := make(map[string]string)
    for k, v := range h {
        if len(v) > 0 {
            result[k] = v[0]
        }
    }
    return result
}
```

**Exit Criteria:**
- [ ] `pkg/graphql/executor.go` created
- [ ] Executes GraphQL queries via HTTP POST
- [ ] Handles authentication
- [ ] Parses GraphQL errors
- [ ] Tests pass

---

### Tasks T009-T020 (Summary)

Due to space constraints, I'll provide summary specifications for the remaining tasks:

### Task T009: Depth/Complexity Analyzer
- **Files:** `pkg/graphql/depth_analyzer.go`, `pkg/graphql/depth_analyzer_test.go`
- **Purpose:** Analyze query depth and complexity for DoS detection

### Task T010: Attack Pattern Generators
- **Files:** `pkg/graphql/attacks.go`, `pkg/graphql/attacks_test.go`
- **Purpose:** Generate introspection, depth, batching, field suggestion attacks

### Task T011: Template GraphQL Extension
- **Files:** Modify `pkg/templates/template.go`
- **Purpose:** Add `GraphQL []GraphQLTest` field to Template struct

### Task T012: Model Operation Extensions
- **Files:** Modify `pkg/model/operation.go`
- **Purpose:** Add Protocol, GraphQLOperation, GraphQLField, GraphQLType fields

### Task T013: CLI Refactoring to Subcommands
- **Files:** `pkg/runner/run.go` (modify), `pkg/runner/graphql.go` (create)
- **Purpose:** Create `test rest` and `test graphql` subcommands

### Task T014-T018: GraphQL Templates
- **Files:** `templates/graphql/*.yaml`
- **Purpose:** Create security test templates for:
  - T014: Introspection disclosure
  - T015: Depth attack
  - T016: Batching attack
  - T017: BOLA
  - T018: BFLA

### Task T019: DVGA Test Setup
- **Files:** `testdata/dvga/docker-compose.yaml`, `testdata/dvga/dvga-roles.yaml`, `testdata/dvga/dvga-auth.yaml`, `testdata/dvga/README.md`
- **Purpose:** Set up DVGA for integration testing

### Task T020: Integration Tests
- **Files:** `pkg/plugins/graphql/integration_test.go`, `pkg/runner/graphql_test.go`
- **Purpose:** End-to-end integration tests

---

## 2.3 Batch Groupings

| Batch | Tasks | Description | Depends On |
|-------|-------|-------------|------------|
| 1 | T001, T002 | Core Plugin Infrastructure | - |
| 2 | T003, T004 | Schema Parsing (SDL + Introspection) | Batch 1 |
| 3 | T005, T006 | Operation Conversion + Plugin Complete | Batch 2 |
| 4 | T007, T008 | Query Construction & Execution | Batch 1 |
| 5 | T009, T010 | Attack Patterns (can parallel with 6) | Batch 4 |
| 6 | T011-T018 | CLI, Templates, Model Extensions | Batch 3, 4 |
| 7 | T019, T020 | Test Infrastructure | All |

---

## 2.4 Acceptance Criteria Summary

| Task | Files Created | Files Modified | Tests Required | Verification Command |
|------|---------------|----------------|----------------|---------------------|
| T001 | 2 | 0 | 3 | `go test ./pkg/graphql/... -run TestTypeRef` |
| T002 | 2 | 0 | 3 | `go test ./pkg/plugins/graphql/... -run TestPlugin` |
| T003 | 2 | 1 (go.mod) | 3 | `go test ./pkg/plugins/graphql/... -run TestParseSDL` |
| T004 | 2 | 0 | 3 | `go test ./pkg/graphql/... -run TestIntrospection` |
| T005 | 2 | 0 | 1 | `go test ./pkg/plugins/graphql/... -run TestConvert` |
| T006 | 0 | 1 | 1 | `go test ./pkg/plugins/graphql/... -run TestParse` |
| T007 | 2 | 0 | 3 | `go test ./pkg/graphql/... -run TestQueryBuilder` |
| T008 | 2 | 0 | 3 | `go test ./pkg/graphql/... -run TestExecutor` |
| T009 | 2 | 0 | 2 | `go test ./pkg/graphql/... -run TestDepth` |
| T010 | 2 | 0 | 4 | `go test ./pkg/graphql/... -run TestAttack` |
| T011 | 0 | 1 | 0 | `go build ./...` |
| T012 | 0 | 1 | 0 | `go build ./...` |
| T013 | 1 | 1 | 2 | `go test ./pkg/runner/... -run TestGraphQL` |
| T014-T018 | 5 | 0 | 0 | YAML lint |
| T019 | 4 | 0 | 0 | `docker-compose config` |
| T020 | 2 | 0 | 3 | `go test -tags=integration ./...` |

---

## Part 3: Phase Exit Criteria

**Overall Exit Criteria for Architecture Plan Completion:**

- [ ] 20 tasks defined with specific file paths
- [ ] 7 batches with clear dependencies
- [ ] All interface definitions verified against existing code
- [ ] Data flow documented from CLI to report
- [ ] Pattern choices documented with rationale
- [ ] Test requirements specified per task
- [ ] Verification commands provided for each task
- [ ] Total estimated LOC: 3,000-4,000 (code) + 1,500-2,000 (tests)

---

## Metadata

```json
{
  "agent": "backend-lead",
  "output_type": "architecture-plan",
  "timestamp": "2026-02-02T00:00:00Z",
  "feature_directory": "/workspaces/praetorian-dev/modules/hadrian/.feature-development",
  "skills_invoked": [
    "using-skills",
    "discovering-reusable-code",
    "semantic-code-operations",
    "calibrating-time-estimates",
    "enforcing-evidence-based-analysis",
    "gateway-backend",
    "persisting-agent-outputs",
    "brainstorming",
    "writing-plans",
    "verifying-before-completion",
    "adhering-to-dry",
    "adhering-to-yagni"
  ],
  "library_skills_read": [
    ".claude/skill-library/development/backend/structuring-go-projects/SKILL.md",
    ".claude/skill-library/development/backend/go-best-practices/SKILL.md",
    ".claude/skill-library/development/backend/implementing-graphql-clients/SKILL.md",
    ".claude/skill-library/claude/mcp-tools/mcp-tools-serena/SKILL.md"
  ],
  "source_files_verified": [
    "/workspaces/praetorian-dev/modules/hadrian/pkg/plugins/plugin.go:1-79",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/plugins/rest/plugin.go:1-321",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/runner/run.go:1-505",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/templates/template.go:1-158",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/templates/compile.go:1-61",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/templates/execute.go:1-539",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/model/operation.go:1-52",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/model/finding.go:1-72",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/matchers/matcher.go:1-19",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/roles/roles.go:1-202",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/runner/execution.go:1-244",
    "/workspaces/praetorian-dev/modules/hadrian/cmd/hadrian/main.go:1-14"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Execute batches 1-7 following TDD methodology. Start with Batch 1 (T001, T002) - core plugin infrastructure."
  }
}
```
