# GraphQL API Security Testing Module - Security Assessment

**Repository:** `/workspaces/praetorian-dev/modules/hadrian`
**Feature:** GraphQL API Security Testing Module
**Date:** 2026-02-02
**Assessment Type:** Security Architecture Review
**Author:** Security Lead (Architect)

---

## Executive Summary

This security assessment evaluates the proposed GraphQL API Security Testing Module architecture against the five review focus areas: query construction security, schema handling security, credential handling, test execution security, and security test coverage.

**Overall Risk Assessment:** MEDIUM-HIGH (without mitigations) / LOW (with recommended controls)

The proposed design leverages Hadrian's existing security patterns (defense-in-depth, credential redaction, production safety) which provide a strong foundation. GraphQL introduces unique attack vectors (injection via query construction, schema poisoning, depth/complexity DoS) that require additional security controls beyond what exists for REST API testing.

---

## Table of Contents

1. [Query Construction Security](#1-query-construction-security)
2. [Schema Handling Security](#2-schema-handling-security)
3. [Credential Handling](#3-credential-handling)
4. [Test Execution Security](#4-test-execution-security)
5. [Security Test Coverage](#5-security-test-coverage)
6. [Recommended Code Patterns](#6-recommended-code-patterns)
7. [Anti-Patterns to Avoid](#7-anti-patterns-to-avoid)
8. [Trade-offs and Risk Acceptance](#8-trade-offs-and-risk-acceptance)

---

## 1. Query Construction Security

### 1.1 Threat Analysis

**STRIDE Assessment:**

| Threat | Description | Risk Level | Mitigation |
|--------|-------------|------------|------------|
| **Injection** | Malicious data in variables could escape query context | HIGH | Use parameterized queries via `variables` map |
| **Tampering** | Query structure modified to access unauthorized fields | MEDIUM | Validate query against schema before execution |
| **Information Disclosure** | Error messages reveal schema structure | LOW | Already mitigated by redactor |

### 1.2 Secure Query Construction Pattern

**MUST FOLLOW:** All GraphQL queries MUST be constructed using parameterized variables, never string concatenation.

```go
// CORRECT: Parameterized query construction
type GraphQLRequest struct {
    Query     string                 `json:"query"`
    Variables map[string]interface{} `json:"variables"`
    OperationName string             `json:"operationName,omitempty"`
}

func BuildQuery(queryTemplate string, variables map[string]interface{}) *GraphQLRequest {
    // Query template is a compile-time constant
    // Variables are ALWAYS passed separately - NEVER interpolated into query string
    return &GraphQLRequest{
        Query:     queryTemplate,
        Variables: variables,
    }
}
```

```go
// WRONG: String concatenation (INJECTION RISK)
func BuildQueryUnsafe(userID string) string {
    // NEVER DO THIS - direct string interpolation allows injection
    return fmt.Sprintf(`query { user(id: "%s") { email } }`, userID)
}
```

### 1.3 Variable Binding Requirements

**Mandatory Controls:**

1. **Type Coercion:** Variables MUST be type-coerced to expected GraphQL scalar types before inclusion
2. **Null Handling:** Null values MUST be explicitly handled, not string-interpolated as "null"
3. **String Escaping:** For any edge case where variable must appear in query string, use `encoding/json.Marshal()` for proper escaping
4. **Variable Name Validation:** Variable names in templates MUST match `^[_A-Za-z][_0-9A-Za-z]*$` (GraphQL spec)

```go
// Variable validation pattern
var variableNameRegex = regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`)

func ValidateVariableName(name string) error {
    if !variableNameRegex.MatchString(name) {
        return fmt.Errorf("invalid GraphQL variable name: %s", name)
    }
    return nil
}

// Type coercion for variables
func CoerceVariable(value interface{}, graphqlType string) (interface{}, error) {
    switch graphqlType {
    case "ID", "String":
        return fmt.Sprintf("%v", value), nil
    case "Int":
        // Parse and validate as integer
        if v, ok := value.(int); ok {
            return v, nil
        }
        return nil, fmt.Errorf("expected Int, got %T", value)
    case "Boolean":
        if v, ok := value.(bool); ok {
            return v, nil
        }
        return nil, fmt.Errorf("expected Boolean, got %T", value)
    default:
        return value, nil // Complex types pass through
    }
}
```

### 1.4 Query Template Validation

**Before executing any query template:**

1. Parse query with `gqlparser` to validate syntax
2. Validate all variables are declared in the query
3. Validate query complexity does not exceed safety limits
4. Validate query depth does not exceed safety limits

```go
import "github.com/vektah/gqlparser/v2"

func ValidateQueryTemplate(query string, schema *ast.Schema) error {
    // Parse and validate against schema
    doc, gqlErr := gqlparser.LoadQuery(schema, query)
    if gqlErr != nil {
        return fmt.Errorf("invalid query: %v", gqlErr)
    }

    // Calculate and validate complexity
    complexity := CalculateComplexity(doc)
    if complexity > MaxQueryComplexity {
        return fmt.Errorf("query complexity %d exceeds limit %d", complexity, MaxQueryComplexity)
    }

    // Calculate and validate depth
    depth := CalculateDepth(doc)
    if depth > MaxQueryDepth {
        return fmt.Errorf("query depth %d exceeds limit %d", depth, MaxQueryDepth)
    }

    return nil
}
```

---

## 2. Schema Handling Security

### 2.1 Threat Analysis

| Threat | Description | Risk Level | Mitigation |
|--------|-------------|------------|------------|
| **Malicious Introspection Response** | Attacker-controlled server returns crafted schema to exploit parser | HIGH | Size limits, depth limits, timeout |
| **SDL File Injection** | Malicious SDL file contains code execution payload | MEDIUM | Use only `gqlparser`, no eval/exec |
| **Resource Exhaustion** | Huge schema causes OOM | MEDIUM | Size and object count limits |
| **Path Traversal** | Schema file path manipulation | LOW | Validate file paths |

### 2.2 Introspection Response Validation

**Mandatory Controls for Introspection:**

```go
const (
    MaxIntrospectionResponseSize = 10 * 1024 * 1024  // 10MB max
    MaxSchemaTypes              = 10000              // Max type definitions
    MaxSchemaFields             = 100000             // Max total fields
    IntrospectionTimeout        = 30 * time.Second  // Timeout for introspection
)

type IntrospectionClient struct {
    httpClient *http.Client
    maxSize    int64
}

func (c *IntrospectionClient) FetchSchema(ctx context.Context, endpoint string) (*Schema, error) {
    // Apply timeout
    ctx, cancel := context.WithTimeout(ctx, IntrospectionTimeout)
    defer cancel()

    // Build introspection query request
    req, err := http.NewRequestWithContext(ctx, "POST", endpoint,
        strings.NewReader(introspectionQuery))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("introspection request failed: %w", err)
    }
    defer resp.Body.Close()

    // CRITICAL: Limit response size to prevent OOM
    limitedReader := io.LimitReader(resp.Body, MaxIntrospectionResponseSize)
    body, err := io.ReadAll(limitedReader)
    if err != nil {
        return nil, fmt.Errorf("failed to read response: %w", err)
    }

    // Check if we hit the limit
    if int64(len(body)) >= MaxIntrospectionResponseSize {
        return nil, fmt.Errorf("introspection response exceeds %d byte limit", MaxIntrospectionResponseSize)
    }

    // Parse and validate schema
    schema, err := ParseIntrospectionResponse(body)
    if err != nil {
        return nil, err
    }

    // Validate schema bounds
    if err := ValidateSchemaBounds(schema); err != nil {
        return nil, err
    }

    return schema, nil
}

func ValidateSchemaBounds(schema *Schema) error {
    typeCount := len(schema.Types)
    if typeCount > MaxSchemaTypes {
        return fmt.Errorf("schema has %d types, exceeds limit of %d", typeCount, MaxSchemaTypes)
    }

    fieldCount := 0
    for _, t := range schema.Types {
        fieldCount += len(t.Fields)
    }
    if fieldCount > MaxSchemaFields {
        return fmt.Errorf("schema has %d fields, exceeds limit of %d", fieldCount, MaxSchemaFields)
    }

    return nil
}
```

### 2.3 SDL File Parsing Security

**Pattern for safe SDL parsing:**

```go
import (
    "github.com/vektah/gqlparser/v2"
    "github.com/vektah/gqlparser/v2/ast"
)

const (
    MaxSDLFileSize = 5 * 1024 * 1024  // 5MB max
)

func ParseSDLFile(filePath string) (*ast.Schema, error) {
    // Validate file path (no path traversal)
    if strings.Contains(filePath, "..") {
        return nil, fmt.Errorf("invalid file path: path traversal detected")
    }

    // Check file permissions (similar to auth.go pattern)
    info, err := os.Stat(filePath)
    if err != nil {
        return nil, fmt.Errorf("cannot stat schema file: %w", err)
    }

    // Check file size before reading
    if info.Size() > MaxSDLFileSize {
        return nil, fmt.Errorf("schema file size %d exceeds limit %d", info.Size(), MaxSDLFileSize)
    }

    // Read file content
    content, err := os.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("failed to read schema file: %w", err)
    }

    // Parse with gqlparser (safe, no code execution)
    schema, gqlErr := gqlparser.LoadSchema(&ast.Source{
        Name:  filePath,
        Input: string(content),
    })
    if gqlErr != nil {
        return nil, fmt.Errorf("failed to parse SDL: %v", gqlErr)
    }

    // Validate bounds
    if err := ValidateSchemaBoundsAST(schema); err != nil {
        return nil, err
    }

    return schema, nil
}
```

### 2.4 Malicious Schema Protection

**Defense-in-depth layers (following existing Hadrian pattern from `defense-in-depth` skill):**

| Layer | Protection | Implementation |
|-------|------------|----------------|
| **Entry** | Size limits on file/response | `io.LimitReader`, file size check |
| **Parse** | Use only `gqlparser`, no reflection/eval | Import only safe parser |
| **Validate** | Count types, fields, depth | `ValidateSchemaBounds()` |
| **Execute** | Query complexity/depth limits | Per-query validation |

---

## 3. Credential Handling

### 3.1 Current Pattern (Verified from Source)

**Source:** `/workspaces/praetorian-dev/modules/hadrian/pkg/auth/auth.go` (lines 36-79)

The existing credential handling provides:

1. **File permission warnings** (lines 39-45): Warns if auth file is world-readable
2. **Environment variable expansion** (lines 58-62): `${TOKEN_VAR}` syntax supported
3. **Hardcoded secret detection** (lines 64-70): Warns on JWT/API key patterns in plaintext
4. **Missing credential warnings** (lines 73-75): Warns when role has no auth configured

### 3.2 Recommended Extensions for GraphQL

The existing `auth.AuthConfig` structure supports the authentication patterns needed for GraphQL:

```yaml
# GraphQL auth.yaml follows same format as REST
method: bearer
roles:
  admin:
    token: "${GRAPHQL_ADMIN_TOKEN}"  # Environment variable (RECOMMENDED)
  user:
    token: "${GRAPHQL_USER_TOKEN}"
```

**Additional GraphQL-specific considerations:**

1. **Subscription Auth:** If testing GraphQL subscriptions (WebSocket), additional handling needed
2. **Custom Headers:** Some GraphQL APIs use custom headers beyond Authorization

```go
// Extension for GraphQL-specific auth headers
type GraphQLAuthConfig struct {
    *auth.AuthConfig

    // GraphQL-specific options
    CustomHeaders map[string]string `yaml:"custom_headers,omitempty"`

    // WebSocket auth for subscriptions (future)
    WSAuth *WSAuthConfig `yaml:"ws_auth,omitempty"`
}
```

### 3.3 Token Injection in Requests

**Pattern (follow existing execute.go lines 380-402):**

```go
func injectGraphQLAuth(req *http.Request, authInfo *auth.AuthInfo) {
    switch authInfo.Method {
    case "bearer", "basic":
        req.Header.Set("Authorization", authInfo.Value)
    case "api_key":
        if authInfo.Location == "header" {
            req.Header.Set(authInfo.KeyName, authInfo.Value)
        } else if authInfo.Location == "query" {
            q := req.URL.Query()
            q.Set(authInfo.KeyName, authInfo.Value)
            req.URL.RawQuery = q.Encode()
        }
    }
}
```

### 3.4 Credential Logging Prevention

**Existing Pattern (Verified from redactor.go lines 1-131):**

The existing `Redactor` already handles:
- JWT tokens (line 27)
- Bearer tokens (line 29)
- Basic auth (line 30)
- API keys (line 31)
- Passwords (line 32)

**MANDATORY:** All GraphQL request/response logging MUST pass through `Redactor.Redact()` before:
- Console output
- File logging
- LLM triage submission

```go
// Example: Safe logging in GraphQL executor
func (e *GraphQLExecutor) logRequest(req *GraphQLRequest, authHeader string) {
    redactor := reporter.NewRedactor()

    // Redact query variables that might contain sensitive data
    safeVariables := redactor.Redact(fmt.Sprintf("%v", req.Variables))

    // Redact auth header
    safeAuth := redactor.Redact(authHeader)

    log.Debug("GraphQL request: query=%s vars=%s auth=%s",
        req.Query, safeVariables, safeAuth)
}
```

---

## 4. Test Execution Security

### 4.1 Existing Safeguards (Verified from Source)

**Source:** `/workspaces/praetorian-dev/modules/hadrian/pkg/runner/production.go`

| Control | Implementation | Lines |
|---------|----------------|-------|
| Production URL detection | `DetectProduction()` | 16-51 |
| Internal IP blocking | `BlockInternalIPs()` | 53-91 |
| Production confirmation prompt | `ConfirmProductionTesting()` | 93-128 |

These controls MUST be applied to GraphQL testing exactly as they are for REST.

### 4.2 Rate Limiting (Already Implemented)

**Source:** CLAUDE.md confirms rate limiting in `pkg/runner/ratelimit.go` and `pkg/runner/ratelimit_client.go`

- Proactive rate limiting (default 5 req/s)
- Reactive backoff on 429/503
- Exponential backoff with cap

**GraphQL-specific consideration:** GraphQL batching can send multiple queries in one request. Rate limiting should account for:

```go
// Rate limit by operation count, not just request count
func (r *RateLimiter) AcquireN(ctx context.Context, operationCount int) error {
    // For batched GraphQL requests, consume N tokens
    for i := 0; i < operationCount; i++ {
        if err := r.limiter.Wait(ctx); err != nil {
            return err
        }
    }
    return nil
}
```

### 4.3 Request ID Tracking for Audit

**Existing Pattern (Verified from execute.go lines 21-35, 157-159):**

```go
// generateRequestID creates a random UUID-style request ID
func generateRequestID() string {
    b := make([]byte, 16)
    _, err := rand.Read(b)
    // ... UUID formatting
}

// In Execute():
requestID := generateRequestID()
req.Header.Set("X-Hadrian-Request-Id", requestID)
e.requestIDs = append(e.requestIDs, requestID)
```

**Recommendation:** Extend to include GraphQL operation name for better audit correlation:

```go
// GraphQL-enhanced request tracking
type GraphQLRequestAudit struct {
    RequestID      string    `json:"request_id"`
    OperationName  string    `json:"operation_name"`
    OperationType  string    `json:"operation_type"`  // query, mutation, subscription
    Timestamp      time.Time `json:"timestamp"`
    Variables      string    `json:"variables"`       // Redacted
}
```

### 4.4 YAML Template Security

**Existing safeguards (from CLAUDE.md):**
- 1MB size limit
- 20-depth limit for YAML parsing

These MUST apply to GraphQL templates as well. No changes needed.

---

## 5. Security Test Coverage

### 5.1 Proposed Attack Templates Assessment

| Attack | Design Status | OWASP Coverage | Assessment |
|--------|---------------|----------------|------------|
| Introspection Disclosure | Included | API8 (Security Misconfiguration) | ADEQUATE |
| Query Depth Attack | Included | API4 (Unrestricted Resource Consumption) | ADEQUATE |
| Query Complexity Attack | Included | API4 | ADEQUATE |
| Batching Attack | Included | API4 | ADEQUATE |
| Field Suggestion | Included | API8 | ADEQUATE |
| BOLA (user access) | Included | API1 | ADEQUATE |
| BFLA (mutation access) | Included | API5 | ADEQUATE |

### 5.2 Missing GraphQL Vulnerability Categories

**Recommend adding these templates:**

| Attack | OWASP | Priority | Description |
|--------|-------|----------|-------------|
| **Directive Overloading** | API4 | HIGH | Abuse of custom directives for DoS |
| **Type Confusion** | API1/API3 | HIGH | Accessing fields via type union/interface abuse |
| **Alias Bombing** | API4 | HIGH | Many aliases to multiply response size |
| **Fragment DoS** | API4 | MEDIUM | Recursive/deep fragment spreads |
| **Subscription Flooding** | API4 | MEDIUM | Open many subscriptions for resource exhaustion |
| **Persisted Query Bypass** | API8 | MEDIUM | Attempt to send arbitrary queries when only persisted allowed |
| **SDL Injection** | API8 | LOW | If API accepts schema uploads |

### 5.3 OWASP GraphQL Cheat Sheet Alignment

Reference: [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

| OWASP Recommendation | Covered | Notes |
|----------------------|---------|-------|
| Disable introspection in production | YES | `introspection-disclosure.yaml` |
| Query depth limiting | YES | `depth-attack.yaml` |
| Query complexity limiting | YES | `complexity-attack.yaml` |
| Query cost analysis | PARTIAL | Complexity covers this |
| Batching limits | YES | `batching-attack.yaml` |
| Query allow-listing | NO | Add `persisted-query-bypass.yaml` |
| Timeout on queries | PARTIAL | Client-side via HTTP timeout |
| Input validation | PARTIAL | Via BOLA/BFLA templates |
| Authorization on all fields | YES | Via BOLA template |
| Disable GraphiQL in production | NO | Add `graphiql-disclosure.yaml` |

### 5.4 Recommended Additional Templates

```yaml
# Template: graphql-alias-bombing.yaml
id: graphql-alias-bombing
info:
  name: "GraphQL Alias Bombing DoS"
  category: "API4:2023"
  severity: "MEDIUM"
  test_pattern: "simple"

http:
  - method: "POST"
    path: "{{graphql_endpoint}}"
    headers:
      Content-Type: "application/json"
      Authorization: "Bearer {{attacker_token}}"
    body: |
      {
        "query": "query { a1: __typename a2: __typename a3: __typename ... a100: __typename }"
      }
    matchers:
      - type: status
        status: [200]
      # Vulnerable if all 100 aliases returned

detection:
  success_indicators:
    - type: word
      words: ["a100"]
      part: "body"
  vulnerability_pattern: "alias_bombing_not_limited"
```

```yaml
# Template: graphql-graphiql-disclosure.yaml
id: graphql-graphiql-disclosure
info:
  name: "GraphiQL IDE Enabled in Production"
  category: "API8:2023"
  severity: "LOW"
  test_pattern: "simple"

http:
  - method: "GET"
    path: "{{graphql_endpoint}}"
    headers:
      Accept: "text/html"
    matchers:
      - type: word
        words: ["graphiql", "GraphiQL", "graphql-playground"]
        part: "body"

detection:
  success_indicators:
    - type: status_code
      status_code: 200
    - type: word
      words: ["graphiql"]
      part: "body"
  vulnerability_pattern: "graphiql_enabled_production"
```

---

## 6. Recommended Code Patterns

### 6.1 GraphQL Query Builder (Safe Pattern)

```go
package graphql

import (
    "encoding/json"
    "fmt"
    "regexp"
)

var variableNameRegex = regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`)

// Request represents a GraphQL request body
type Request struct {
    Query         string                 `json:"query"`
    Variables     map[string]interface{} `json:"variables,omitempty"`
    OperationName string                 `json:"operationName,omitempty"`
}

// QueryBuilder constructs GraphQL requests safely
type QueryBuilder struct {
    query         string
    variables     map[string]interface{}
    operationName string
}

// NewQueryBuilder creates a builder with a query template
// IMPORTANT: Query template is a compile-time constant, NOT user input
func NewQueryBuilder(queryTemplate string) *QueryBuilder {
    return &QueryBuilder{
        query:     queryTemplate,
        variables: make(map[string]interface{}),
    }
}

// SetVariable adds a variable with validation
func (b *QueryBuilder) SetVariable(name string, value interface{}) error {
    // Validate variable name follows GraphQL spec
    if !variableNameRegex.MatchString(name) {
        return fmt.Errorf("invalid variable name %q: must match [_A-Za-z][_0-9A-Za-z]*", name)
    }

    // Variables are ALWAYS passed separately, NEVER interpolated
    b.variables[name] = value
    return nil
}

// SetOperationName sets the operation name for multi-operation documents
func (b *QueryBuilder) SetOperationName(name string) *QueryBuilder {
    b.operationName = name
    return b
}

// Build creates the request body
func (b *QueryBuilder) Build() (*Request, error) {
    return &Request{
        Query:         b.query,
        Variables:     b.variables,
        OperationName: b.operationName,
    }, nil
}

// MarshalJSON returns the JSON-encoded request body
func (b *QueryBuilder) MarshalJSON() ([]byte, error) {
    req, err := b.Build()
    if err != nil {
        return nil, err
    }
    return json.Marshal(req)
}
```

### 6.2 Schema Validator (Safe Pattern)

```go
package graphql

import (
    "fmt"
    "io"
    "os"
    "strings"

    "github.com/vektah/gqlparser/v2"
    "github.com/vektah/gqlparser/v2/ast"
)

const (
    MaxSDLFileSize   = 5 * 1024 * 1024  // 5MB
    MaxSchemaTypes   = 10000
    MaxSchemaFields  = 100000
    MaxSchemaDepth   = 20
)

// SchemaLoader safely loads and validates GraphQL schemas
type SchemaLoader struct {
    maxFileSize   int64
    maxTypes      int
    maxFields     int
    maxDepth      int
}

func NewSchemaLoader() *SchemaLoader {
    return &SchemaLoader{
        maxFileSize: MaxSDLFileSize,
        maxTypes:    MaxSchemaTypes,
        maxFields:   MaxSchemaFields,
        maxDepth:    MaxSchemaDepth,
    }
}

// LoadFromFile loads SDL from a file with security checks
func (l *SchemaLoader) LoadFromFile(path string) (*ast.Schema, error) {
    // Layer 1: Path validation (no traversal)
    if strings.Contains(path, "..") || strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "/workspaces") {
        return nil, fmt.Errorf("invalid schema path: potential path traversal")
    }

    // Layer 2: File size check before read
    info, err := os.Stat(path)
    if err != nil {
        return nil, fmt.Errorf("cannot access schema file: %w", err)
    }
    if info.Size() > l.maxFileSize {
        return nil, fmt.Errorf("schema file too large: %d > %d bytes", info.Size(), l.maxFileSize)
    }

    // Layer 3: Read with limit
    content, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read schema: %w", err)
    }

    return l.parseAndValidate(path, string(content))
}

// LoadFromReader loads SDL from an io.Reader (for introspection responses)
func (l *SchemaLoader) LoadFromReader(name string, r io.Reader) (*ast.Schema, error) {
    // Layer 1: Size-limited read
    limitedReader := io.LimitReader(r, l.maxFileSize+1)
    content, err := io.ReadAll(limitedReader)
    if err != nil {
        return nil, fmt.Errorf("failed to read schema: %w", err)
    }
    if int64(len(content)) > l.maxFileSize {
        return nil, fmt.Errorf("schema too large: exceeds %d bytes", l.maxFileSize)
    }

    return l.parseAndValidate(name, string(content))
}

func (l *SchemaLoader) parseAndValidate(name, content string) (*ast.Schema, error) {
    // Layer 2: Parse with gqlparser (no code execution)
    schema, gqlErr := gqlparser.LoadSchema(&ast.Source{
        Name:  name,
        Input: content,
    })
    if gqlErr != nil {
        return nil, fmt.Errorf("schema parse error: %v", gqlErr)
    }

    // Layer 3: Validate bounds
    if err := l.validateBounds(schema); err != nil {
        return nil, err
    }

    return schema, nil
}

func (l *SchemaLoader) validateBounds(schema *ast.Schema) error {
    typeCount := len(schema.Types)
    if typeCount > l.maxTypes {
        return fmt.Errorf("schema has %d types (max %d)", typeCount, l.maxTypes)
    }

    fieldCount := 0
    for _, t := range schema.Types {
        if t.Fields != nil {
            fieldCount += len(t.Fields)
        }
    }
    if fieldCount > l.maxFields {
        return fmt.Errorf("schema has %d fields (max %d)", fieldCount, l.maxFields)
    }

    return nil
}
```

### 6.3 GraphQL Executor (Safe Pattern)

```go
package graphql

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"

    "github.com/praetorian-inc/hadrian/pkg/auth"
    "github.com/praetorian-inc/hadrian/pkg/reporter"
)

const (
    MaxResponseSize = 10 * 1024 * 1024  // 10MB
    DefaultTimeout  = 30 * time.Second
)

type Executor struct {
    httpClient *http.Client
    redactor   *reporter.Redactor
    requestIDs []string
}

func NewExecutor(client *http.Client) *Executor {
    return &Executor{
        httpClient: client,
        redactor:   reporter.NewRedactor(),
        requestIDs: make([]string, 0),
    }
}

func (e *Executor) Execute(
    ctx context.Context,
    endpoint string,
    request *Request,
    authInfo *auth.AuthInfo,
) (*Response, error) {
    // Generate request ID for audit trail
    requestID := generateRequestID()
    e.requestIDs = append(e.requestIDs, requestID)

    // Marshal request body
    body, err := json.Marshal(request)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    // Build HTTP request
    req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    // Set headers
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Hadrian-Request-Id", requestID)

    // Inject authentication
    if authInfo != nil {
        injectAuth(req, authInfo)
    }

    // Execute request
    resp, err := e.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    // Read response with size limit
    limitedReader := io.LimitReader(resp.Body, MaxResponseSize)
    respBody, err := io.ReadAll(limitedReader)
    if err != nil {
        return nil, fmt.Errorf("failed to read response: %w", err)
    }

    // Parse GraphQL response
    var gqlResp Response
    if err := json.Unmarshal(respBody, &gqlResp); err != nil {
        // Not valid JSON - might be error page
        return &Response{
            StatusCode: resp.StatusCode,
            RawBody:    string(respBody),
            RequestID:  requestID,
        }, nil
    }

    gqlResp.StatusCode = resp.StatusCode
    gqlResp.RequestID = requestID

    return &gqlResp, nil
}

func generateRequestID() string {
    b := make([]byte, 16)
    rand.Read(b)
    return hex.EncodeToString(b[0:4]) + "-" +
        hex.EncodeToString(b[4:6]) + "-" +
        hex.EncodeToString(b[6:8]) + "-" +
        hex.EncodeToString(b[8:10]) + "-" +
        hex.EncodeToString(b[10:16])
}

func injectAuth(req *http.Request, authInfo *auth.AuthInfo) {
    switch authInfo.Method {
    case "bearer", "basic":
        req.Header.Set("Authorization", authInfo.Value)
    case "api_key":
        if authInfo.Location == "header" {
            req.Header.Set(authInfo.KeyName, authInfo.Value)
        } else if authInfo.Location == "query" {
            q := req.URL.Query()
            q.Set(authInfo.KeyName, authInfo.Value)
            req.URL.RawQuery = q.Encode()
        }
    }
}

// Response represents a GraphQL response
type Response struct {
    Data       interface{}  `json:"data,omitempty"`
    Errors     []GQLError   `json:"errors,omitempty"`
    Extensions interface{}  `json:"extensions,omitempty"`
    StatusCode int          `json:"-"`
    RawBody    string       `json:"-"`
    RequestID  string       `json:"-"`
}

type GQLError struct {
    Message    string                 `json:"message"`
    Locations  []Location             `json:"locations,omitempty"`
    Path       []interface{}          `json:"path,omitempty"`
    Extensions map[string]interface{} `json:"extensions,omitempty"`
}

type Location struct {
    Line   int `json:"line"`
    Column int `json:"column"`
}
```

---

## 7. Anti-Patterns to Avoid

### 7.1 Query Construction Anti-Patterns

```go
// ANTI-PATTERN 1: String interpolation for user input
// RISK: GraphQL injection
query := fmt.Sprintf(`query { user(id: "%s") { email } }`, userID)

// ANTI-PATTERN 2: Using reflect/eval for query building
// RISK: Code injection, unpredictable behavior
query := reflect.ValueOf(queryTemplate).Call(args)

// ANTI-PATTERN 3: Concatenating multiple user inputs
// RISK: Injection via any input
query := "query { " + userField + "(id: " + userID + ") { " + userSelection + " } }"

// ANTI-PATTERN 4: Not validating variable names
// RISK: Variable injection
variables[untrustedName] = untrustedValue
```

### 7.2 Schema Handling Anti-Patterns

```go
// ANTI-PATTERN 1: Reading schema without size limits
// RISK: OOM from large malicious schema
content, _ := io.ReadAll(resp.Body)

// ANTI-PATTERN 2: Not validating schema source
// RISK: Malicious schema injection
schema := gqlparser.MustLoadSchema(untrustedInput)

// ANTI-PATTERN 3: Using exec/eval for schema processing
// RISK: Code execution
exec.Command("graphql-tools", "process", schemaPath)

// ANTI-PATTERN 4: Trusting introspection response structure
// RISK: Malformed response exploitation
types := resp.Data.Schema.Types  // May panic or be manipulated
```

### 7.3 Credential Handling Anti-Patterns

```go
// ANTI-PATTERN 1: Logging credentials
// RISK: Credential exposure
log.Printf("Using token: %s", authInfo.Value)

// ANTI-PATTERN 2: Hardcoding tokens in templates
// RISK: Credential exposure in VCS
token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

// ANTI-PATTERN 3: Not using environment variables
// RISK: Credentials in config files
token: "sk_live_abcd1234..."

// ANTI-PATTERN 4: Sending credentials to LLM without redaction
// RISK: Credential exposure to third party
llm.Analyze(request)  // Contains auth header
```

### 7.4 Test Execution Anti-Patterns

```go
// ANTI-PATTERN 1: Skipping production checks for GraphQL
// RISK: Accidental production testing
if isREST { checkProduction() }  // Missing GraphQL check

// ANTI-PATTERN 2: No rate limiting for batched queries
// RISK: DoS against target
for _, query := range batchQueries { execute(query) }

// ANTI-PATTERN 3: No response size limits
// RISK: OOM from large responses
body, _ := io.ReadAll(resp.Body)

// ANTI-PATTERN 4: Missing request IDs
// RISK: Cannot correlate audit logs
req.Header.Set("Content-Type", "application/json")  // No request ID
```

---

## 8. Trade-offs and Risk Acceptance

### 8.1 Decision: Use gqlparser Instead of graphql-go

**Alternatives Considered:**

| Library | Pros | Cons |
|---------|------|------|
| `vektah/gqlparser` | Pure parser, no server code, well-maintained | Less feature-rich |
| `graphql-go/graphql` | Full implementation | More attack surface, heavier |
| `99designs/gqlgen` | Code generation | Overkill for parsing |

**Decision:** Use `vektah/gqlparser/v2`
**Rationale:** Minimal attack surface (pure parser), widely used, maintained by Ariadne developers
**Risk Acceptance:** May need to implement some utilities manually

### 8.2 Decision: Parameterized Queries Only (No Query Building DSL)

**Alternatives Considered:**

| Approach | Pros | Cons |
|----------|------|------|
| Parameterized queries | Simple, safe, follows spec | Less flexible |
| Query builder DSL | Flexible, type-safe | More complex, injection risk |
| String templates | Very flexible | High injection risk |

**Decision:** Parameterized queries with static templates
**Rationale:** Lowest injection risk, matches how GraphQL clients work in production
**Risk Acceptance:** Templates are less flexible but security > flexibility for a security tool

### 8.3 Decision: Introspection Over Manual Schema

**Alternatives Considered:**

| Approach | Pros | Cons |
|----------|------|------|
| Introspection default | Automatic, always up-to-date | Requires enabled introspection |
| SDL file default | Works when introspection disabled | May be out of sync |
| Both with fallback | Best coverage | More complex |

**Decision:** Introspection by default, SDL via `--schema` flag
**Rationale:** Matches design document, provides flexibility
**Risk Acceptance:** Introspection responses from untrusted servers must be carefully validated

### 8.4 Residual Risks

| Risk | Likelihood | Impact | Mitigation | Residual |
|------|------------|--------|------------|----------|
| Query injection via template variables | Low | High | Parameterized queries | Very Low |
| OOM from large schema | Low | Medium | Size limits | Low |
| Credential logging | Medium | High | Redactor enforcement | Low |
| Production testing accident | Low | High | Existing controls | Very Low |
| Malicious introspection response | Low | Medium | Validation + limits | Low |

---

## Appendix A: Security Checklist for Implementation

### A.1 Query Construction Checklist

- [ ] All queries use `variables` map, never string interpolation
- [ ] Variable names validated against GraphQL spec regex
- [ ] Query templates validated with gqlparser before use
- [ ] Query complexity calculated and limited
- [ ] Query depth calculated and limited

### A.2 Schema Handling Checklist

- [ ] File paths validated (no path traversal)
- [ ] File size checked before reading
- [ ] Response size limited with `io.LimitReader`
- [ ] Schema parsed only with `gqlparser` (no eval/exec)
- [ ] Type and field counts validated
- [ ] Depth validated

### A.3 Credential Handling Checklist

- [ ] Auth tokens loaded from environment variables
- [ ] Hardcoded credential detection active
- [ ] All logging passes through `Redactor.Redact()`
- [ ] LLM submissions use `RedactForLLM()`
- [ ] File permissions warned if world-readable

### A.4 Test Execution Checklist

- [ ] Production URL detection applied
- [ ] Internal IP blocking applied
- [ ] Rate limiting applied (accounting for batched queries)
- [ ] Request ID added to all requests
- [ ] Response size limited
- [ ] Timeout configured

### A.5 Template Security Checklist

- [ ] YAML size limit enforced (1MB)
- [ ] YAML depth limit enforced (20)
- [ ] Query templates are static (not user-provided)
- [ ] Variables are validated before use

---

## Metadata

```json
{
  "agent": "security-lead",
  "output_type": "security-assessment",
  "timestamp": "2026-02-02T00:00:00Z",
  "feature_directory": "/workspaces/praetorian-dev/modules/hadrian/.feature-development",
  "skills_invoked": [
    "using-skills",
    "discovering-reusable-code",
    "semantic-code-operations",
    "calibrating-time-estimates",
    "enforcing-evidence-based-analysis",
    "gateway-security",
    "persisting-agent-outputs",
    "brainstorming",
    "writing-plans",
    "verifying-before-completion",
    "adhering-to-dry",
    "adhering-to-yagni"
  ],
  "library_skills_read": [
    ".claude/skill-library/security/auth-implementation-patterns/SKILL.md",
    ".claude/skill-library/security/authorization-testing/SKILL.md",
    ".claude/skill-library/security/defense-in-depth/SKILL.md",
    ".claude/skill-library/security/secrets-management/SKILL.md",
    ".claude/skill-library/security/reviewing-backend-security/SKILL.md"
  ],
  "source_files_verified": [
    "/workspaces/praetorian-dev/modules/hadrian/pkg/auth/auth.go:36-179",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/templates/template.go:1-158",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/templates/execute.go:1-539",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/reporter/redactor.go:1-131",
    "/workspaces/praetorian-dev/modules/hadrian/internal/http/client.go:1-100",
    "/workspaces/praetorian-dev/modules/hadrian/pkg/runner/production.go:1-129",
    "/workspaces/praetorian-dev/modules/hadrian/CLAUDE.md",
    "/workspaces/praetorian-dev/modules/hadrian/docs/architecture.md",
    "/workspaces/praetorian-dev/modules/hadrian/.feature-development/brainstorming.md"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "backend-developer",
    "context": "Security assessment complete. Implement GraphQL module following the secure code patterns in Section 6 and avoiding anti-patterns in Section 7. Use checklist in Appendix A for verification."
  }
}
```
