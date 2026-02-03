# Discovery Report

**Feature:** GraphQL API Security Testing Module
**Work Type:** LARGE
**Feature Type:** Backend (Go)
**Discovered:** 2026-02-02

## Executive Summary

Hadrian is a well-architected, extensible API security testing framework (~5,725 LOC) with a plugin-based, template-driven design. The codebase **already includes a GraphQL protocol placeholder** (`ProtocolGraphQL = "graphql"`) in `pkg/plugins/plugin.go`, indicating this extension was anticipated.

## Technologies Detected

### Backend
- Go 1.24.0 (toolchain 1.24.2)
- Cobra (CLI framework)
- kin-openapi (OpenAPI parsing - REST only)
- gopkg.in/yaml.v3 (YAML parsing)
- golang.org/x/time/rate (Rate limiting)
- Standard library: crypto/tls, net/http, regexp, sync, context

### Testing
- stretchr/testify (assertions)
- httptest (HTTP mocking)
- Race detection ready (`-race` flag)

## Core Architecture

### Package Responsibilities

| Package | LOC | Responsibility |
|---------|-----|----------------|
| `pkg/runner/` | 500 | CLI orchestration, rate limiting, test execution |
| `pkg/templates/` | 1000 | YAML template parsing, compilation, HTTP execution |
| `pkg/owasp/` | 600 | OWASP security patterns, mutation testing |
| `pkg/plugins/rest/` | 320 | REST/OpenAPI plugin (reference implementation) |
| `pkg/model/` | 100 | Data structures (Finding, Operation, Evidence) |
| `pkg/matchers/` | 250 | Response matching (status, word, regex) |
| `pkg/roles/` | 300 | Permission model (`<action>:<object>:<scope>`) |
| `pkg/reporter/` | 400 | Output formatting (terminal, JSON, markdown) |
| `pkg/auth/` | 150 | Authentication config and token handling |

### Key Interfaces

```go
// Plugin interface - GraphQL will implement this
type Plugin interface {
    Name() string
    Type() Protocol
    CanParse(input []byte, filename string) bool
    Parse(input []byte) (*model.APISpec, error)
}

// Already defined in pkg/plugins/plugin.go:
const (
    ProtocolREST    Protocol = "rest"
    ProtocolGraphQL Protocol = "graphql"  // PLACEHOLDER EXISTS!
    ProtocolGRPC    Protocol = "grpc"
    ProtocolSOAP    Protocol = "soap"
)
```

### Execution Flow

1. CLI parses flags → Config struct
2. Plugin auto-detects protocol from input file
3. Plugin parses spec → `model.APISpec` with Operations
4. Load roles config → `roles.RoleConfig`
5. Load/compile YAML templates → `templates.CompiledTemplate[]`
6. For each operation × template × role:
   - Check endpoint selector match
   - Execute HTTP test
   - Evaluate detection rules
   - Collect findings
7. Optional LLM triage
8. Generate report

## Existing Patterns to Reuse

| Pattern | Location | How to Reuse |
|---------|----------|--------------|
| Plugin registration | `pkg/plugins/plugin.go` | Self-register via `init()` |
| REST plugin | `pkg/plugins/rest/plugin.go` | Reference implementation |
| Template system | `pkg/templates/` | Extend for GraphQL queries |
| Role-based testing | `pkg/roles/` | Adapt for field-level permissions |
| Mutation testing | `pkg/owasp/mutation.go` | Reuse 3-phase pattern |
| Rate limiting | `pkg/runner/ratelimit*.go` | Works for any HTTP |
| Matchers | `pkg/matchers/` | Works as-is |
| Reporters | `pkg/reporter/` | Works as-is |

## Files to Modify

| File | Change Type | Reason |
|------|-------------|--------|
| `cmd/hadrian/main.go` | Modify | Add GraphQL-specific CLI flags |
| `pkg/runner/run.go` | Modify | Protocol detection enhancement |
| `pkg/model/operation.go` | Modify | Add GraphQL operation types |
| `pkg/templates/template.go` | Modify | Add GraphQL template fields |

## New Files to Create

### Core GraphQL Plugin
| File | Purpose |
|------|---------|
| `pkg/plugins/graphql/plugin.go` | Main plugin implementation |
| `pkg/plugins/graphql/schema_parser.go` | SDL and introspection parsing |
| `pkg/plugins/graphql/operation_converter.go` | Convert GraphQL types → Operations |
| `pkg/plugins/graphql/query_builder.go` | Dynamic query construction |
| `pkg/plugins/graphql/plugin_test.go` | Plugin unit tests |

### GraphQL Security Testing
| File | Purpose |
|------|---------|
| `pkg/graphql/schema.go` | GraphQL schema type definitions |
| `pkg/graphql/introspection.go` | Introspection result handling |
| `pkg/graphql/permissions.go` | Field-level permission testing |
| `pkg/graphql/attacks.go` | GraphQL-specific attack patterns |
| `pkg/graphql/executor.go` | GraphQL query execution |

### Templates
| File | Purpose |
|------|---------|
| `templates/graphql/*.yaml` | GraphQL security test templates |

### Test Data
| File | Purpose |
|------|---------|
| `testdata/graphql/` | Test schemas, introspection results |

## Dependencies Needed

No new Go dependencies required for basic implementation. Optional:
- `github.com/graphql-go/graphql` - For advanced schema handling
- `github.com/vektah/gqlparser/v2` - GraphQL SDL parsing (recommended)

## Constraints & Risks

1. **No existing GraphQL parser** in go.mod - need to add or implement
2. **Introspection vs SDL** - must support both input formats
3. **Query complexity** - GraphQL queries can be deeply nested
4. **Field-level permissions** - more granular than REST endpoints
5. **Batching attacks** - GraphQL allows multiple operations per request

## Integration Points

### CLI Integration
```bash
# New flags needed:
hadrian test \
  --graphql \                    # Enable GraphQL mode
  --schema schema.graphql \      # SDL file (when introspection disabled)
  --graphql-endpoint /graphql \  # Endpoint path (default: /graphql)
  --depth-limit 10 \             # Max query depth for DoS testing
  --complexity-limit 1000        # Max complexity for DoS testing
```

### Template Integration
```yaml
# Extended template format for GraphQL:
graphql:
  query: |
    query GetUser($id: ID!) {
      user(id: $id) {
        id
        email
        role
      }
    }
  variables:
    id: "{{victim_id}}"
  operation_name: "GetUser"
```

### Roles Integration
```yaml
# GraphQL field-level permissions:
roles:
  - name: admin
    permissions:
      - "read:User.*:all"       # All User fields
      - "write:User.*:all"
  - name: user
    permissions:
      - "read:User.id:own"      # Only own id
      - "read:User.email:own"   # Only own email
      - "read:User.role:none"   # Cannot read role field
```

## Estimated Scope

- **Files to modify:** 4-5
- **Files to create:** 15-20
- **Test files:** 10-15
- **Templates:** 10-15
- **Estimated LOC:** 2,500-3,500

## Test Application Requirement

**Note:** Need a vulnerable GraphQL application for dynamic testing, similar to how crAPI is used for REST API testing. Options:
1. DVGA (Damn Vulnerable GraphQL Application)
2. GraphQL-specific test server in testdata/
3. Custom vulnerable GraphQL server

## Next Steps

1. Phase 4: Map detected technologies to skills
2. Phase 5: Assess complexity and execution strategy
3. Phase 6: Brainstorm design with user input
4. Phase 7: Create detailed architecture plan
