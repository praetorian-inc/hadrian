# GraphQL Security Testing Module - Design Document

**Feature:** GraphQL API Security Testing Module
**Date:** 2026-02-02
**Status:** Design Complete (Phase 6)

## Problem Statement

Hadrian currently only tests REST APIs, but many modern applications use GraphQL. GraphQL has unique security challenges (introspection disclosure, query depth attacks, field-level authorization) that REST-focused testing misses.

**Users:** Security engineers conducting penetration tests on GraphQL APIs.

**Success:** A security engineer can point Hadrian at a GraphQL endpoint (or provide a schema file), automatically discover the schema, test authorization boundaries at field/type level, and identify GraphQL-specific vulnerabilities.

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Schema source | Introspection by default, SDL via `--schema` | Flexibility for both enabled and disabled introspection |
| Operation mapping | One Operation per Query/Mutation | Aligns with existing model, simpler implementation |
| Permission format | Extend existing: `read:User.email:own` | Reuses existing role system, familiar syntax |
| Test application | DVGA | Mature, well-documented, comprehensive vulnerabilities |
| CLI structure | Subcommands: `hadrian test graphql`, `hadrian test rest` | Clean, explicit, extensible |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI Layer                               │
│   hadrian test graphql --target URL --schema file --roles ...   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                      Plugin Registry                            │
│   plugins.Get(ProtocolGraphQL) → GraphQLPlugin                  │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                    GraphQL Plugin                               │
│   ├── Introspection Client (fetch schema from endpoint)         │
│   ├── SDL Parser (parse .graphql files)                         │
│   └── Operation Converter (schema → model.Operation[])          │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                  Existing Runner                                │
│   For each operation × template × role:                         │
│   ├── Query Builder (construct GraphQL query)                   │
│   ├── Executor (HTTP POST to /graphql)                          │
│   ├── Matchers (evaluate response)                              │
│   └── Reporter (output findings)                                │
└─────────────────────────────────────────────────────────────────┘
```

## CLI Design

### GraphQL Testing

```bash
hadrian test graphql \
  --target https://api.example.com \   # Base URL (required)
  --schema schema.graphql \            # Optional: SDL file (otherwise introspect)
  --endpoint /graphql \                # GraphQL endpoint path (default: /graphql)
  --depth-limit 10 \                   # Max query depth for DoS testing
  --complexity-limit 1000 \            # Max complexity score for DoS testing
  --roles roles.yaml \
  --auth auth.yaml \
  --allow-internal \
  --verbose
```

### REST Testing

```bash
hadrian test rest \
  --api openapi.json \                 # OpenAPI spec (required)
  --roles roles.yaml \
  --auth auth.yaml \
  --allow-internal \
  --verbose
```

No auto-detect - explicit subcommands only.

## Permission Format

Extends existing `<action>:<object>:<scope>` for field-level:

```yaml
roles:
  - name: admin
    level: 100
    permissions:
      - "read:User.*:all"        # All User fields for all users
      - "write:User.*:all"
      - "execute:deleteUser:all" # Mutation access

  - name: user
    level: 10
    permissions:
      - "read:User.id:own"       # Can read own id
      - "read:User.email:own"    # Can read own email
      - "read:User.role:none"    # Cannot read role field
      - "execute:updateProfile:own"
```

## GraphQL Attack Patterns

| Attack | Description | Template |
|--------|-------------|----------|
| Introspection Disclosure | Check if introspection enabled in production | graphql-introspection-disclosure.yaml |
| Query Depth Attack | Deeply nested query for DoS | graphql-depth-attack.yaml |
| Query Complexity Attack | Many expensive fields | graphql-complexity-attack.yaml |
| Batching Attack | 100+ queries via aliases | graphql-batching-attack.yaml |
| Field Suggestion | Invalid field reveals schema | graphql-field-suggestion.yaml |
| BOLA | Cross-user data access | graphql-bola-user-access.yaml |
| BFLA | Unauthorized mutation access | graphql-bfla-mutation.yaml |

## BOLA Template Example

```yaml
id: graphql-bola-user-access
info:
  name: "GraphQL BOLA - Cross-User Data Access"
  category: "API1:2023"
  severity: "HIGH"
  test_pattern: "mutation"

role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"

test_phases:
  setup:
    - graphql:
        query: |
          query GetMyProfile {
            me { id email orders { id total } }
          }
      auth: "victim"
      store_response_fields:
        victim_id: "data.me.id"
        victim_order_id: "data.me.orders[0].id"

    - graphql:
        query: |
          query GetMyProfile {
            me { id }
          }
      auth: "attacker"
      store_response_fields:
        attacker_id: "data.me.id"

  attack:
    graphql:
      query: |
        query GetUser($id: ID!) {
          user(id: $id) { id email orders { id total } }
        }
      variables:
        id: "{victim_id}"
    auth: "attacker"

  verify:
    detection:
      success_indicators:
        - type: status_code
          status_code: 200
        - type: word
          words: ["{victim_id}"]
          part: "body"
      vulnerability_pattern: "attacker_accessed_victim_data"
```

## Files to Create

### Core Plugin

| File | Purpose |
|------|---------|
| `cmd/hadrian/test_graphql.go` | GraphQL subcommand |
| `cmd/hadrian/test_rest.go` | REST subcommand (refactor) |
| `pkg/plugins/graphql/plugin.go` | Plugin implementation |
| `pkg/plugins/graphql/schema_parser.go` | SDL/introspection parsing |
| `pkg/plugins/graphql/operation_converter.go` | Schema → Operations |

### GraphQL Package

| File | Purpose |
|------|---------|
| `pkg/graphql/schema.go` | Schema type definitions |
| `pkg/graphql/introspection.go` | Introspection client |
| `pkg/graphql/query_builder.go` | Query construction |
| `pkg/graphql/attacks.go` | Attack pattern implementations |

### Templates

| File | Purpose |
|------|---------|
| `templates/graphql/introspection-disclosure.yaml` | Check introspection |
| `templates/graphql/depth-attack.yaml` | Query depth DoS |
| `templates/graphql/complexity-attack.yaml` | Complexity DoS |
| `templates/graphql/bola-user-access.yaml` | BOLA testing |
| `templates/graphql/bfla-mutation.yaml` | BFLA testing |

### Test Infrastructure

| File | Purpose |
|------|---------|
| `testdata/dvga/docker-compose.yaml` | DVGA container |
| `testdata/dvga/dvga-roles.yaml` | Role definitions |
| `testdata/dvga/dvga-auth.yaml` | Auth tokens |
| `testdata/dvga/README.md` | Setup instructions |

## Dependencies

- `github.com/vektah/gqlparser/v2` - GraphQL SDL parsing (to be added to go.mod)

## Test Application

**DVGA (Damn Vulnerable GraphQL Application)** provides:
- Introspection enabled
- No query depth limit
- BOLA via `user(id: $id)` query
- BFLA via admin-only mutations
- SQL injection in search
- DoS via batching

## Next Steps

1. **Phase 7:** Create detailed architecture plan with implementation tasks
2. **Phase 8:** Implement in batches per complexity assessment
3. **Phase 13:** Test against DVGA
