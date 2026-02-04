# Hadrian

**API Security Testing Framework**

Hadrian is a security testing framework for REST and GraphQL APIs that tests for OWASP API vulnerabilities and custom security issues using role-based authorization testing.

## Features

- **OWASP API Top 10 Coverage**: Test for BOLA, broken authentication, and more
- **Role-Based Testing**: Define roles with permissions and test cross-role access
- **Template-Driven**: YAML templates for customizable security tests
- **REST & GraphQL Support**: Comprehensive testing for both API types
- **Multiple Output Formats**: Terminal, JSON, and Markdown reports
- **Production Safety**: Built-in safeguards against testing production systems
- **Adaptive Rate Limiting**: Proactive request throttling with reactive backoff on 429/503 responses
- **Proxy Support**: Route traffic through Burp Suite or other proxies
- **LLM Triage**: Optional AI-powered finding analysis (Anthropic, OpenAI, Ollama)

## OWASP API Security Top 10 Coverage

| Category | Name | REST | GraphQL |
|----------|------|------|---------|
| API1:2023 | Broken Object Level Authorization | ✅ | ✅ |
| API2:2023 | Broken Authentication | ✅ | ✅ |
| API3:2023 | Broken Object Property Level Authorization | ✅ | ✅ |
| API4:2023 | Unrestricted Resource Consumption | ❌ | ✅ |
| API5:2023 | Broken Function Level Authorization | ✅ | ✅ |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | ❌ | ❌ |
| API7:2023 | Server Side Request Forgery | ❌ | ❌ |
| API8:2023 | Security Misconfiguration | ✅ | ✅ |
| API9:2023 | Improper Inventory Management | ✅ | ❌ |
| API10:2023 | Unsafe Consumption of APIs | ❌ | ❌ |

**Legend:** ✅ = Supported, ❌ = Not Supported

**REST templates:** 8 templates in `templates/rest/`
**GraphQL templates:** 13 templates in `templates/graphql/`

## Table of Contents

- [OWASP Coverage](#owasp-api-security-top-10-coverage)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Tutorials](#tutorials)
- [Configuration Files](#configuration-files)
- [CLI Reference](#cli-reference)
- [GraphQL Testing](#graphql-testing)
- [Writing Custom Templates](#writing-custom-templates)
- [Output Examples](#output-examples)
- [Testing](#testing)
- [Security & Rate Limiting](#security-considerations)
- [Environment Variables](#environment-variables)
- [License](#license)
- [Contributing](#contributing)

## Installation

```bash
# Build from source
go build -o hadrian ./cmd/hadrian

# Or install directly
go install github.com/praetorian-inc/hadrian/cmd/hadrian@latest
```

## Quick Start

### REST API Testing

```bash
# Basic security test
hadrian test --api api.yaml --roles roles.yaml

# With authentication
hadrian test --api api.yaml --roles roles.yaml --auth auth.yaml

# Test specific OWASP categories
hadrian test --api api.yaml --roles roles.yaml --owasp API1,API2,API5

# Dry run (show what would be tested)
hadrian test --api api.yaml --roles roles.yaml --dry-run

# Verbose output
hadrian test --api api.yaml --roles roles.yaml --verbose

# Output to JSON file
hadrian test --api api.yaml --roles roles.yaml --output json --output-file report.json
```

### GraphQL API Testing

```bash
# Basic scan (uses introspection)
hadrian test graphql --target https://api.example.com

# With SDL schema file
hadrian test graphql --target https://api.example.com --schema schema.graphql

# With authentication for authorization testing
hadrian test graphql --target https://api.example.com --auth auth.yaml --roles roles.yaml
```

## Tutorials

- **REST API Testing**: [crAPI Tutorial](testdata/crapi/README.md) - Test OWASP crAPI (intentionally vulnerable REST API)
- **GraphQL API Testing**: [DVGA Tutorial](testdata/dvga/README.md) - Test DVGA (Damn Vulnerable GraphQL Application)

## Configuration Files

### API Specification (api.yaml)

Hadrian supports OpenAPI 3.0 specifications:

```yaml
openapi: "3.0.0"
info:
  title: My API
  version: "1.0.0"
servers:
  - url: "https://api.example.com"
paths:
  /api/users:
    get:
      summary: List users
      security:
        - bearerAuth: []
      responses:
        "200":
          description: Success
  /api/users/{id}:
    get:
      summary: Get user by ID
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: Success
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
```

### Roles Configuration (roles.yaml)

Define your application's roles and their permissions:

```yaml
objects:
  - users
  - posts
  - admin

roles:
  - name: admin
    level: 100          # Explicit privilege level (higher = more privilege)
    permissions:
      - "read:users:all"
      - "write:users:all"
      - "delete:users:all"
      - "read:posts:all"
      - "write:posts:all"
      - "execute:admin:all"

  - name: moderator
    level: 50           # Mid-level privilege
    permissions:
      - "read:users:all"
      - "read:posts:all"
      - "write:posts:all"
      - "delete:posts:all"

  - name: user
    level: 10           # Basic user privilege
    permissions:
      - "read:users:own"
      - "read:posts:all"
      - "write:posts:own"

  - name: guest
    level: 0            # No privilege (unauthenticated)
    permissions: []

endpoints:
  - path: "/api/users/{id}"
    object: users
    owner_field: id
  - path: "/api/posts/{id}"
    object: posts
    owner_field: author_id
```

**Permission Format**: `<action>:<object>:<scope>`

- **Actions**: `read`, `write`, `delete`, `execute`, `*`
- **Objects**: Defined in the `objects` list
- **Scopes**: `public`, `own`, `org`, `all`, `*`

**Role Level**: The `level` field defines explicit privilege levels for BOLA testing:

- Higher values indicate more privileged roles (e.g., admin: 100)
- Used by `role_selector` to determine "lower" vs "higher" permission levels
- Prevents incorrect classification when admins have fewer but more powerful permissions (e.g., `*:*:all`)

### GraphQL Schema (schema.graphql)

For GraphQL testing, Hadrian can discover schemas via introspection or load them from SDL files:

```graphql
# Example GraphQL SDL schema file
type Query {
  user(id: ID!): User
  users: [User!]!
  paste(id: ID!): Paste
  pastes: [Paste!]!
}

type Mutation {
  createUser(username: String!, password: String!): User
  login(username: String!, password: String!): AuthPayload
  createPaste(content: String!, title: String): Paste
}

type User {
  id: ID!
  username: String!
  email: String
}

type Paste {
  id: ID!
  title: String
  content: String!
  owner: User
}

type AuthPayload {
  accessToken: String!
  user: User
}
```

**Usage:**
- **Introspection (default)**: Hadrian queries the endpoint automatically
- **SDL File**: Use `--schema schema.graphql` when introspection is disabled

```bash
# With introspection (default)
hadrian test graphql --target https://api.example.com

# With SDL schema file
hadrian test graphql --target https://api.example.com --schema schema.graphql
```

### Authentication Configuration (auth.yaml)

Configure how to authenticate as each role:

```yaml
auth_method: bearer_token

roles:
  admin:
    token: "eyJhbGciOiJIUzI1NiIs..."
  moderator:
    token: "eyJhbGciOiJIUzI1NiIs..."
  user:
    token: "eyJhbGciOiJIUzI1NiIs..."
  guest:
    token: ""
```

## CLI Reference

### test command

Run security tests against a REST API.

```bash
hadrian test [flags]
```

**Required Flags:**
- `--api <file>` - API specification file (OpenAPI, Swagger, Postman)
- `--roles <file>` - Roles and permissions YAML file

**Optional Flags:**
- `--auth <file>` - Authentication configuration YAML file
- `--proxy <url>` - HTTP/HTTPS proxy URL (e.g., http://localhost:8080)
- `--ca-cert <file>` - CA certificate for proxy (Burp Suite)
- `--insecure` - Skip TLS verification (use with proxies)
- `--concurrency <n>` - Concurrent requests (default: 1, max: 10)
- `--rate-limit <n>` - Global rate limit in req/s (default: 5.0)
- `--rate-limit-backoff <type>` - Backoff type for rate limit retries: exponential, fixed (default: exponential)
- `--rate-limit-max-wait <duration>` - Maximum backoff wait time (default: 60s)
- `--rate-limit-max-retries <n>` - Maximum retry attempts on rate limit response (default: 5)
- `--rate-limit-status-codes <codes>` - Status codes that trigger rate limit retry (default: 429,503)
- `--timeout <n>` - Request timeout in seconds (default: 30)
- `--allow-production` - Allow testing production URLs
- `--allow-internal` - Allow testing internal/private IP addresses
- `--output <format>` - Output format: terminal, json, markdown (default: terminal)
- `--output-file <file>` - Write findings to file
- `--category <list>` - Test categories: owasp, custom (default: owasp)
- `--template <list>` - Specific template files to run
- `--owasp <list>` - OWASP API categories to test (e.g., API1,API2,API5,API9)
- `--verbose, -v` - Enable verbose logging output
- `--dry-run` - Show what would be tested without making requests
- `--audit-log <file>` - Audit log file (default: .hadrian/audit.log)

### test graphql command

Run security tests against a GraphQL API.

```bash
hadrian test graphql [flags]
```

**Required Flags:**
- `--target <url>` - Target base URL (e.g., https://api.example.com)

**Schema Source (choose one):**
- `--schema <file>` - GraphQL SDL schema file (`.graphql` or `.gql`)
- *(default)* - Uses introspection query to discover schema

**Authentication:**
- `--auth <file>` - Authentication configuration YAML file
- `--roles <file>` - Roles and permissions YAML file

**Security Limits:**
- `--depth-limit <n>` - Maximum query depth for DoS testing (default: 10)
- `--complexity-limit <n>` - Maximum complexity score for DoS testing (default: 1000)
- `--batch-size <n>` - Number of queries in batch attack tests (default: 100)

**Template Options:**
- `--templates <dir>` - GraphQL templates directory (e.g., templates/graphql)
- `--template <id>` - Filter templates by ID (can specify multiple)
- `--owasp <list>` - Filter by OWASP API Security category (e.g., API1,API2,API5)
- `--skip-builtin-checks` - Skip built-in security checks (introspection, depth, batching)

**Network Options:**
- `--proxy <url>` - HTTP/HTTPS proxy URL
- `--ca-cert <file>` - CA certificate for proxy
- `--insecure` - Skip TLS verification
- `--rate-limit <n>` - Rate limit in req/s (default: 5.0)
- `--timeout <n>` - Request timeout in seconds (default: 30)
- `--allow-internal` - Allow internal/private IP addresses
- `--allow-production` - Allow testing production URLs

**Output Options:**
- `--output <format>` - Output format: terminal, json, markdown (default: terminal)
- `--output-file <file>` - Write findings to file
- `--verbose` - Enable verbose logging
- `--dry-run` - Show what would be tested without making requests

**LLM Triage (optional):**
- `--llm-host <url>` - LLM service host for finding triage
- `--llm-model <model>` - LLM model name for triage
- `--llm-timeout <n>` - LLM request timeout in seconds (default: 30)
- `--llm-context <text>` - Additional context for LLM triage

### parse command

Parse and display API specification details for REST APIs.

```bash
hadrian parse <api-spec-file>
```

**Supported Formats:**
- OpenAPI 3.0/3.1 (YAML/JSON)
- Swagger 2.0 (YAML/JSON)
- Postman Collection v2.1

**Note:** The `parse` command is for REST API specifications only. For GraphQL, use `hadrian test graphql --schema <file>` to load SDL schema files.

### version command

Show Hadrian version.

```bash
hadrian version
```

## GraphQL Testing

Hadrian supports comprehensive GraphQL API security testing with 13 built-in templates covering OWASP API Security Top 10 categories. Features include:

- **Schema Discovery**: Automatic introspection or SDL file loading
- **Built-in Security Checks**: Introspection disclosure, query depth limits, batch query limits
- **Authorization Testing**: BOLA/BFLA testing with role-based authentication
- **DoS Protection Testing**: Depth attacks, alias attacks, circular fragments

For complete GraphQL documentation including example commands, security checks, and template development, see [docs/graphql.md](docs/graphql.md).

For a hands-on tutorial, see [DVGA Tutorial](testdata/dvga/README.md).

## Writing Custom Templates

Create YAML templates in the `templates/rest/` directory for REST APIs or `templates/graphql/` for GraphQL APIs.

**Template Execution Order**: Templates are executed in **alphabetical order by filename**. To control execution order, prefix filenames with numbers (e.g., `01-read-tests.yaml`, `02-write-tests.yaml`, `03-delete-tests.yaml`). This is useful when some tests are destructive and should run last.

### REST Template Example

```yaml
id: api1-bola-cross-user
info:
  name: "BOLA - Cross-User Resource Access"
  category: "API1:2023"
  severity: "HIGH"
  description: |
    Tests for Broken Object Level Authorization by attempting
    to access resources belonging to other users.

endpoint_selector:
  has_path_parameter: true
  requires_auth: true
  methods: ["GET", "PUT", "DELETE"]

role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"

http:
  - method: "{{method}}"
    path: "{{path}}"
    headers:
      Authorization: "{{attacker_auth}}"

detection:
  success_indicators:
    - type: status_code
      status_code: 200
    - type: body_contains
      pattern: "\"id\":"

  failure_indicators:
    - type: status_code
      status_code: 403
    - type: status_code
      status_code: 401
```

### Template Fields

- **endpoint_selector**: Filter which endpoints to test
  - `has_path_parameter`: Require path parameters (e.g., `/users/{id}`)
  - `requires_auth`: Require authentication
  - `methods`: HTTP methods to match

- **role_selector**: Define attacker/victim role combinations
  - `attacker_permission_level`: "lower", "higher", "all", "none"
  - `victim_permission_level`: "lower", "higher", "all"

- **detection**: How to identify vulnerabilities
  - `success_indicators`: Conditions indicating vulnerability found
  - `failure_indicators`: Conditions indicating proper protection

## Output Examples

### Terminal Output

```
[INFO] Loaded 12 templates from ./templates/rest
[INFO] Testing 8 operations against 4 roles

[FINDING] API1:2023 - BOLA - Cross-User Resource Access
  Severity: HIGH
  Endpoint: GET /api/users/{id}
  Attacker: user → Victim: admin
  Evidence: Status 200, body contains user data

[FINDING] API2:2023 - Broken Authentication
  Severity: CRITICAL
  Endpoint: POST /api/auth/token
  Evidence: Token issued without proper validation

Summary: 2 findings (1 CRITICAL, 1 HIGH)
```

### JSON Output

```json
{
  "findings": [
    {
      "id": "api1-bola-GET-api-users-id",
      "category": "API1:2023",
      "name": "BOLA - Cross-User Resource Access",
      "severity": "HIGH",
      "endpoint": "/api/users/{id}",
      "method": "GET",
      "attacker_role": "user",
      "victim_role": "admin",
      "is_vulnerability": true,
      "evidence": {
        "response": {
          "status_code": 200,
          "body": "{\"id\": \"123\", \"name\": \"admin\"}"
        }
      },
      "timestamp": "2025-01-24T18:30:00Z"
    }
  ],
  "stats": {
    "operations_tested": 8,
    "templates_loaded": 12,
    "roles_tested": 4,
    "findings_count": 2,
    "duration": "45.2s"
  }
}
```

## Testing

```bash
# Run unit tests
go test ./...

# Run integration tests
go test -tags=integration ./...

# Run with race detection
go test -race ./...

# Run specific package
go test ./pkg/runner/...
```

## Security Considerations

- **Production Safety**: By default, Hadrian blocks testing against production URLs and internal IPs
- **Audit Logging**: All requests are logged for compliance and debugging
- **Proxy Support**: Use `--proxy` with Burp Suite for manual verification

### Rate Limiting

Hadrian includes comprehensive rate limiting to prevent overwhelming target APIs:

**Proactive Rate Limiting**

Limits outgoing requests to a configured rate (default 5 requests/second):

```bash
# Set custom rate limit
hadrian test --api api.yaml --roles roles.yaml --rate-limit 10.0
```

**Reactive Backoff**

Automatically detects rate limit responses and implements retry with backoff:

```bash
# Use fixed backoff (constant 5s wait)
hadrian test --api api.yaml --roles roles.yaml --rate-limit-backoff fixed

# Configure max retries and wait time
hadrian test --api api.yaml --roles roles.yaml \
  --rate-limit-max-retries 10 \
  --rate-limit-max-wait 120s

# Custom status codes for rate limit detection
hadrian test --api api.yaml --roles roles.yaml \
  --rate-limit-status-codes 429,503,529
```

**Backoff Strategies**

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| **exponential** (default) | Wait doubles each retry: 1s, 2s, 4s, 8s... | Most APIs |
| **fixed** | Constant wait time between retries | APIs with fixed rate windows |

The backoff respects the server's `Retry-After` header when present, capping at the configured `--rate-limit-max-wait`.

## Environment Variables

- `HADRIAN_TEMPLATES` - Custom templates directory path
- `ANTHROPIC_API_KEY` - Anthropic API key for LLM triage
- `OPENAI_API_KEY` - OpenAI API key for LLM triage
- `OLLAMA_HOST` - Ollama host for local LLM triage

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.
