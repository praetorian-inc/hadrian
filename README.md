<img width="2944" height="1440" alt="hadrian" src="https://github.com/user-attachments/assets/b47c85d7-6020-4ddb-85c2-4baf9c9d6a24" />

# Hadrian

**API Security Testing Framework**

Hadrian is a security testing framework for REST APIs that tests for OWASP API vulnerabilities and custom security issues using role-based authorization testing.

## Features

- **OWASP API Top 10 Coverage**: Test for BOLA, broken authentication, injection, and more
- **Role-Based Testing**: Define roles with permissions and test cross-role access
- **Template-Driven**: YAML templates for customizable security tests
- **Multiple Output Formats**: Terminal, JSON, and Markdown reports
- **Production Safety**: Built-in safeguards against testing production systems
- **Proxy Support**: Route traffic through Burp Suite or other proxies
- **LLM Triage**: Optional AI-powered finding analysis (Anthropic, OpenAI, Ollama)

## Installation

```bash
# Build from source
cd modules/hadrian
go build -o hadrian ./cmd/hadrian

# Or install directly
go install github.com/praetorian-inc/hadrian/cmd/hadrian@latest
```

## Quick Start

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
    permissions:
      - "read:users:all"
      - "write:users:all"
      - "delete:users:all"
      - "read:posts:all"
      - "write:posts:all"
      - "execute:admin:all"

  - name: moderator
    permissions:
      - "read:users:all"
      - "read:posts:all"
      - "write:posts:all"
      - "delete:posts:all"

  - name: user
    permissions:
      - "read:users:own"
      - "read:posts:all"
      - "write:posts:own"

  - name: guest
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

Run security tests against an API.

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

### parse command

Parse and display API specification details.

```bash
hadrian parse <api-spec-file>
```

### version command

Show Hadrian version.

```bash
hadrian version
```

## Writing Custom Templates

Create YAML templates in the `templates/owasp/` directory:

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

## Environment Variables

- `HADRIAN_TEMPLATES` - Custom templates directory path
- `ANTHROPIC_API_KEY` - Anthropic API key for LLM triage
- `OPENAI_API_KEY` - OpenAI API key for LLM triage
- `OLLAMA_HOST` - Ollama host for local LLM triage

## Output Examples

### Terminal Output

```
[INFO] Loaded 12 templates from ./templates/owasp
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
- **Rate Limiting**: Default rate limit of 5 req/s prevents overwhelming target systems
- **Audit Logging**: All requests are logged for compliance and debugging
- **Proxy Support**: Use `--proxy` with Burp Suite for manual verification

## OWASP API Security Top 10 Coverage

| Category | Name | Status |
|----------|------|--------|
| API1:2023 | Broken Object Level Authorization | ✅ |
| API2:2023 | Broken Authentication | ✅ |
| API3:2023 | Broken Object Property Level Authorization | ✅ |
| API4:2023 | Unrestricted Resource Consumption | ⏳ |
| API5:2023 | Broken Function Level Authorization | ✅ |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | ⏳ |
| API7:2023 | Server Side Request Forgery | ✅ |
| API8:2023 | Security Misconfiguration | ✅ |
| API9:2023 | Improper Inventory Management | ✅ |
| API10:2023 | Unsafe Consumption of APIs | ⏳ |

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.
