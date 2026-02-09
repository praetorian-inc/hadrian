# Hadrian: API Security Testing Framework

[![CI](https://github.com/praetorian-inc/hadrian/actions/workflows/ci.yml/badge.svg)](https://github.com/praetorian-inc/hadrian/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/praetorian-inc/hadrian)](https://goreportcard.com/report/github.com/praetorian-inc/hadrian)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Hadrian tests REST, GraphQL, and gRPC APIs for OWASP API Security Top 10 vulnerabilities using role-based authorization testing and YAML-driven templates. It takes an API specification and a roles configuration, then systematically tests every endpoint against every role combination to find broken object-level authorization (BOLA), broken authentication, broken function-level authorization (BFLA), and other access control flaws.

Built for penetration testers and security engineers who need to validate API authorization logic during authorized security assessments.

## Table of Contents

- [Why Hadrian](#why-hadrian)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Files](#configuration-files)
- [CLI Reference](#cli-reference)
- [Writing Custom Templates](#writing-custom-templates)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Why Hadrian

API authorization testing is tedious and error-prone when done manually. For an API with 20 endpoints, 4 roles, and 3 HTTP methods, a tester faces hundreds of request-role combinations to verify. Missing even one combination can leave a critical BOLA or privilege escalation vulnerability unreported.

Existing approaches have limitations:

- **Manual testing** with Burp Suite or Postman requires crafting individual requests for each endpoint-role pair, which doesn't scale and is prone to incomplete coverage
- **Generic DAST scanners** send malformed input to find injection flaws but don't understand role-based authorization or ownership semantics
- **Custom scripts** are written per engagement, aren't reusable across clients, and lack structured reporting

Hadrian takes a different approach: you define your roles and their permissions declaratively, point it at an API specification (OpenAPI for REST, schema introspection for GraphQL, proto definitions for gRPC), and it systematically tests every endpoint against every role combination using YAML templates that encode OWASP vulnerability patterns. The templates are reusable across engagements, and the role-permission model means Hadrian understands which access patterns should be allowed and which indicate a vulnerability.

## How It Works

Hadrian uses a template-driven pipeline that matches security test patterns against API endpoints and role combinations:

```
API Spec ──────┐
(OpenAPI,       ├──▶ Template Matching ──▶ Execution ──▶ Detection ──▶ Report
 GraphQL,      │    (endpoint_selector    (role-based    (success/     (terminal,
 gRPC proto) ──┘      + role_selector)     requests)     failure       JSON, MD)
Roles Config ──────                                       indicators)
YAML Templates ────
```

1. **Parse** the API specification into a list of operations (REST endpoints, GraphQL queries/mutations, or gRPC methods)
2. **Load** the roles configuration with permissions in `<action>:<object>:<scope>` format
3. **Match** each YAML template's `endpoint_selector` and `role_selector` against operations and roles
4. **Execute** HTTP requests with attacker/victim role credentials substituted into the template
5. **Detect** vulnerabilities by evaluating response status codes and body patterns against success/failure indicators
6. **Report** findings with severity, evidence, and attacker/victim role context

## Features

- **Multi-Protocol**: Supports REST, GraphQL, and gRPC APIs
- **OWASP API Top 10 Coverage**: Test for BOLA and broken authentication
- **Role-Based Testing**: Define roles with permissions and test cross-role access
- **Template-Driven**: YAML templates for customizable security tests
- **Multiple Output Formats**: Terminal, JSON, and Markdown reports
- **Production Safety**: Built-in safeguards against testing production systems
- **Adaptive Rate Limiting**: Proactive request throttling with reactive backoff on 429/503 responses
- **Proxy Support**: Route traffic through Burp Suite or other proxies
- **LLM Triage**: Optional AI-powered finding analysis (Anthropic, OpenAI, Ollama)

## Installation

### From source

```bash
go install github.com/praetorian-inc/hadrian/cmd/hadrian@latest
```

### From releases

Download the latest binary from the [Releases](https://github.com/praetorian-inc/hadrian/releases) page.

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

## Tutorial

You can find a tutorial that uses Hadrian to test crAPI at [testdata/crapi/README.md](testdata/crapi/README.md)

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

Create YAML templates in the `templates/owasp/` directory.

**Template Execution Order**: Templates are executed in **alphabetical order by filename**. To control execution order, prefix filenames with numbers (e.g., `01-read-tests.yaml`, `02-write-tests.yaml`, `03-delete-tests.yaml`). This is useful when some tests are destructive and should run last.

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

## Development

### Prerequisites

- [Go 1.24+](https://go.dev/dl/)
- [golangci-lint](https://golangci-lint.run/welcome/install/)

### Getting started

```bash
git clone https://github.com/praetorian-inc/hadrian.git
cd hadrian
make build
```

### Common commands

```bash
make build       # Build the binary
make test        # Run tests
make lint        # Run linters
make fmt         # Format code
make check       # Run all checks (fmt, vet, lint, test)
```

### Testing

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
- **Adaptive Rate Limiting**:
  - Proactive: Limits outgoing requests to configured rate (default 5 req/s)
  - Reactive: Automatically backs off when detecting rate limit responses (429/503)
  - Supports exponential and fixed backoff strategies
  - Honors server `Retry-After` headers when present
- **Audit Logging**: All requests are logged for compliance and debugging
- **Proxy Support**: Use `--proxy` with Burp Suite for manual verification

## Rate Limiting

Hadrian includes comprehensive rate limiting to prevent overwhelming target APIs:

### Proactive Rate Limiting

Limits outgoing requests to a configured rate (default 5 requests/second):

```bash
# Set custom rate limit
hadrian test --api api.yaml --roles roles.yaml --rate-limit 10.0
```

### Reactive Backoff

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

### Backoff Strategies

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| **exponential** (default) | Wait doubles each retry: 1s, 2s, 4s, 8s... | Most APIs |
| **fixed** | Constant wait time between retries | APIs with fixed rate windows |

The backoff respects the server's `Retry-After` header when present, capping at the configured `--rate-limit-max-wait`.

## OWASP API Security Top 10 Coverage

| Category | Name | Status |
|----------|------|--------|
| API1:2023 | Broken Object Level Authorization | ✅ |
| API2:2023 | Broken Authentication | ✅ |
| API3:2023 | Broken Object Property Level Authorization | ⏳ |
| API4:2023 | Unrestricted Resource Consumption | ⏳ |
| API5:2023 | Broken Function Level Authorization | ⏳ |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | ⏳ |
| API7:2023 | Server Side Request Forgery | ⏳ |
| API8:2023 | Security Misconfiguration | ⏳ |
| API9:2023 | Improper Inventory Management | ⏳ |
| API10:2023 | Unsafe Consumption of APIs | ⏳ |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please ensure all CI checks pass before requesting review.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## About Praetorian

[Praetorian](https://www.praetorian.com/) is a cybersecurity company that helps organizations secure their most critical assets through offensive security services and the [Praetorian Guard](https://www.praetorian.com/guard) attack surface management platform.
