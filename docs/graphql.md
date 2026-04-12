# GraphQL Security Testing

Hadrian supports security testing of GraphQL APIs, including introspection detection, DoS vulnerability testing, and authorization bypass detection.

## Quick Start

```bash
# Basic GraphQL security scan (uses introspection)
hadrian test graphql --target https://api.example.com

# With custom endpoint path
hadrian test graphql --target https://api.example.com --endpoint /api/graphql

# With SDL schema file (when introspection is disabled)
hadrian test graphql --target https://api.example.com --schema schema.graphql

# With authentication for authorization testing
hadrian test graphql --target https://api.example.com --auth auth.yaml --roles roles.yaml
```

## Command Options

```
hadrian test graphql [flags]

Flags:
      --target string          Target base URL (required)
      --endpoint string        GraphQL endpoint path (default "/graphql")
      --schema string          GraphQL SDL schema file (optional, uses introspection if not provided)
      --roles string           Roles and permissions YAML file
      --auth string            Authentication configuration YAML file
      --template-dir string    GraphQL templates directory (default: $HADRIAN_TEMPLATES or ./templates/graphql)
      --depth-limit int        Maximum query depth for DoS testing (default 10)
      --complexity-limit int   Maximum complexity score for DoS testing (default 1000)
      --batch-size int         Number of queries in batch attack tests (default 100)
      --proxy string           HTTP/HTTPS proxy URL
      --ca-cert string         CA certificate for proxy
      --insecure               Skip TLS verification
      --rate-limit float       Rate limit in requests per second (default 5.0)
      --timeout int            Request timeout in seconds (default 30)
      --output string          Output format: terminal, json, markdown (default "terminal")
      --output-file string     Output file path
      --verbose                Verbose output
      --dry-run                Show what would be tested without executing
```

## Security Checks

Hadrian performs the following GraphQL security checks:

### 1. Introspection Disclosure (MEDIUM)

Detects if GraphQL introspection is enabled in production. Introspection allows attackers to discover the entire API schema.

```
Finding: GraphQL introspection is enabled
Remediation: Disable introspection in production environments
```

### 2. Query Depth Limit (HIGH)

Tests for missing query depth limits. Deep queries can cause server resource exhaustion.

```
Finding: Server allows deeply nested queries (depth 10) without restriction
Remediation: Implement query depth limiting to prevent resource exhaustion attacks
```

### 3. Query Batching Limit (MEDIUM)

Tests for missing batching limits. Batched queries can multiply server load.

```
Finding: Server allows batched queries with 100 operations without restriction
Remediation: Implement batching limits to prevent resource exhaustion attacks
```

### 4. BOLA - Broken Object Level Authorization (CRITICAL)

Tests if users can access other users' data through object ID manipulation.

```
Finding: BOLA detected: attacker can access victim data via user query
Remediation: Implement proper object-level authorization checks
```

### 5. BFLA - Broken Function Level Authorization (CRITICAL)

Tests if low-privileged users can execute admin-only mutations.

```
Finding: BFLA detected: low-privileged user can execute deleteUser mutation
Remediation: Implement proper function-level authorization checks
```

## Authentication Configuration

For BOLA/BFLA testing, you need to provide authentication configuration:

### auth.yaml

```yaml
# Authentication configuration for multi-role testing
roles:
  admin:
    type: bearer
    token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

  user:
    type: bearer
    token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

  attacker:
    type: bearer
    token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

  victim:
    type: bearer
    token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Supported auth types:
# - bearer: Authorization: Bearer <token>
# - basic: Authorization: Basic <base64(user:pass)>
# - api_key: X-API-Key: <key> (or custom header)
# - cookie: Cookie: <name>=<value>
```

### roles.yaml

```yaml
# Role definitions with permission levels
roles:
  - name: admin
    permissions:
      - "read:*:all"
      - "write:*:all"
      - "delete:*:all"

  - name: user
    permissions:
      - "read:user:own"
      - "write:user:own"

  - name: attacker
    permissions:
      - "read:user:own"

  - name: victim
    permissions:
      - "read:user:own"
      - "write:user:own"
```

## Template System

GraphQL security tests are defined using YAML templates. Hadrian includes 12 built-in templates:

| Template | Vulnerability | Severity |
|----------|--------------|----------|
| introspection-disclosure | Introspection enabled | MEDIUM |
| depth-attack | Missing depth limits | HIGH |
| batching-attack | Missing batch limits | MEDIUM |
| bola-user-access | Object-level authorization | HIGH |
| bfla-mutation | Function-level authorization | HIGH |
| alias-dos-attack | Alias-based DoS | HIGH |
| field-duplication-attack | Field duplication DoS | MEDIUM |
| error-disclosure | Verbose error messages | MEDIUM |
| directive-overloading | Directive abuse | MEDIUM |
| circular-fragment-attack | Circular fragments | HIGH |
| injection-via-variables | GraphQL injection | HIGH |
| excessive-data-exposure | Over-fetching data | HIGH |

### Custom Templates

Create custom templates in a directory and specify with `--template-dir`:

```yaml
# my-templates/custom-check.yaml
id: graphql-custom-check
info:
  name: "Custom GraphQL Check"
  category: "API3:2023 Broken Object Property Level Authorization"
  severity: "HIGH"
  author: "your-name"
  tags: ["graphql", "custom"]
  requires_llm_triage: true
  test_pattern: "simple"

endpoint_selector:
  requires_auth: true

role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"

graphql:
  - query: |
      query CustomQuery {
        sensitiveData {
          secret
        }
      }
    auth: "attacker"
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["secret"]
        part: body

detection:
  success_indicators:
    - type: status_code
      status_code: 200
    - type: body_field
      body_field: "data.sensitiveData"
      exists: true
  vulnerability_pattern: "graphql_custom_vuln"
```

### Template Variable Limitations

The `store_response_fields` directive uses JSON path expressions to extract values from GraphQL responses for use in subsequent phases. These paths only support **dot-separated object key traversal** (e.g., `data.user.id`). Array indexing (e.g., `data.users[0].id`), keys containing dots, and nested arrays are not supported — unsupported paths silently return empty strings.

```bash
hadrian test graphql --target https://api.example.com --template-dir ./my-templates
```

## Example: Testing DVGA

[DVGA (Damn Vulnerable GraphQL Application)](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) is an intentionally vulnerable GraphQL application for testing.

### Setup DVGA

```bash
# Clone and run DVGA
git clone https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application.git
cd Damn-Vulnerable-GraphQL-Application
docker-compose up -d

# DVGA runs at http://localhost:5013/graphql
```

### Run Hadrian

```bash
# Basic scan
hadrian test graphql --target http://localhost:5013

# Expected findings:
# [MEDIUM] introspection-disclosure: GraphQL introspection is enabled
# [HIGH] no-depth-limit: Server allows deeply nested queries (depth 10)
# [MEDIUM] no-batching-limit: Server allows batched queries with 100 operations
```

## Output Formats

### Terminal (default)

```
Starting GraphQL security test
Target: http://localhost:5013/graphql

Schema loaded:
  Queries: 2
  Mutations: 1
  Types: 5

=== Security Findings (3) ===

[MEDIUM] introspection-disclosure: GraphQL introspection is enabled
[HIGH] no-depth-limit: Server allows deeply nested queries (depth 10)
[MEDIUM] no-batching-limit: Server allows batched queries with 100 operations
```

### JSON

```bash
hadrian test graphql --target http://localhost:5013 --output json --output-file report.json
```

```json
{
  "target": "http://localhost:5013/graphql",
  "timestamp": "2026-02-03T12:00:00Z",
  "findings": [
    {
      "id": "f8a1b2c3-...",
      "type": "introspection-disclosure",
      "severity": "MEDIUM",
      "evidence": "GraphQL introspection is enabled",
      "remediation": "Disable introspection in production"
    }
  ]
}
```

### Markdown

```bash
hadrian test graphql --target http://localhost:5013 --output markdown --output-file report.md
```

## Proxy Support

Route traffic through a proxy for debugging or integration with tools like Burp Suite:

```bash
# HTTP proxy
hadrian test graphql --target https://api.example.com --proxy http://localhost:8080

# HTTPS proxy with custom CA
hadrian test graphql --target https://api.example.com --proxy https://localhost:8080 --ca-cert ca.crt

# Skip TLS verification (development only)
hadrian test graphql --target https://api.example.com --proxy https://localhost:8080 --insecure
```

## Rate Limiting

Hadrian includes built-in rate limiting to prevent overwhelming target servers:

```bash
# Default: 5 requests/second
hadrian test graphql --target https://api.example.com

# Custom rate limit
hadrian test graphql --target https://api.example.com --rate-limit 2.0

# Reactive backoff on 429/503 responses is automatic
```

## Troubleshooting

### "Introspection is disabled"

If the target has introspection disabled, provide a schema file:

```bash
hadrian test graphql --target https://api.example.com --schema schema.graphql
```

### "TLS certificate error"

For self-signed certificates or proxy interception:

```bash
hadrian test graphql --target https://api.example.com --insecure
# Or provide CA certificate
hadrian test graphql --target https://api.example.com --ca-cert ca.crt
```

## Best Practices

1. **Start with dry-run**: Use `--dry-run` to see what will be tested
2. **Use appropriate rate limits**: Don't overwhelm the target server
3. **Test in staging first**: Avoid testing production without authorization
4. **Provide auth for BOLA/BFLA**: Authorization tests require valid tokens
5. **Review findings with LLM triage**: Enable `requires_llm_triage` for better context
