# REST API Security Testing

Hadrian provides comprehensive REST API security testing with 8 built-in templates covering OWASP API Security Top 10 categories. REST testing uses OpenAPI/Swagger specifications to automatically discover endpoints and generate role-based authorization tests.

## Quick Start

```bash
# Basic security test
hadrian test rest --api api.yaml --roles roles.yaml

# With authentication
hadrian test rest --api api.yaml --roles roles.yaml --auth auth.yaml

# Test specific OWASP categories
hadrian test rest --api api.yaml --roles roles.yaml --owasp API1,API2,API5

# Dry run (show what would be tested)
hadrian test rest --api api.yaml --roles roles.yaml --dry-run

# Verbose output with JSON report
hadrian test rest --api api.yaml --roles roles.yaml --verbose --output json --output-file report.json
```

## Command Options

```
hadrian test rest [flags]

Required Flags:
      --api <file>              API specification file (OpenAPI, Swagger, Postman)
      --roles <file>            Roles and permissions YAML file

Optional Flags:
      --auth <file>             Authentication configuration YAML file
      --template-dir <dir>      Directory containing test templates (default: $HADRIAN_TEMPLATES or ./templates/rest)
      --template <list>         Specific template files to run
      --category <list>         Test categories: owasp, custom (default: owasp)
      --owasp <list>            OWASP API categories to test (e.g., API1,API2,API5,API9)
      --concurrency <n>         Concurrent requests (default: 1, max: 10)
      --timeout <n>             Request timeout in seconds (default: 30)
      --verbose, -v             Enable verbose logging output
      --dry-run                 Show what would be tested without making requests
      --audit-log <file>        Audit log file (default: .hadrian/audit.log)
```

For network options (proxy, rate limiting, TLS) and output options, see [Configuration](configuration.md).

## Supported API Specifications

Hadrian supports multiple API specification formats:

- **OpenAPI 3.0/3.1** (YAML/JSON)
- **Swagger 2.0** (YAML/JSON)
- **Postman Collection v2.1**

Use `hadrian parse <file>` to preview what Hadrian discovers from your spec.

## Security Checks

Hadrian includes 8 built-in REST templates:

| Template | Vulnerability | Severity | Pattern |
|----------|--------------|----------|---------|
| `01-api1-bola-read` | BOLA - Cross-User Resource Read | HIGH | Simple |
| `02-api1-bola-write` | BOLA - Unauthorized Resource Modification | HIGH | Mutation |
| `03-api1-bola-delete` | BOLA - Unauthorized Resource Deletion | CRITICAL | Mutation |
| `04-api2-broken-auth-no-token` | Broken Authentication - No Token | HIGH | Simple |
| `05-api3-excessive-data-exposure` | Excessive Data Exposure | HIGH | Simple |
| `06-api5-bfla-admin-access` | BFLA - Unauthorized Admin Access | HIGH | Simple |
| `07-api8-security-misconfiguration` | Security Misconfiguration | MEDIUM | Simple |
| `08-api9-improper-inventory` | Improper Inventory Management | MEDIUM | Simple |

### 1. BOLA - Broken Object Level Authorization (API1:2023)

Tests if users can access, modify, or delete other users' resources through object ID manipulation. Covers read (simple), write (mutation), and delete (mutation) patterns.

```
Finding: Attacker with lower privileges accessed victim's resource via GET /api/users/{id}
Remediation: Implement proper object-level authorization checks on all resource endpoints
```

### 2. Broken Authentication (API2:2023)

Tests if endpoints are accessible without any authentication token.

```
Finding: Endpoint accessible without authentication token
Remediation: Enforce authentication on all sensitive endpoints
```

### 3. Excessive Data Exposure (API3:2023)

Tests if API responses expose sensitive data fields (PII, internal identifiers).

```
Finding: Response contains sensitive fields that should be filtered
Remediation: Implement response filtering to return only necessary fields
```

### 4. BFLA - Broken Function Level Authorization (API5:2023)

Tests if low-privileged users can access admin-only endpoints.

```
Finding: Regular user can access admin endpoint GET /api/admin/users
Remediation: Implement function-level authorization checks
```

### 5. Security Misconfiguration (API8:2023)

Tests for common security misconfigurations like missing security headers, verbose error messages, and exposed debug endpoints.

### 6. Improper Inventory Management (API9:2023)

Tests for deprecated or undocumented API versions still accessible.

## Template System

REST security tests are defined using YAML templates in `templates/rest/`.

### Template Execution Order

Templates are executed in **alphabetical order by filename**. Prefix filenames with numbers to control order:

- `01-*` to `05-*`: Non-destructive read tests
- `06-*` to `07-*`: Write/modification tests
- `08-*` to `09-*`: Destructive delete tests

### Simple Template Example

```yaml
id: api1-bola-cross-user
info:
  name: "BOLA - Cross-User Resource Access"
  category: "API1:2023"
  severity: "HIGH"
  description: |
    Tests for Broken Object Level Authorization by attempting
    to access resources belonging to other users.
  tags: ["bola", "owasp-api-top10", "api1"]
  requires_llm_triage: true
  test_pattern: "simple"

endpoint_selector:
  has_path_parameter: true
  requires_auth: true
  methods: ["GET"]

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

### Mutation Template Example (Three-Phase)

For vulnerability patterns that modify state (BFLA, BOPLA), templates use `test_phases`:

```yaml
id: api5-bfla-delete
info:
  name: "BFLA - Unauthorized Resource Deletion"
  category: "API5:2023"
  severity: "HIGH"
  test_pattern: "mutation"

endpoint_selector:
  has_path_parameter: true
  requires_auth: true
  methods: ["DELETE"]

role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"

test_phases:
  setup:
    - path: "/api/user/dashboard"
      auth: "victim"
      store_response_fields:
        victim_id: "id"
        victim_video_id: "video_id"
    - path: "/api/user/dashboard"
      auth: "attacker"
      store_response_fields:
        attacker_video_id: "video_id"
  attack:
    path: "/api/resource/{victim_video_id}"
    auth: "attacker"
    operation: "delete"
    expected_status: 200
  verify:
    path: "/api/resource/{victim_video_id}"
    auth: "victim"
    check_field: "status"
    expected_value: "deleted"
```

- **`setup`**: One or more phases that establish state and store response fields for later substitution
- **`attack`**: Attempts the unauthorized action using the attacker's credentials
- **`verify`**: Confirms whether the attack succeeded by checking resource state as the victim

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

### Template Variable Limitations

The `store_response_fields` directive uses JSON path expressions to extract values from responses. These paths only support **dot-separated object key traversal** (e.g., `data.user.id`). Array indexing, keys containing dots, and nested arrays are not supported.

## Example: Testing crAPI

[crAPI (OWASP Completely Ridiculous API)](https://github.com/OWASP/crAPI) is an intentionally vulnerable API for testing.

### Setup crAPI

```bash
git clone https://github.com/OWASP/crAPI.git && cd crAPI/deploy/docker && docker-compose up -d
# crAPI runs at http://localhost:8888
```

### Run Hadrian

```bash
hadrian test rest \
  --api test/crapi/crapi-openapi-spec.json \
  --roles test/crapi/roles.yaml \
  --auth test/crapi/auth.yaml \
  --allow-internal \
  --verbose
```

For complete crAPI setup including user registration and token generation, see [crAPI Tutorial](../test/crapi/README.md).

## Troubleshooting

### "Loaded 0 templates"

The default category filter is `owasp`. If template filenames don't contain "owasp", use `--category all`:

```bash
hadrian test rest --api api.yaml --roles roles.yaml --category all
```

### "Role has no credentials configured"

Ensure the environment variables or tokens in your `auth.yaml` are set. See [Authentication Configuration](configuration.md#authentication-authyaml).

### "Connection refused"

For local testing, allow internal IPs:

```bash
hadrian test rest --api api.yaml --roles roles.yaml --allow-internal
```

## Best Practices

1. **Start with dry-run**: Use `--dry-run` to see what will be tested before sending requests
2. **Use appropriate rate limits**: Don't overwhelm the target server (default: 5 req/s)
3. **Test in staging first**: Avoid testing production without explicit authorization
4. **Order templates carefully**: Run read tests before write/delete tests
5. **Review findings with LLM triage**: Enable `--llm-host` and `--llm-model` for AI-powered analysis
