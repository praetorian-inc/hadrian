# Configuration

This document covers cross-cutting configuration that applies to all Hadrian test modes (REST, GraphQL, gRPC).

## Table of Contents

- [Authentication](#authentication-authyaml)
- [Roles and Permissions](#roles-and-permissions-rolesyaml)
- [Rate Limiting](#rate-limiting)
- [Proxy Support](#proxy-support)
- [LLM Triage](#llm-triage)
- [Production Safety](#production-safety)
- [Output Formats](#output-formats)
- [Environment Variables](#environment-variables)

## Authentication (auth.yaml)

Configure how to authenticate as each role. The same format is used across REST, GraphQL, and gRPC.

### Bearer Token

```yaml
method: bearer

roles:
  admin:
    token: "eyJhbGciOiJIUzI1NiIs..."
  user:
    token: "eyJhbGciOiJIUzI1NiIs..."
  guest:
    token: ""
```

### Basic Auth

```yaml
method: basic

roles:
  admin:
    username: "${ADMIN_USER}"
    password: "${ADMIN_PASS}"
  readonly:
    username: "reader"
    password: ""
```

### API Key

```yaml
method: api_key
location: header       # or "query"
key_name: X-API-Key    # header name or query parameter name

roles:
  admin:
    api_key: "${ADMIN_API_KEY}"
  service:
    api_key: "service-key-123"
```

### Cookie

```yaml
method: cookie
cookie_name: JSESSIONID    # defaults to "session" if omitted

roles:
  administrator:
    cookie: "6916A1CBD61194CA9A2C64B6ECAB729C"
  monitoring:
    cookie: "${MONITORING_COOKIE}"
  anonymous:
    cookie: ""
```

**Supported authentication methods:**

| Method | Description | Config Fields | Example Header |
|--------|-------------|---------------|----------------|
| `bearer` | Bearer token | `token` | `Authorization: Bearer <token>` |
| `basic` | Username/password | `username`, `password` | `Authorization: Basic <base64>` |
| `api_key` | Custom header or query param | `api_key`, `location`, `key_name` | `X-API-Key: <key>` |
| `cookie` | Cookie-based auth | `cookie`, `cookie_name` | `Cookie: session=<value>` |

### No Authentication Header

Use `no_auth: true` on a role to send requests without any authentication header. This works with any auth method:

```yaml
method: bearer
roles:
  admin:
    token: "${ADMIN_TOKEN}"
  anonymous:
    no_auth: true    # requests sent with no Authorization header
```

### Raw Credentials (Basic Auth)

Use `credentials` instead of `username`/`password` to control the exact base64-encoded value. The string is base64-encoded directly, bypassing the `username:password` format:

```yaml
method: basic
roles:
  admin:
    username: "admin"
    password: "secret"
  empty_basic:
    credentials: ""    # sends "Authorization: Basic " (empty base64)
```

When `credentials` is set, `username` and `password` are ignored.

### Empty Credentials

Roles with empty credentials still send authentication headers with the corresponding empty values. This is useful for testing how APIs handle malformed or empty auth:

| Method | Config | Header Sent |
|--------|--------|-------------|
| any | `no_auth: true` | *(no header sent)* |
| `bearer` | `token: ""` | `Authorization: Bearer ` |
| `basic` | `username: ""`, `password: ""` | `Authorization: Basic Og==` (base64 of `:`) |
| `basic` | `credentials: ""` | `Authorization: Basic ` (empty base64) |
| `basic` | `username: "admin"`, `password: ""` | `Authorization: Basic YWRtaW46` |
| `api_key` | `api_key: ""` | `X-API-Key: ` (empty value) |
| `cookie` | `cookie: ""` | `Cookie: session=` |

**Using environment variables:**

Tokens can reference environment variables to avoid hardcoding credentials:

```yaml
roles:
  admin:
    token: "${ADMIN_TOKEN}"
  user:
    token: "${USER_TOKEN}"
```

**Security warning:** Hadrian warns if `auth.yaml` has world-readable permissions. Run `chmod 0600 auth.yaml` to fix.

## Roles and Permissions (roles.yaml)

Define your application's roles, their privilege levels, and permissions:

```yaml
objects:
  - users
  - posts
  - admin

roles:
  - name: admin
    level: 100
    permissions:
      - "read:users:all"
      - "write:users:all"
      - "delete:users:all"
      - "execute:admin:all"

  - name: user
    level: 10
    permissions:
      - "read:users:own"
      - "read:posts:all"
      - "write:posts:own"

  - name: guest
    level: 0
    permissions: []

endpoints:
  - path: "/api/users/{id}"
    object: users
    owner_field: id
  - path: "/api/posts/{id}"
    object: posts
    owner_field: author_id
```

### Permission Format

Permissions follow `<action>:<object>:<scope>`:

| Component | Values | Description |
|-----------|--------|-------------|
| **Action** | `read`, `write`, `delete`, `execute`, `*` | What the role can do |
| **Object** | Any value from the `objects` list | What resource it applies to |
| **Scope** | `public`, `own`, `org`, `all`, `*` | How broadly it applies |

### Role Levels

The `level` field defines explicit privilege ordering for BOLA testing:

- Higher values = more privileged (e.g., admin: 100, user: 10, guest: 0)
- Used by `role_selector` to determine "lower" vs "higher" permission levels
- Prevents incorrect classification when admins have fewer but more powerful permissions (e.g., `*:*:all`)

## Custom Headers

Add custom HTTP headers to every request using the `--header` / `-H` flag. Headers are repeatable:

```bash
hadrian test rest --api api.yaml --roles roles.yaml \
  -H "X-Custom-Tenant: acme" \
  -H "X-Request-Source: hadrian"
```

Custom headers are applied to all requests across all test modes (REST, GraphQL, gRPC).

## Rate Limiting

Hadrian includes comprehensive rate limiting to prevent overwhelming target APIs. These flags apply to all test modes.

### Proactive Rate Limiting

Limits outgoing requests to a configured rate (default: 5 requests/second):

```bash
hadrian test rest --api api.yaml --roles roles.yaml --rate-limit 10.0
```

### Reactive Backoff

Automatically detects rate limit responses and implements retry with backoff:

```bash
# Use fixed backoff (constant 5s wait)
hadrian test rest --api api.yaml --roles roles.yaml --rate-limit-backoff fixed

# Configure max retries and wait time
hadrian test rest --api api.yaml --roles roles.yaml \
  --rate-limit-max-retries 10 \
  --rate-limit-max-wait 120s

# Custom status codes for rate limit detection
hadrian test rest --api api.yaml --roles roles.yaml \
  --rate-limit-status-codes 429,503,529
```

### Backoff Strategies

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| **exponential** (default) | Wait doubles each retry: 1s, 2s, 4s, 8s... | Most APIs |
| **fixed** | Constant wait time between retries | APIs with fixed rate windows |

The backoff respects the server's `Retry-After` header when present, capping at `--rate-limit-max-wait`.

### Rate Limiting Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--rate-limit` | 5.0 | Requests per second |
| `--rate-limit-backoff` | exponential | Backoff strategy: `exponential` or `fixed` |
| `--rate-limit-max-retries` | 5 | Maximum retry attempts |
| `--rate-limit-max-wait` | 60s | Maximum backoff wait time |
| `--rate-limit-status-codes` | 429,503 | Status codes that trigger backoff |

## Proxy Support

Route traffic through an HTTP proxy for debugging or integration with tools like Burp Suite:

```bash
# HTTP proxy
hadrian test rest --api api.yaml --roles roles.yaml --proxy http://localhost:8080

# HTTPS proxy with custom CA certificate
hadrian test rest --api api.yaml --roles roles.yaml \
  --proxy https://localhost:8080 --ca-cert burp-ca.crt

# Skip TLS verification (development only)
hadrian test rest --api api.yaml --roles roles.yaml \
  --proxy https://localhost:8080 --insecure
```

### Proxy Flags

| Flag | Description |
|------|-------------|
| `--proxy <url>` | HTTP/HTTPS proxy URL (e.g., `http://localhost:8080`) |
| `--ca-cert <file>` | CA certificate for proxy TLS interception |
| `--insecure` | Skip TLS certificate verification |

## LLM Triage

Hadrian supports optional AI-powered finding analysis using a local LLM via [Ollama](https://ollama.ai/). When enabled, each finding is sent to the LLM for contextual triage to reduce false positives.

```bash
# Enable LLM triage with Ollama
hadrian test rest --api api.yaml --roles roles.yaml \
  --llm-host http://localhost:11434 \
  --llm-model llama3.2:latest

# Add domain context for better analysis
hadrian test rest --api api.yaml --roles roles.yaml \
  --llm-host http://localhost:11434 \
  --llm-model llama3.2:latest \
  --llm-context "This API handles financial data with PCI DSS requirements"
```

### LLM Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--llm-host <url>` | - | LLM service host URL (e.g., `http://localhost:11434` for Ollama) |
| `--llm-model <model>` | - | Model name (e.g., `llama3.2:latest`) |
| `--llm-timeout <n>` | 180 | Request timeout in seconds |
| `--llm-context <text>` | - | Additional context for analysis |

### Data Safety

Hadrian redacts sensitive data (tokens, credentials) before sending findings to the LLM. See [Architecture](architecture.md) for details.

### Setup Ollama

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama3.2:latest

# Ollama runs at http://localhost:11434 by default
```

## Production Safety

Hadrian includes built-in safeguards to prevent accidental testing against production systems:

| Safeguard | Default | Override Flag |
|-----------|---------|---------------|
| Concurrency limit | 1 (max: 10) | `--concurrency <n>` |
| YAML bomb protection | 1MB size, 20-depth | Not configurable |
| TLS 1.3 enforcement | Enabled | Not configurable |
| Credential validation | Warns on insecure config | Not configurable |
| Audit logging | `.hadrian/audit.log` | `--audit-log <file>` |

## Output Formats

All test modes support the same output formats:

### Terminal (default)

```
[INFO] Loaded 8 templates from ./templates/rest
[INFO] Testing 44 operations against 5 roles

[FINDING] API1:2023 - BOLA - Cross-User Resource Access
  Severity: HIGH
  Endpoint: GET /api/users/{id}
  Attacker: user -> Victim: admin
  Evidence: Status 200, body contains user data

Summary: 2 findings (1 CRITICAL, 1 HIGH)
```

### JSON

```bash
hadrian test rest --api api.yaml --roles roles.yaml --output json --output-file report.json
```

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
      }
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

### Markdown

```bash
hadrian test rest --api api.yaml --roles roles.yaml --output markdown --output-file report.md
```

### Output Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output <format>` | terminal | Output format: `terminal`, `json`, `markdown` |
| `--output-file <file>` | - | Write findings to file (stdout if omitted) |
| `--request-ids <n>` | 1 | Number of request IDs per finding (0 = all) |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HADRIAN_TEMPLATES` | Custom templates directory path | `./templates/rest` |
| `OLLAMA_HOST` | Ollama host for LLM triage | `http://localhost:11434` |
