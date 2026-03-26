# Hadrian Authentication Configuration Examples

Complete examples for all four Hadrian authentication methods.

## Required Structure Summary

**CRITICAL:** Every auth.yaml file MUST begin with these top-level fields (NOT under `roles:`):

```yaml
method: <bearer|basic|api_key|cookie>   # ALWAYS REQUIRED as first line

# Additional required fields based on method:
# For api_key: location + key_name
# For cookie: cookie_name

roles:  # REQUIRED top-level key
  role-name:
    # Per-role credentials here
```

| Auth Method | Top-Level Required Fields |
|-------------|---------------------------|
| `bearer` | `method: bearer` |
| `basic` | `method: basic` |
| `api_key` | `method: api_key`, `location: header\|query`, `key_name: <name>` |
| `cookie` | `method: cookie`, `cookie_name: <name>` |

---

## Bearer Token Authentication

```yaml
method: bearer

roles:
  admin:
    token: "${ADMIN_TOKEN}"
  user-001:
    token: "${USER_001_TOKEN}"
  user-002:
    token: "${USER_002_TOKEN}"
  anonymous:
    token: ""  # Empty token
  no_header:
    no_auth: true  # Omits Authorization header entirely
```

**Sends**: `Authorization: Bearer <token>`

## Basic Authentication

```yaml
method: basic

roles:
  admin:
    username: "${ADMIN_USERNAME}"
    password: "${ADMIN_PASSWORD}"
  user-001:
    username: "${USER_001_USERNAME}"
    password: "${USER_001_PASSWORD}"
  service:
    credentials: "${SERVICE_CREDENTIALS}"  # Alternative to username/password
  anonymous:
    username: ""
    password: ""  # Sends "Authorization: Basic Og==" (base64 of ":")
  no_header:
    no_auth: true  # Omits Authorization header entirely
```

**Sends**: `Authorization: Basic <base64(username:password)>`

**Note**: Use `credentials` field as alternative to `username`/`password` for pre-combined credentials.

## API Key Authentication

```yaml
method: api_key
location: header
key_name: X-API-Key

roles:
  admin:
    api_key: "${ADMIN_API_KEY}"
  user-001:
    api_key: "${USER_001_API_KEY}"
  user-002:
    api_key: "${USER_002_API_KEY}"
  anonymous:
    api_key: ""  # Sends "X-API-Key: " (empty value)
  no_header:
    no_auth: true  # Omits X-API-Key header entirely
```

**Sends**: `X-API-Key: <api_key>`

### API Key as Query Parameter

```yaml
method: api_key
location: query
key_name: api_key

roles:
  admin:
    api_key: "${ADMIN_API_KEY}"
  user:
    api_key: "${USER_API_KEY}"
```

**Sends**: `GET /endpoint?api_key=<api_key>`

## Cookie Authentication

```yaml
method: cookie
cookie_name: session_id

roles:
  admin:
    cookie: "${ADMIN_SESSION}"
  user-001:
    cookie: "${USER_001_SESSION}"
  user-002:
    cookie: "${USER_002_SESSION}"
  anonymous:
    cookie: ""  # Sends "Cookie: session_id=" (empty value)
  no_header:
    no_auth: true  # Omits Cookie header entirely
```

**Sends**: `Cookie: session_id=<cookie>`

**Note**: `cookie_name` is REQUIRED. While Hadrian defaults to "session" if omitted, you MUST specify it explicitly to avoid ambiguity.

## Field Reference

### Top-Level Fields

| Field | Auth Methods | Required | Description |
|-------|--------------|----------|-------------|
| `method` | All | Yes | One of: `bearer`, `basic`, `api_key`, `cookie` |
| `location` | `api_key` only | Yes for api_key | `header` or `query` |
| `key_name` | `api_key` only | Yes for api_key | Header name or query param name |
| `cookie_name` | `cookie` only | Required | Cookie name (e.g., session_id, JSESSIONID) |

### Per-Role Fields

| Field | Auth Method | Description |
|-------|-------------|-------------|
| `token` | `bearer` | Bearer token value |
| `api_key` | `api_key` | API key value |
| `username` | `basic` | Basic auth username |
| `password` | `basic` | Basic auth password |
| `credentials` | `basic` | Alternative to username/password (pre-combined string) |
| `cookie` | `cookie` | Cookie value (session ID) |
| `no_auth` | All | Set to `true` to omit auth header entirely |

## Environment Variables

Use `${VAR_NAME}` syntax for credentials:

```yaml
roles:
  admin:
    token: "${ADMIN_TOKEN}"  # Expands from environment at runtime
```

Hadrian expands `${VAR}` references at runtime. Use environment variables for all credentials.
