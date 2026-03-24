# OpenAPI Security Scheme Parsing Reference

## OpenAPI 3.x Security Schemes

Location: `components.securitySchemes`

### Bearer Token (most common)

```yaml
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT  # optional hint
```

**Maps to Hadrian:**
```yaml
method: bearer
```

### API Key in Header

```yaml
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
```

**Maps to Hadrian:**
```yaml
method: api_key
location: header
key_name: X-API-Key
```

### API Key in Query Parameter

```yaml
components:
  securitySchemes:
    apiKeyQuery:
      type: apiKey
      in: query
      name: api_key
```

**Maps to Hadrian:**
```yaml
method: api_key
location: query
key_name: api_key
```

### Basic Authentication

```yaml
components:
  securitySchemes:
    basicAuth:
      type: http
      scheme: basic
```

**Maps to Hadrian:**
```yaml
method: basic
```

### OAuth2 (use as bearer)

```yaml
components:
  securitySchemes:
    oauth2:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://auth.example.com/authorize
          tokenUrl: https://auth.example.com/token
          scopes:
            read: Read access
            write: Write access
```

**Maps to Hadrian:**
```yaml
method: bearer   # Use the OAuth2 access token as a bearer token
```

### Cookie-Based (apiKey type with in: cookie)

```yaml
components:
  securitySchemes:
    cookieAuth:
      type: apiKey
      in: cookie
      name: session_id
```

**Maps to Hadrian:**
```yaml
method: cookie
cookie_name: session_id
```

---

## Swagger 2.0 Security Definitions

Location: `securityDefinitions` (top-level)

### Bearer via apiKey type

```yaml
securityDefinitions:
  Bearer:
    type: apiKey
    name: Authorization
    in: header
    description: "JWT token. Example: Bearer eyJ..."
```

**Maps to Hadrian:** `method: bearer` (despite OpenAPI type being apiKey, the `name: Authorization` and description indicate bearer usage)

### Basic Auth

```yaml
securityDefinitions:
  basicAuth:
    type: basic
```

**Maps to Hadrian:** `method: basic`

### API Key

```yaml
securityDefinitions:
  api_key:
    type: apiKey
    name: X-API-Key
    in: header
```

**Maps to Hadrian:**
```yaml
method: api_key
location: header
key_name: X-API-Key
```

---

## Mapping Table

| OpenAPI Type | `scheme`/`in` | Hadrian `method` | Extra Hadrian Fields |
|-------------|---------------|------------------|---------------------|
| `http` | `bearer` | `bearer` | — |
| `http` | `basic` | `basic` | — |
| `apiKey` | `in: header` | `api_key` | `location: header`, `key_name: <name>` |
| `apiKey` | `in: query` | `api_key` | `location: query`, `key_name: <name>` |
| `apiKey` | `in: cookie` | `cookie` | `cookie_name: <name>` |
| `oauth2` | any flow | `bearer` | — (use access token) |

## Detecting Public Endpoints

Public (unauthenticated) endpoints are identified by:

1. **Empty security override**: `security: []` on the operation
2. **No global security + no operation security**: If no `security` at any level
3. **Optional security**: `security: [{}]` (empty object in array)

```yaml
# Global security (applies to all unless overridden)
security:
  - bearerAuth: []

paths:
  /products:
    get:
      security: []         # OVERRIDE: public, no auth needed
      summary: List products
  /orders:
    get:
      # No security override: inherits global bearerAuth
      summary: List orders
```

For anonymous role permissions, ONLY include endpoints with explicit `security: []`.

## Extracting Path Parameters for owner_field

Path parameters in OpenAPI that represent resource identifiers should map to `owner_field`:

```yaml
paths:
  /users/{userId}:           # owner_field: userId
    parameters:
      - name: userId
        in: path
        required: true
  /orders/{id}:              # owner_field: id
    get:
      parameters:
        - name: id
          in: path
          required: true
  /teams/{teamId}/members:   # owner_field: teamId (parent resource)
```

**Heuristic**: Use the FIRST path parameter as `owner_field` for simple CRUD endpoints. For nested resources (`/teams/{teamId}/members/{memberId}`), use the most specific parameter (`memberId`).
