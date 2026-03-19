# Hadrian Schema Reference (from Go source)

## auth.yaml (`auth.AuthConfig` — pkg/auth/auth.go)

Uses `KnownFields(true)` — **extra fields cause parse errors**.

```yaml
method: bearer|basic|api_key|cookie    # REQUIRED first line
location: header|query                  # REQUIRED for api_key
key_name: X-API-Key                    # REQUIRED for api_key
cookie_name: session_id                # REQUIRED for cookie

roles:                                 # REQUIRED map
  role-name:
    token: "..."         # bearer
    api_key: "..."       # api_key
    username: "..."      # basic
    password: "..."      # basic
    credentials: "..."   # basic (alternative)
    cookie: "..."        # cookie
    no_auth: true        # omit auth header
```

## roles.yaml (`roles.RoleConfig` — pkg/roles/roles.go)

```yaml
objects:               # REQUIRED list of resource types
  - resource-name

roles:                 # REQUIRED array
  - name: role-name    # REQUIRED string
    level: 100         # REQUIRED integer
    id: "user-uuid"    # OPTIONAL for BOLA
    username: "user"   # OPTIONAL
    description: "..."  # OPTIONAL
    permissions:       # REQUIRED list
      - "action:object:scope"

endpoints:             # REQUIRED array
  - path: "/api/v1/resource/{id}"
    object: resource-name     # REQUIRED — must be in objects
    owner_field: id           # REQUIRED on parameterized paths
```

## Valid Permission Values

| Component | Values |
|-----------|--------|
| Action | `read`, `write`, `delete`, `execute`, `*` |
| Object | Any string from the `objects` list, or `*` |
| Scope | `public`, `own`, `org`, `all`, `*` |
