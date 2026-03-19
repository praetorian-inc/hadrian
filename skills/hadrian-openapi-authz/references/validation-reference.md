# Hadrian YAML Validation Reference

## Common Errors to Avoid

### Error 1: Auth embedded in roles.yaml

**This is the most common mistake.** The Hadrian `Role` struct has NO `auth` field.

```yaml
# roles.yaml
roles:
  - name: admin
    level: 100
    permissions:
      - "*:*:*"
    auth:                    # WRONG — this field does not exist in Role struct
      token: "${ADMIN_TOKEN}"
```

**Why wrong**: Hadrian's `roles.RoleConfig` parses roles with `yaml.Unmarshal` which silently ignores unknown fields. The auth block is never read — credentials must be in `auth.yaml`.

```yaml
# CORRECT — auth.yaml (separate file)
method: bearer
roles:
  admin:
    token: "${ADMIN_TOKEN}"

# CORRECT — roles.yaml (no auth blocks)
roles:
  - name: admin
    level: 100
    permissions:
      - "*:*:*"
```

### Error 2: Missing `method` field in auth.yaml

```yaml
# WRONG
roles:
  admin:
    token: "..."
```

**Why wrong**: `auth.AuthConfig` uses `KnownFields(true)` and validates method. Missing method causes: `unsupported auth method "" (valid: bearer, basic, api_key, cookie)`.

```yaml
# CORRECT
method: bearer
roles:
  admin:
    token: "..."
```

### Error 3: Missing `owner_field` on parameterized endpoints

```yaml
# WRONG
endpoints:
  - path: "/users/{id}"
    object: users
  - path: "/orders/{orderId}"
    object: orders
```

**Why wrong**: Without `owner_field`, Hadrian cannot identify which path parameter ties the resource to a user. BOLA tests require this to substitute attacker/victim IDs.

```yaml
# CORRECT
endpoints:
  - path: "/users/{id}"
    object: users
    owner_field: id
  - path: "/orders/{orderId}"
    object: orders
    owner_field: orderId
```

### Error 4: Missing `cookie_name` for cookie auth

```yaml
# WRONG
method: cookie
roles:
  admin:
    cookie: "session-abc123"
```

**Why wrong**: While Hadrian defaults to "session", explicit `cookie_name` prevents ambiguity. Different apps use different names (session_id, JSESSIONID, connect.sid).

```yaml
# CORRECT
method: cookie
cookie_name: session_id
roles:
  admin:
    cookie: "session-abc123"
```

### Error 5: Missing `location` and `key_name` for api_key

```yaml
# WRONG
method: api_key
roles:
  admin:
    api_key: "key123"
```

**Why wrong**: API keys can be in headers or query params. Without `location` and `key_name`, Hadrian doesn't know where to place the key.

```yaml
# CORRECT
method: api_key
location: header
key_name: X-API-Key
roles:
  admin:
    api_key: "key123"
```

---

## Complete Validation Checklist

### auth.yaml

- [ ] `method` field present as FIRST top-level field (one of: `bearer`, `basic`, `api_key`, `cookie`)
- [ ] `roles` top-level key present containing all role definitions
- [ ] For `api_key`: top-level `location` (header/query) and `key_name` present
- [ ] For `cookie`: top-level `cookie_name` present
- [ ] Each role has correct credential field (token/api_key/username+password/cookie)
- [ ] `anonymous` role present with empty credentials or `no_auth: true`

### roles.yaml

- [ ] Three top-level keys present: `objects`, `roles`, `endpoints`
- [ ] **NO `auth:` field in any role definition**
- [ ] Each role has: `name` (string), `level` (integer), `permissions` (list)
- [ ] All permissions use `action:object:scope` format (exactly two colons)
- [ ] Valid actions only: `read`, `write`, `delete`, `execute`, `*`
- [ ] Valid scopes only: `public`, `own`, `org`, `all`, `*`
- [ ] Every object in permissions appears in `objects` list
- [ ] Every endpoint maps to an object from `objects` list
- [ ] **All parameterized endpoints have `owner_field`**
- [ ] `anonymous` role present with `level: 0`

### Cross-file

- [ ] Every role name in auth.yaml matches a role name in roles.yaml
- [ ] Every role name in roles.yaml has a matching entry in auth.yaml
- [ ] **All permissions annotated as confirmed or inferred** (YAML comments)
- [ ] Environment variable names use `SCREAMING_SNAKE_CASE`

### BOLA Compliance

Hadrian's execution loop pairs roles using `attacker.Level < victim.Level` (skips level 0 and same-name).

- [ ] At least 2 authenticated roles (level > 0) with **different** levels exist
- [ ] The lower-level role has real credentials (not empty token)
- [ ] **If fails: HALT and return to Phase 2 with error**

---

## Passing Example

### auth.yaml (Bearer) — PASSING

```yaml
method: bearer

roles:
  admin:
    token: "${ADMIN_TOKEN}"
  user-victim:
    token: "${USER_VICTIM_TOKEN}"
  user-attacker:
    token: "${USER_ATTACKER_TOKEN}"
  anonymous:
    token: ""
```

### roles.yaml — PASSING

```yaml
objects:
  - users
  - orders
  - products

roles:
  - name: admin
    level: 100
    permissions:
      - "*:*:*"

  - name: user-victim
    level: 30
    permissions:
      - "read:users:own"       # inferred — GET /users/{id}
      - "write:users:own"      # inferred — PUT /users/{id}
      - "read:orders:own"      # inferred — GET /orders
      - "write:orders:own"     # inferred — POST /orders
      - "read:products:public" # confirmed — security: [] on GET /products

  - name: user-attacker
    level: 3
    permissions:
      - "read:users:own"       # inferred — same as victim
      - "read:products:public" # confirmed — security: []

  - name: anonymous
    level: 0
    permissions:
      - "read:products:public" # confirmed — security: [] on GET /products

endpoints:
  - path: "/api/v1/users/{id}"
    object: users
    owner_field: id
  - path: "/api/v1/orders"
    object: orders
  - path: "/api/v1/orders/{orderId}"
    object: orders
    owner_field: orderId
  - path: "/api/v1/products"
    object: products
```

**Why this passes all checks:**
- auth.yaml: `method` as first line, all roles have `token` field, anonymous has empty token
- roles.yaml: Three top-level keys (`objects`, `roles`, `endpoints`), NO auth blocks in roles
- Permissions: All use `action:object:scope` format, all annotated confirmed/inferred
- Endpoints: Parameterized paths (`/users/{id}`, `/orders/{orderId}`) have `owner_field`
- BOLA: user-attacker(3) < user-victim(30) — valid pairing. user-attacker(3) < admin(100) — also valid. Two authenticated roles with different levels exist.

---

## BOLA Role Pairing — How It Works

Hadrian's execution loop (`pkg/runner/execution.go`) uses **pairwise level comparison**, NOT a median:

```
for each attackerRole:
    skip if attackerRole.Level == 0          (anonymous never attacks for BOLA)
    for each victimRole:
        skip if attackerRole.Name == victimRole.Name   (no self-attack)
        skip if attackerRole.Level >= victimRole.Level  (attacker must be lower)
        → execute BOLA test: attacker accesses victim's resource
```

**What works:**

| Roles (levels) | Valid Pairings | BOLA Tests? |
|---------------|----------------|-------------|
| [0, 5, 20, 100] | 5→20, 5→100, 20→100 | YES — 3 pairings |
| [0, 10, 10, 100] | 10→100, 10→100 | YES — but no horizontal (same-level) test |
| [0, 20, 100] | 20→100 | YES — 1 pairing |
| [0, 0] | none | NO — only anonymous roles |
| [0, 50, 50] | none | NO — both auth roles at same level |

**Key rules:**
- At least 2 authenticated roles (level > 0) with **different** levels
- Lower-level role must have real credentials
- For **horizontal** BOLA testing (same privilege, different accounts), create 2 roles at the same level — Hadrian tests these as same-level cross-account access
