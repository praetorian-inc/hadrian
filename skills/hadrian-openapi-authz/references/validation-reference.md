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

- [ ] Calculate: `sorted_levels = sorted([level for each role])`
- [ ] Calculate: `median = sorted_levels[(len - 1) // 2]`
- [ ] Verify: at least one non-anonymous role with real credentials has `level < median`
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
    level: 5
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

**Why this passes:**
- auth.yaml: `method` first line, all roles have `token`, anonymous has empty token
- roles.yaml: Three top-level keys, NO auth blocks in roles
- Permissions: All `action:object:scope`, all annotated confirmed/inferred
- Endpoints: Parameterized paths have `owner_field`
- BOLA: Median of [0, 5, 30, 100] = sorted[3//2] = sorted[1] = 5. user-attacker(5) is NOT < 5...

Wait — recalculate: sorted = [0, 5, 30, 100], len=4, median = sorted[(4-1)//2] = sorted[1] = 5. user-attacker at level 5 is NOT strictly below median 5. This would fail BOLA!

**Fix**: Set user-attacker to level 4 (below median 5):

```yaml
  - name: user-attacker
    level: 4    # Below median (5) for BOLA attacker role
```

New check: sorted = [0, 4, 30, 100], median = sorted[1] = 4. user-attacker(4) NOT < 4. Still fails!

**Correct fix**: With 4 roles, ensure spread. Set levels [0, 5, 20, 100]:
- median = sorted[1] = 5. user-attacker(5) NOT < 5. Fails!

**Working configuration**: [0, 5, 30, 100] with dedicated attacker at level 3:
- median = sorted[1] = 5. attacker(3) < 5. PASSES!

This demonstrates why BOLA verification is mandatory — level assignment is non-obvious.
