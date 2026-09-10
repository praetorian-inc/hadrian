# Hadrian template system (agent reference)

Relocated from `AGENTS.md` (ENG-6805). Struct tags for every key below are in `pkg/templates/template.go`.

## Template System

Templates in `templates/rest/` define security tests with:
- `endpoint_selector`: Filters which operations to test — methods, path params (`has_path_parameter`), auth requirements, and **parameter-scoped selectors** for identity carried outside the path: `has_query_parameter` / `has_body_field` (operation exposes any query param / body field) and `query_parameter_names` / `body_field_names` (narrow to identity/scope params by name, case-insensitive)
- `role_selector`: Defines attacker/victim role combinations by permission level (lower/higher/all/none)
- `http`: HTTP request definition with template variables (`{{operation.method}}`, `{{attacker_token}}`)
- `detection`: Success/failure indicators to determine if vulnerability exists

Templates support both simple single-phase tests and multi-phase mutation tests (setup → attack → verify).

### Multi-Phase Mutation Tests

For complex vulnerability patterns like BFLA and BOPLA, templates use `test_phases`:

```yaml
test_phases:
  setup:
    # Single phase (backwards compatible)
    - path: "/api/user/dashboard"
      auth: "victim"
      store_response_fields:
        victim_id: "id"
        victim_video_id: "video_id"
    # Multiple setup phases supported (array syntax)
    - path: "/api/user/dashboard"
      auth: "attacker"
      store_response_fields:
        attacker_video_id: "video_id"
  attack:
    path: "/api/resource/{victim_id}"
    auth: "attacker"
    use_stored_field: "victim_id"
  verify:
    path: "/api/resource/{victim_id}"
    auth: "victim"
    check_field: "status"
    expected_value: "deleted"
```

Key features:
- **`store_response_fields`**: Map of `alias: json_path` to extract and store multiple fields from setup responses
- **`setup` as array**: Supports multiple sequential setup phases (e.g., get attacker's data, then victim's data)
- **Placeholder substitution**: Use `{alias}` in paths and data fields to reference stored values
- **Phase `operation`**: Maps to an HTTP verb — `create`→POST, `update`→PUT, `patch`/`write`→PATCH, `delete`→DELETE, `read`/empty→GET (`pkg/orchestrator/mutation.go`)
- **Phase `body` (+ optional `content_type`)**: A raw request body supporting `{alias}` substitution (defaults to JSON). Substituted values are context-escaped for the content type — JSON-string-escaped for JSON, query-escaped for form-urlencoded, XML-escaped for XML; other content types (e.g. multipart form data, HTML) receive the raw value

Parameter-scoped BOLA examples (query/body identity) live under `examples/param-scoped-bola/` and load via `HADRIAN_TEMPLATES` with `--category all` (the `--category` flag defaults to `owasp` and matches exactly against `info.category` and `info.tags`).

### Two-Phase Cache-Deception Tests

`test_pattern: "cache-deception"` routes an operation to the self-priming Web Cache Deception executor (`pkg/orchestrator/cache_deception.go`, dispatched from `pkg/runner/execution.go`). For each auth-required **GET** it selects (non-GET operations are skipped — only GET responses are CDN-cacheable), the executor authenticates as the **explicit `prime_role`** and sends `prime_repeat` GETs to warm the cache, then replays the **same URL** anonymously (no `Authorization`/`Cookie`/api-key, and — via a dedicated request path, not the shared executor — none of the operator `--header` custom headers) and flags a match when the anonymous response is 2xx **and** carries an explicit cache-HIT header **and** its body proves the victim's cached content leaked. The prime identity is **never guessed**: if `prime_role` is unset or not authenticatable the operation is skipped, so a privileged account is never selected implicitly. Config lives in the `cache_deception` block:

```yaml
cache_deception:
  prime_role: "canary"     # REQUIRED: exact roles.yaml/auth.yaml name of a SELF-SCOPED canary account; unset/not-authenticatable => skip
  prime_repeat: 2          # authed GETs to warm the cache (default 2, min 1, capped at 20)
  canary_field: "email"    # JSON path of a HIGH-ENTROPY self-scoped value (matched by substring); empty => exact body-equality proof
  cache_hit_headers:       # optional regexes over "Header: value"; empty => CF-Cache-Status HIT, X-Cache ...HIT
    - '(?im)^cf-cache-status:\s*hit'
```

This is an **ACTIVE, intrusive** check (it writes an authenticated response into a shared cache) and must be primed only with a self-scoped canary account, so it ships opt-in under `examples/cache-deception/` (load via `HADRIAN_TEMPLATES=examples/cache-deception` + `--category all`). It is distinct from the passive observational template `templates/rest/12-api8-web-cache-deception.yaml` (`test_pattern: "simple"`), which sends a single unauthenticated GET, never writes to a cache, and stays the safe default in `templates/rest/`.

Replay invariants and caveats: operator custom headers (`--header`) are intentionally **not** applied to the anonymous replay (only to the priming requests), so an auth-bearing `--header` cannot fake a leak — the trade-off is that dropping a required **non-auth** header on the replay can change the cache key and cause a false negative. Both phases probe the **same** concrete URL: path-parameter values are URL-escaped and every **required** query parameter is appended, so a query-driven endpoint is reached with a stable cache key rather than 400ing on the probe. `canary_field` is matched by **substring**, so it must name a **high-entropy, unique** value (`email`, an account token, a full name — never a short/numeric `id`); values shorter than 8 characters, and low-entropy placeholder/sentinel values (`null`, `undefined`, `none`, `anonymous`, `not_found`, …), are rejected as not-leaked with a warning. In the exact **body-equality** fallback (empty `canary_field`) a trivial or very short body (`{}`, `[]`, whitespace, < 16 chars) is rejected, because a public role-independent cached body would otherwise match; prefer `canary_field`. If either the prime or the anonymous body is **truncated** at the 10 MB cap the comparison **fails closed** (not-leaked) rather than comparing prefixes. A `prime_role` that authenticates via a **query-parameter** api-key is a known false-negative source: priming keys the cache on `/path?api_key=…` while the replay hits the bare `/path`, so the cache keys never match.

The passive observational template `templates/rest/12-api8-web-cache-deception.yaml` is reported at **MEDIUM** (not HIGH): it cannot read the HTTP status code or confirm the cached body is sensitive, so a cache-HIT header is a candidate requiring confirmation. The active two-phase template is the HIGH-confidence path.

## Permission Format

Permissions follow `<action>:<object>:<scope>` (validated in `pkg/roles/roles.go`):
- Actions: `read`, `write`, `delete`, `execute`, `*`
- Scopes: `public`, `own`, `org`, `all`, `*`
