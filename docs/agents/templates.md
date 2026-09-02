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

## Permission Format

Permissions follow `<action>:<object>:<scope>` (validated in `pkg/roles/roles.go`):
- Actions: `read`, `write`, `delete`, `execute`, `*`
- Scopes: `public`, `own`, `org`, `all`, `*`
