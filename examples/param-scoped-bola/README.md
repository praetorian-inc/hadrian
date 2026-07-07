# Parameter-scoped BOLA examples

These templates detect Broken Object Level Authorization (BOLA) where the
user/owner identity is carried in a **query parameter** or **request-body field**
rather than the URL path. Hadrian's built-in BOLA templates select on
`has_path_parameter`, so they miss this class — which is how most modern APIs
actually scope ownership (search filters, JSON:API `filter[...]`, body identities).

| Template | Identity location | Example finding class |
|----------|-------------------|-----------------------|
| `query-param-bola.yaml` | query parameter (`filter[user-ids]`) | cross-user search/list enumeration |
| `body-field-bola.yaml`  | request-body field (`username`, `video_id`) | caller-supplied identity trusted over session |

## Capability used

The templates rely on the parameter-scoped selector and mutation-body support:

- `endpoint_selector.has_query_parameter` / `has_body_field` — match endpoints that
  expose a query parameter / request-body field.
- `endpoint_selector.query_parameter_names` / `body_field_names` — narrow to
  identity/scope parameters by name (case-insensitive).
- mutation phase `body` (+ optional `content_type`) — a raw request body that
  supports `{alias}` placeholder substitution from stored fields, so the victim's
  captured identity is injected into the attack request.

## Running

```bash
HADRIAN_TEMPLATES=examples/param-scoped-bola \
  ./hadrian test rest --api <spec> --roles <roles.yaml> --auth <auth.yaml> \
  --category all --verbose
```

Two things the flags above are load-bearing for:

- **`test rest`** (not just `test`): `--api`/`--roles`/`--auth` are registered on
  the `test rest` subcommand.
- **`--category all`**: `--category` defaults to `owasp` and matches exactly
  (case-insensitive) against a template's `info.category` and `info.tags`. These
  examples are `category: API1:2023` (tagged `owasp-api-top10`, not `owasp`), so
  they load only under `--category all` — or an explicit `--category api1`
  (matches the `api1` tag) / `--category API1:2023`. Without one of these you get
  `Loaded 0 templates`.

## Adapting to your target

Like all REST mutation templates, the phases use **literal paths** — these are
placeholders. Edit the `setup`/`attack` paths, the stored-field JSON paths, and
the body shape to match your target before running; nothing is auto-detected
against an arbitrary spec. The selector fields (`query_parameter_names`,
`body_field_names`) control which operations the flow is considered relevant for.

The three source patterns map onto these examples as follows: query
`filter[user-ids]` → `query-param-bola.yaml`; body `username` → `body-field-bola.yaml`
(demonstrated). A body identity field such as `video_id` uses the same mechanism —
`body-field-bola.yaml` lists `video_id` in `body_field_names` and its comments show
the one-line body change to substitute it.
