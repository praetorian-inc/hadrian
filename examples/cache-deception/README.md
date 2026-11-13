# Web Cache Deception examples (ACTIVE, self-priming)

This directory holds the **active, two-phase** Web Cache Deception (WCD, CWE-525)
template. It reproduces the manual WCD methodology deterministically:

1. **PRIME** — authenticate as a scanner-controlled, self-scoped canary account
   and send `prime_repeat` (default 2) GETs to the target URL to warm the CDN/edge
   cache.
2. **REPLAY** — send one fully anonymous GET (no `Authorization`/`Cookie`/api-key)
   to the same URL.
3. **DETECT** — flag when the anonymous response is 2xx, carries an explicit
   cache-HIT header, and its body proves it is the victim's cached content.

| Template | Pattern | Class |
|----------|---------|-------|
| `12-api8-web-cache-deception-active.yaml` | `cache-deception` | authenticated response cached and served to an unauthenticated client |

This is distinct from the passive observational check
`templates/rest/12-api8-web-cache-deception.yaml`, which ships as a **safe
default** in `templates/rest/`: it sends a single unauthenticated GET and never
writes to a cache, so it only catches an already-warm exposure. The active test
here **warms the cache itself**, so it also catches cold-cache exposures — at the
cost of being intrusive.

## Safety / Rules of Engagement

- **Prime only with a self-scoped canary test account** whose response embeds no
  real third-party PII. The value the detector asserts on is that account's own
  data.
- The check **writes an authenticated response into a shared cache**, so it is an
  **active, intrusive** test. Confirm it is within engagement scope before running.
- It is **opt-in by design** (shipped under `examples/`, not `templates/rest/`) and
  never replaces the passive observational template.
- **Operator custom headers (`--header`) are intentionally NOT applied to the
  anonymous replay** — only to the priming requests. This preserves the
  unauthenticated invariant: an auth-bearing `--header` would otherwise
  authenticate the "anonymous" replay and produce an invalid leak finding.
  Cache-key-parity caveat: if a required **non-auth** header is needed for the CDN
  to key/serve the cache entry, dropping it on the replay can change the cache key
  and cause a **false negative**.
- **A query-parameter API key is omitted from the replay.** `buildCacheDeceptionPath`
  drops the victim role's api-key query parameter when its auth location is `query`,
  and `applyHeaders` adds the real key only to the authenticated prime — so the
  anonymous replay stays correctly key-free. Priming still keys the cache entry on
  `/path?api_key=…` while the replay hits the bare `/path`, a different cache key, so
  the test can silently **under-detect** (false negative) for query-based api-key targets.

## Capability used

The template relies on the `cache-deception` test pattern and its config block:

- `test_pattern: "cache-deception"` — routes the operation to the two-phase
  self-priming executor.
- `cache_deception.prime_repeat` — number of authenticated GETs used to warm the
  cache (default 2).
- `cache_deception.canary_field` — optional JSON path (dot/array notation) of a
  stable, self-scoped value in the authenticated body. When set, that value must
  appear in the anonymous body for a match (robust to per-request dynamic fields).
  Empty selects exact body-equality proof. Choose a **high-entropy, unique**
  field — `e.g. "email", "account_uuid"`, or a full name. **Do NOT use short or
  numeric fields** such as `"id"`: the value is matched by substring, so an id
  like `"1"` matches almost any body and yields false positives. Canary values
  shorter than 8 characters are rejected (treated as not-leaked) with a warning.
- `cache_deception.cache_hit_headers` — optional list of regexes (matched over
  `Header: value`) confirming an explicit cache HIT. Empty uses the built-in
  defaults (`CF-Cache-Status: HIT`, `X-Cache: ...HIT`).

## Running

```bash
HADRIAN_TEMPLATES=examples/cache-deception \
  ./hadrian test rest --api <spec> --roles <roles.yaml> --auth <auth.yaml> \
  --category all --verbose
```

Two things the flags above are load-bearing for:

- **`test rest`** (not just `test`): `--api`/`--roles`/`--auth` are registered on
  the `test rest` subcommand.
- **`--category all`**: `--category` defaults to `owasp` and matches exactly
  (case-insensitive) against `info.category`/`info.tags`. This template is
  `category: API8:2023` (tagged `owasp-api-top10`, not `owasp`), so it loads only
  under `--category all` — or `--category api8` / `--category API8:2023`. Without
  one of these you get `Loaded 0 templates`.

## Adapting to your target

Set `cache_deception.canary_field` to a stable field on your canary account when
the authenticated response varies per request (timestamps, request IDs, cursors);
otherwise the default exact body-equality proof yields false negatives. Override
`cache_hit_headers` if your CDN signals a hit with a non-default header.
