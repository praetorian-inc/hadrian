# OWASP Test Templates for Vulnerable API

These Hadrian templates test for BOLA (Broken Object Level Authorization) and related vulnerabilities in the vulnerable-api test target.

## Template Execution Order

**Hadrian executes templates in alphabetical order by filename.** Templates are numbered with prefixes (01-, 02-, etc.) to ensure proper execution order:

| # | Template | Type | Destructive? |
|---|----------|------|--------------|
| 01 | `01-api1-bola-read.yaml` | Read (GET) | No |
| 02 | `02-api1-bola-document-access.yaml` | Read (GET) | No |
| 03 | `03-api3-sensitive-data-exposure.yaml` | Read (GET) | No |
| 04 | `04-api1-bola-horizontal-escalation.yaml` | Read/Write/Delete | Partially |
| 05 | `05-api5-function-level-authz.yaml` | Read (GET) | No |
| 06 | `06-api1-bola-write.yaml` | Write (PUT) | Modifies data |
| 07 | `07-api1-bola-profile-mutation.yaml` | Write (PUT) | Modifies data |
| 08 | `08-api1-bola-user-read.yaml` | Read (GET) | No |
| 09 | `09-api1-bola-order-read.yaml` | Read (GET) | No |
| 10 | `10-api1-bola-document-read.yaml` | Read (GET) | No |
| 11 | `11-api1-bola-user-write.yaml` | Write (PUT) | Modifies data |
| 12 | `12-api1-bola-profile-write.yaml` | Write (PUT) | Modifies data |
| 13 | `13-api1-bola-document-write.yaml` | Write (PUT/POST) | Modifies data |
| 14 | `14-api1-bola-delete.yaml` | Delete | **Yes** |
| 15 | `15-api1-bola-order-deletion-mutation.yaml` | Delete | **Yes** |

### Why Order Matters

- **01-05**: Non-destructive tests (read-only or admin protection checks)
- **06-07**: Modification tests (change data but don't delete)
- **08-13**: Additional read and write tests
- **14-15**: Deletion tests (permanently remove resources)

Running deletion tests first would remove test data, causing subsequent tests to fail.

### How Ordering Works

Hadrian's template loader (`pkg/owasp/loader.go` and `pkg/runner/run.go`) sorts all template files alphabetically by their full file path before execution. This guarantees deterministic, reproducible test ordering across all platforms.

To control execution order, prefix template filenames with numbers:
- `01-first-test.yaml` runs before `02-second-test.yaml`
- `09-last-test.yaml` runs after all single-digit prefixed templates

## Resetting Test Data

After running destructive tests, reset the API data:

```bash
# Option 1: Call the reset endpoint
curl -X POST http://localhost:8080/api/reset

# Option 2: Restart the API
# Stop the API (Ctrl+C) and restart it
AUTH_METHOD=api_key ./vulnerable-api
```

## Running Templates

```bash
# Run all templates in order
HADRIAN_TEMPLATES=./templates/owasp hadrian test \
  --api openapi.yaml \
  --roles roles.yaml \
  --auth auth-apikey.yaml \
  --allow-internal \
  --verbose

# Run only non-destructive templates (01-13)
HADRIAN_TEMPLATES=./templates/owasp hadrian test \
  --api openapi.yaml \
  --roles roles.yaml \
  --auth auth-apikey.yaml \
  --allow-internal \
  --template "0[1-9]-*" --template "1[0-3]-*"

# Run and then reset
hadrian test ... && curl -X POST http://localhost:8080/api/reset
```

## Template Categories

### OWASP API1:2023 - BOLA
- `01-api1-bola-read.yaml` - Unauthorized read access
- `02-api1-bola-document-access.yaml` - Private document access
- `04-api1-bola-horizontal-escalation.yaml` - Peer-to-peer access
- `06-api1-bola-write.yaml` - Unauthorized modifications
- `07-api1-bola-profile-mutation.yaml` - Verified profile changes
- `08-api1-bola-user-read.yaml` - User resource read access
- `09-api1-bola-order-read.yaml` - Order resource read access
- `10-api1-bola-document-read.yaml` - Document resource read access
- `11-api1-bola-user-write.yaml` - User resource write access
- `12-api1-bola-profile-write.yaml` - Profile resource write access
- `13-api1-bola-document-write.yaml` - Document resource write access
- `14-api1-bola-delete.yaml` - Unauthorized deletion
- `15-api1-bola-order-deletion-mutation.yaml` - Verified deletion

### OWASP API3:2023 - Broken Object Property Level Authorization
- `03-api3-sensitive-data-exposure.yaml` - SSN exposure via BOLA

### OWASP API5:2023 - BFLA
- `05-api5-function-level-authz.yaml` - Admin endpoint protection (should NOT find vulnerability)
