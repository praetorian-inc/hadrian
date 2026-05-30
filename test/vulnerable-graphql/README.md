# Vulnerable GraphQL Server

An **intentionally insecure** in-house Go binary that replaces the `dolevf/dvga` Docker image as the GraphQL test target for Hadrian's live-test harness.

It exposes the same GraphQL surface as DVGA so all existing Hadrian templates fire against it — without requiring Docker.

---

## WARNING

This server performs **real OS command execution** and **real file writes with path traversal**. Run it only in isolated test environments. Never expose it on a public network.

---

## Vulnerabilities

| Category | Location | Description |
|----------|----------|-------------|
| BOLA (API1) | `paste(id)`, `editPaste`, `deletePaste` | No ownership check — any user can read/modify/delete any paste |
| BFLA (API5) | `deleteAllPastes` | No authorisation — any caller can wipe all pastes |
| Sensitive data (API3) | `users { password }` | Plaintext password field exposed in schema |
| Command injection (API8) | `systemDiagnostics(cmd)` | `exec.Command("sh","-c",cmd)` — real RCE |
| Path traversal (API8) | `uploadPaste(filename)` | Writes to `filepath.Join(uploadDir, filename)` without sanitising `..` |
| Error disclosure (API8) | All resolvers | Verbose internal error messages in GraphQL response |
| No depth/complexity limits | All queries | Alias-DoS / field-duplication checks fire |
| Introspection | `/graphql` | Always enabled |

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/graphql` | GraphQL endpoint (query + mutation) |
| `GET` | `/health` | Health check — returns `{"status":"healthy"}` |
| `POST` | `/api/reset` | Reset in-memory data to initial seed state |
| `GET` | `/` | Banner |

---

## Seed Users

| Username | Password | ID | Role | Notes |
|----------|----------|----|------|-------|
| `admin` | `admin123` | 1 | admin | Admin user |
| `user1` | `user1pass` | 2 | user | Victim in BOLA tests (owns paste id=1) |
| `user2` | `user2pass` | 3 | user | Attacker in BOLA tests |

---

## Quick Start

```bash
# Build
make build

# Run on default port 5013
make run

# Run on custom port
make run-custom PORT=8080

# Run tests
make test
```

---

## Obtaining Tokens

```bash
# Log in and get a JWT
curl -s -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { login(username:\"admin\", password:\"admin123\") { accessToken } }"}' \
  | jq -r .data.login.accessToken
```

Export for use with `auth.yaml`:
```bash
export VULN_GRAPHQL_ADMIN_TOKEN=$(curl -s ... | jq -r .data.login.accessToken)
export VULN_GRAPHQL_USER1_TOKEN=$(...)
export VULN_GRAPHQL_USER2_TOKEN=$(...)
```

---

## Running Hadrian against this target

```bash
# Start the target
PORT=5013 ./test/vulnerable-graphql/vulnerable-graphql &

# Acquire tokens (see above) and export them

# Run Hadrian
HADRIAN_TEMPLATES=test/vulnerable-graphql/templates/owasp \
  ./hadrian test graphql \
    --api http://localhost:5013/graphql \
    --roles test/vulnerable-graphql/roles.yaml \
    --auth test/vulnerable-graphql/auth.yaml \
    --verbose
```

---

## Replacing DVGA Docker Image

This binary replaces `dolevf/dvga` at `http://localhost:5013/graphql`. The GraphQL schema, query/mutation names, field names, and argument names match DVGA's published interface so all existing templates work unchanged.

Key differences from DVGA:
- No Docker required — single statically-linked Go binary
- In-memory data store (no persistent DB)
- `POST /api/reset` to restore seed data between test runs
- Faster cold start for devcontainer CI
