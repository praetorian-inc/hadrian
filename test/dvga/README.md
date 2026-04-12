# DVGA Test Configuration for Hadrian

Configuration files for testing [DVGA (Damn Vulnerable GraphQL Application)](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) with Hadrian's GraphQL security scanning.

## Setup

### 1. Start DVGA

```bash
# Run DVGA in Docker
docker run -d -p 5013:5013 --name dvga dolevf/dvga:latest

# Or use docker-compose
docker compose up -d dvga
```

DVGA will be available at:
- **GraphQL Playground**: http://localhost:5013/graphql
- **GraphiQL IDE**: http://localhost:5013/graphiql

**Troubleshooting**: If the container fails to start, run `docker system prune -a` to free up disk space, then retry.

### 2. Verify DVGA is Running

```bash
# Test introspection endpoint
curl -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

You should receive a JSON response with GraphQL type names.

### 3. Create Test Users

Create accounts for authentication testing:

```bash
# Create admin user
curl -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { createUser(username: \"admin\", password: \"admin123\") { username } }"}'

# Create regular user
curl -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { createUser(username: \"user1\", password: \"user123\") { username } }"}'

# Create second user (for BOLA testing)
curl -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { createUser(username: \"user2\", password: \"user456\") { username } }"}'
```

### 4. Get JWT Tokens

Login with each user to get JWT tokens:

```bash
# Get admin token
curl -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { login(username: \"admin\", password: \"admin123\") { accessToken } }"}' | jq -r '.data.login.accessToken'

# Get user1 token
curl -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { login(username: \"user1\", password: \"user123\") { accessToken } }"}' | jq -r '.data.login.accessToken'

# Get user2 token
curl -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { login(username: \"user2\", password: \"user456\") { accessToken } }"}' | jq -r '.data.login.accessToken'
```

### 5. Set Environment Variables

Create a `.env` file in this directory with your tokens:

```bash
# test/dvga/.env
DVGA_ADMIN_TOKEN=eyJ...
DVGA_USER1_TOKEN=eyJ...
DVGA_USER2_TOKEN=eyJ...
```

Note: The `.env` file is gitignored to prevent committing secrets.

### 6. Update Auth Configuration

Update `auth.yaml` with the tokens:

```yaml
method: bearer
location: header
key_name: Authorization

roles:
  admin:
    token: "eyJ..."  # DVGA_ADMIN_TOKEN
  user:
    token: "eyJ..."  # DVGA_USER1_TOKEN
  user2:
    token: "eyJ..."  # DVGA_USER2_TOKEN
  anonymous:
    token: ""
```

### 7. Run Hadrian

From the repository root:

**Option A: With DVGA-Specific Templates (Recommended)**

```bash
# Build Hadrian
go build -o hadrian ./cmd/hadrian

# Run with DVGA-specific templates
./hadrian test graphql \
  --target http://localhost:5013 \
  --schema test/dvga/schema.graphql \
  --template-dir test/dvga/templates/owasp \
  --verbose
```

**Option B: With Authentication for BOLA/BFLA Testing**

```bash
# Load environment variables and run tests
set -a && source test/dvga/.env && set +a && \
./hadrian test graphql \
  --target http://localhost:5013 \
  --schema test/dvga/schema.graphql \
  --template-dir test/dvga/templates/owasp \
  --auth test/dvga/auth.yaml \
  --roles test/dvga/roles.yaml \
  --verbose
```

**Option C: With Generic GraphQL Templates**

```bash
# Run all GraphQL attack templates (uses default template directory)
./hadrian test graphql \
  --target http://localhost:5013 \
  --verbose
```

**Option D: Output to JSON**

```bash
./hadrian test graphql \
  --target http://localhost:5013 \
  --template-dir test/dvga/templates/owasp \
  --output json \
  --output-file dvga-results.json
```

## Expected Vulnerabilities

DVGA is intentionally vulnerable. Hadrian should detect:

### DVGA-Specific Templates (`test/dvga/templates/owasp/`)

| OWASP Category | Vulnerability | Template | Severity |
|----------------|---------------|----------|----------|
| API1:2023 | BOLA - Access other user's pastes | `api1-bola-dvga.yaml` | HIGH |
| API3:2023 | Sensitive Data Exposure in user queries | `03-api3-sensitive-data-exposure-dvga.yaml` | MEDIUM |
| API7:2023 | SSRF via `importPaste` mutation | `api7-ssrf-dvga.yaml` | HIGH |
| API8:2023 | Command Injection via `systemDiagnostics` | `04-api8-command-injection-dvga.yaml` | CRITICAL |
| API8:2023 | Path Traversal via `uploadPaste` filename | `06-api8-path-traversal-dvga.yaml` | HIGH |
| API8:2023 | GraphQL Error Information Disclosure | `05-api8-information-disclosure-dvga.yaml` | LOW |

### Generic GraphQL Templates (`templates/graphql/`)

| OWASP Category | Vulnerability | Template | Severity |
|----------------|---------------|----------|----------|
| API8:2023 | Introspection enabled | `13-api8-introspection-disclosure.yaml` | MEDIUM |
| API4:2023 | No query depth limit (DoS) | `08-api4-depth-attack.yaml` | HIGH |
| API4:2023 | No batch query limit (DoS) | `06-api4-batching-attack.yaml` | HIGH |
| API4:2023 | Alias-based DoS | `05-api4-alias-dos-attack.yaml` | HIGH |
| API8:2023 | Error information leakage | `12-api8-error-disclosure.yaml` | MEDIUM |

## DVGA Vulnerable Endpoints

DVGA exposes these intentionally vulnerable GraphQL operations:

| Operation | Type | Vulnerability |
|-----------|------|---------------|
| `systemDiagnostics` | Query | OS Command Injection (RCE) |
| `importPaste` | Mutation | Server-Side Request Forgery (SSRF) |
| `uploadPaste` | Mutation | Path Traversal / Arbitrary File Write |
| `paste(id)` | Query | IDOR / BOLA (access any paste by ID) |
| `users` | Query | Sensitive Data Exposure (lists all users) |
| `systemHealth` | Query | Information Disclosure |

## Roles Overview

| Role | Description | Token Env Var |
|------|-------------|---------------|
| `admin` | Full system access | `DVGA_ADMIN_TOKEN` |
| `user` | Regular user | `DVGA_USER1_TOKEN` |
| `user2` | Second user for BOLA tests | `DVGA_USER2_TOKEN` |
| `anonymous` | Unauthenticated | (none) |

## Troubleshooting

### DVGA Not Responding

```bash
# Check if container is running
docker ps | grep dvga

# Check container logs
docker logs dvga

# Restart container
docker restart dvga
```

### Connection Refused

- Ensure DVGA is running on port 5013
- Check firewall/network settings
- Check firewall settings when testing local/Docker endpoints

### No Findings Reported

- Use `--verbose` flag for detailed output
- Verify templates are being loaded: check "Loaded N template(s)" message
- Some tests require authenticated requests - ensure tokens are valid

### Schema Loading Issues

```bash
# Test with introspection (default)
./hadrian test graphql --target http://localhost:5013

# Or use local SDL schema file
./hadrian test graphql \
  --target http://localhost:5013 \
  --schema test/dvga/schema.graphql
```

## Integration Tests

Run Hadrian's integration tests against DVGA:

```bash
export DVGA_ENDPOINT="http://localhost:5013/graphql"
cd /workspaces/hadrian
go test -tags=integration ./pkg/plugins/graphql/... -v
```

## Files in This Directory

| File | Purpose |
|------|---------|
| `schema.graphql` | DVGA GraphQL SDL schema |
| `auth.yaml` | Authentication configuration |
| `roles.yaml` | Role definitions and permissions |
| `templates/owasp/` | DVGA-specific OWASP vulnerability templates |
| `.env` | Environment variables (gitignored) |
