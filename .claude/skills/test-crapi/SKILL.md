---
name: test-crapi
description: Run Hadrian security tests against a local crAPI instance with automatic setup
allowed-tools: "Read, Write, Bash"
---

# Test Hadrian against crAPI

Run Hadrian security tests against a local crAPI instance with automatic setup.

## Preconditions

Before running tests, verify and set up the following:

### 1. Check if crAPI is running

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/identity/api/auth/signup
```

If this returns 000 or connection refused, crAPI is not running. Inform the user:
- Clone crAPI: `git clone https://github.com/OWASP/crAPI.git`
- Start it: `cd crAPI/deploy/docker && docker-compose up -d`
- Wait for services to be ready (may take a minute)

### 2. Create test users (if they don't exist)

Try to create each user. If they already exist, the API will return an error which is fine.

```bash
# User 1
curl -s -X POST http://localhost:8888/identity/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"user1@test.com","name":"Test User 1","number":"1234567890","password":"TestPass123"}'

# User 2
curl -s -X POST http://localhost:8888/identity/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"user2@test.com","name":"Test User 2","number":"0987654321","password":"TestPass123"}'

# Mechanic
curl -s -X POST http://localhost:8888/workshop/api/mechanic/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"mechanic@test.com","name":"Test Mechanic","number":"5555555555","password":"TestPass123","mechanic_code":"MECH001"}'
```

### 3. Get fresh JWT tokens

Login with each user and capture the tokens:

```bash
# Get tokens
USER_TOKEN=$(curl -s -X POST http://localhost:8888/identity/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user1@test.com","password":"TestPass123"}' | jq -r '.token')

USER2_TOKEN=$(curl -s -X POST http://localhost:8888/identity/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user2@test.com","password":"TestPass123"}' | jq -r '.token')

MECHANIC_TOKEN=$(curl -s -X POST http://localhost:8888/identity/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"mechanic@test.com","password":"TestPass123"}' | jq -r '.token')
```

### 4. Write the .env file

Write the tokens to `testdata/crapi/.env`:

```
CRAPI_USER_TOKEN=<user_token>
CRAPI_USER2_TOKEN=<user2_token>
CRAPI_MECHANIC_TOKEN=<mechanic_token>
```

## Build and Run

### 5. Build the binary

```bash
go build -o hadrian ./cmd/hadrian
```

### 6. Run the tests

```bash
set -a && source testdata/crapi/.env && set +a && \
HADRIAN_TEMPLATES=testdata/crapi/templates/owasp ./hadrian test \
  --api testdata/crapi/crapi-openapi-spec.json \
  --roles testdata/crapi/roles.yaml \
  --auth testdata/crapi/auth.yaml \
  --allow-internal
```

## Arguments

If the user provides arguments like `--verbose` or `--proxy http://127.0.0.1:8080`, append them to the hadrian command.

## Output

Report the test results to the user, summarizing:
- Number of findings by severity (HIGH, MEDIUM, LOW)
- Key vulnerabilities found
- Any errors or skipped tests
