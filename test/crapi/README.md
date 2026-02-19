# crAPI Test Configuration for Hadrian

Configuration files for testing [OWASP crAPI](https://github.com/OWASP/crAPI) with Hadrian.

## Setup

### 1. Start crAPI

```bash
# Clone crAPI
git clone https://github.com/OWASP/crAPI.git

# Start with Docker Compose (note: compose file is in deploy/docker/)
cd crAPI/deploy/docker
docker-compose up -d
```

**Troubleshooting**: If containers fail with "No space left on device" errors, run `docker system prune -a` to free up disk space, then retry.

crAPI will be available at:
- **Web UI**: http://localhost:8888
- **Email (MailHog)**: http://localhost:8025

### 2. Create Test Users

Create accounts for each role:

```bash
# User 1 (regular user)
curl -X POST http://localhost:8888/identity/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"user1@test.com","name":"Test User 1","number":"1234567890","password":"TestPass123"}'

# User 2 (for BOLA testing)
curl -X POST http://localhost:8888/identity/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"user2@test.com","name":"Test User 2","number":"0987654321","password":"TestPass123"}'

# Mechanic
curl -X POST http://localhost:8888/workshop/api/mechanic/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"mechanic@test.com","name":"Test Mechanic","number":"5555555555","password":"TestPass123","mechanic_code":"MECH001"}'
```

### 3. Get JWT Tokens

Login with each user to get JWT tokens:

```bash
# Get user token
curl -X POST http://localhost:8888/identity/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user1@test.com","password":"TestPass123"}' | jq -r '.token'

# Get user2 token
curl -X POST http://localhost:8888/identity/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user2@test.com","password":"TestPass123"}' | jq -r '.token'

# Get mechanic token
curl -X POST http://localhost:8888/identity/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"mechanic@test.com","password":"TestPass123"}' | jq -r '.token'
```

### 4. Set Environment Variables

Create a `.env` file in this directory with your tokens:

```bash
# test/crapi/.env
CRAPI_USER_TOKEN=eyJ...
CRAPI_USER2_TOKEN=eyJ...
CRAPI_MECHANIC_TOKEN=eyJ...
CRAPI_ADMIN_TOKEN=eyJ...
```

Note: The `.env` file is gitignored to prevent committing secrets.

### 5. Upload Test Videos (Required for BFLA/BOPLA tests)

The BFLA and BOPLA mass assignment tests require each user to have an uploaded video:

```bash
# Run the setup script (requires .env file with tokens)
./test/crapi/setup-videos.sh
```

This script uploads test videos for user, user2, and mechanic accounts. The videos are required because:
- **BFLA test**: Detects if regular users can delete admin videos
- **BOPLA test**: Detects mass assignment via ID field injection in video updates

### 6. (Optional) Start Burp Suite

If you want to inspect requests in Burp Suite, start it and configure the proxy listener on `127.0.0.1:8080`.

### 7. Run Hadrian

From the repository root:

```bash
# Load environment variables and run tests
set -a && source test/crapi/.env && set +a && \
HADRIAN_TEMPLATES=test/crapi/templates/rest ./hadrian test \
  --api test/crapi/crapi-openapi-spec.json \
  --roles test/crapi/roles.yaml \
  --auth test/crapi/auth.yaml \
  --allow-internal

# Optional: add --verbose for detailed output
# Optional: add --proxy http://127.0.0.1:8080 to route through Burp Suite
```

## Expected Vulnerabilities

crAPI is intentionally vulnerable. Hadrian should detect:

| OWASP Category | Vulnerability | Endpoint Example | Template |
|----------------|---------------|------------------| -------- |
| API1:2023 | ✅ BOLA - Access other user's vehicle | `GET /identity/api/v2/vehicle/{vehicleId}/location` | `01-api1-bola-read.yaml` |
| API1:2023 | ✅ BOLA - Access other user's order | `GET /workshop/api/shop/orders/{order_id}` |  `01-api1-bola-read.yaml` |
| API2:2023 | ✅ Broken Auth - No rate limit on OTP | `POST /identity/api/auth/v2/check-otp` | `03-api2-otp-bruteforce` |
| API3:2023 | ✅ BOPLA - Mass assignment via ID injection | `PUT /identity/api/v2/user/videos/{video_id}` | `05-api3-bopla-mass-assignment.yaml` |
| API5:2023 | ✅ BFLA - User deleting admin videos | `DELETE /identity/api/v2/admin/videos/{video_id}` | `06-api5-bfla-admin-video-delete.yaml` |

## Expected No Vulnerabilities
crAPI is does not have the following vulnerability. Hadrian should not detect:

| OWASP Category | Vulnerability | Endpoint Example | Template |
|----------------|---------------|------------------| -------- |
| API1:2023 | ✅ BOLA - Access other user's video | `GET /identity/api/v2/user/videos/{video_id}` |  `02-api1-bola-video-mutation.yaml` |

## Roles Overview

| Role | Description | Token Env Var |
|------|-------------|---------------|
| `admin` | Full system access | `CRAPI_ADMIN_TOKEN` |
| `mechanic` | Service provider | `CRAPI_MECHANIC_TOKEN` |
| `user` | Regular vehicle owner | `CRAPI_USER_TOKEN` |
| `user2` | Second user for BOLA tests | `CRAPI_USER2_TOKEN` |
| `anonymous` | Unauthenticated | (none) |
