# crAPI Test Configuration for Hadrian

Configuration files for testing [OWASP crAPI](https://github.com/OWASP/crAPI) with Hadrian.

## Recommended: automated setup

`test/setup-live-targets.sh` handles everything below — clone, start,
patch the compose to bind crAPI to your chosen port, sign up the
canonical users, and write a config file `run-live-tests.sh` and
`test-llm-planner.sh` consume:

```bash
# From the repository root
./test/setup-live-targets.sh --targets crapi
./test/run-live-tests.sh     --targets crapi
```

See [`test/README.md`](../README.md) for the full workflow, including
port-override env vars and `--teardown --purge`.

### Canonical users (created by `setup-live-targets.sh`)

The setup script signs up these accounts via
[`crapi-helpers.sh`](crapi-helpers.sh). All values are overridable via
environment variables of the same name before invoking setup.

| Role     | Email                          | Phone        | Password (`CRAPI_PASSWORD`) |
|----------|--------------------------------|--------------|-----------------------------|
| admin    | `hadrian-admin@test.com`       | `1111111111` | `HadrianTest123!`           |
| user     | `hadrian-user1@test.com`       | `2222222222` | `HadrianTest123!`           |
| user2    | `hadrian-user2@test.com`       | `3333333333` | `HadrianTest123!`           |
| mechanic | `hadrian-mechanic@test.com`    | `4444444444` | `HadrianTest123!` (`mechanic_code` `TRAC_MECH1`) |

`setup-live-targets.sh` also writes a port-patched copy of
`crapi-openapi-spec.json` to `test/.live-test-cache/` and emits its path
as `CRAPI_SPEC_FILE` in `.live-test-config`. Downstream scripts read
that path so they always point hadrian at the port crAPI is actually
listening on, regardless of upstream's compose default.

## Manual setup (fallback)

If you'd rather start crAPI by hand — for development, debugging
upstream compose issues, or running hadrian without the wrapper
scripts — these are the underlying steps.

### 1. Start crAPI

```bash
git clone https://github.com/OWASP/crAPI.git
cd crAPI/deploy/docker
docker compose up -d
```

**Troubleshooting**: If containers fail with "No space left on device"
errors, run `docker system prune -a` to free up disk space, then retry.

crAPI will be available at:
- **Web UI**: http://localhost:8888 (set by `setup-live-targets.sh` via
  the compose patch; upstream's current default is 8889 — check
  `docker port crapi-web 80`)
- **Email (MailHog)**: http://localhost:8025

### 2. Create test users

You can run the canonical-roster signup with one call:

```bash
. test/crapi/crapi-helpers.sh
crapi_setup_users http://localhost:8888
```

Or do it manually with `curl`. The values below match the **canonical
roster** that `crapi-helpers.sh` provisions, so `run-live-tests.sh` and
`test-llm-planner.sh` will recognize the accounts you create here:

```bash
# user1 — canonical "user" role
curl -X POST http://localhost:8888/identity/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"hadrian-user1@test.com","name":"Hadrian User1","number":"2222222222","password":"HadrianTest123!"}'

# user2 — canonical "user2" role (BOLA target)
curl -X POST http://localhost:8888/identity/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"hadrian-user2@test.com","name":"Hadrian User2","number":"3333333333","password":"HadrianTest123!"}'

# mechanic — canonical "mechanic" role
curl -X POST http://localhost:8888/workshop/api/mechanic/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"hadrian-mechanic@test.com","name":"Hadrian Mechanic","number":"4444444444","password":"HadrianTest123!","mechanic_code":"TRAC_MECH1"}'
```

### 3. Get JWT tokens

```bash
curl -X POST http://localhost:8888/identity/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"hadrian-user1@test.com","password":"HadrianTest123!"}' | jq -r '.token'

curl -X POST http://localhost:8888/identity/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"hadrian-user2@test.com","password":"HadrianTest123!"}' | jq -r '.token'

curl -X POST http://localhost:8888/identity/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"hadrian-mechanic@test.com","password":"HadrianTest123!"}' | jq -r '.token'
```

### 4. Set environment variables

Create a `.env` file in this directory with your tokens:

```bash
# test/crapi/.env
CRAPI_USER_TOKEN=eyJ...
CRAPI_USER2_TOKEN=eyJ...
CRAPI_MECHANIC_TOKEN=eyJ...
CRAPI_ADMIN_TOKEN=eyJ...
```

Note: The `.env` file is gitignored to prevent committing secrets.

### 5. Upload test videos (required for BFLA/BOPLA tests)

The BFLA and BOPLA mass assignment tests require each user to have an
uploaded video:

```bash
./test/crapi/setup-videos.sh
```

This script uploads test videos for user, user2, and mechanic accounts.
The videos are required because:
- **BFLA test**: Detects if regular users can delete admin videos
- **BOPLA test**: Detects mass assignment via ID field injection in video updates

`run-live-tests.sh` does the equivalent video upload automatically.

### 6. (Optional) Start Burp Suite

If you want to inspect requests in Burp Suite, start it and configure
the proxy listener on `127.0.0.1:8080`.

### 7. Run Hadrian

```bash
set -a && source test/crapi/.env && set +a && \
HADRIAN_TEMPLATES=test/crapi/templates/rest ./hadrian test \
  --api test/crapi/crapi-openapi-spec.json \
  --roles test/crapi/roles.yaml \
  --auth test/crapi/auth.yaml

# Optional: add --verbose for detailed output
# Optional: add --proxy http://127.0.0.1:8080 to route through Burp Suite
```

## Expected vulnerabilities

crAPI is intentionally vulnerable. Hadrian should detect:

| OWASP Category | Vulnerability | Endpoint Example | Template |
|----------------|---------------|------------------| -------- |
| API1:2023 | BOLA - Access other user's vehicle | `GET /identity/api/v2/vehicle/{vehicleId}/location` | `01-api1-bola-read.yaml` |
| API1:2023 | BOLA - Access other user's order | `GET /workshop/api/shop/orders/{order_id}` |  `01-api1-bola-read.yaml` |
| API2:2023 | Broken Auth - No rate limit on OTP | `POST /identity/api/auth/v2/check-otp` | `03-api2-otp-bruteforce` |
| API3:2023 | BOPLA - Mass assignment via ID injection | `PUT /identity/api/v2/user/videos/{video_id}` | `05-api3-bopla-mass-assignment.yaml` |
| API5:2023 | BFLA - User deleting admin videos | `DELETE /identity/api/v2/admin/videos/{video_id}` | `06-api5-bfla-admin-video-delete.yaml` |

## Expected absence of vulnerabilities

crAPI does not have the following vulnerability. Hadrian should not detect:

| OWASP Category | Vulnerability | Endpoint Example | Template |
|----------------|---------------|------------------| -------- |
| API1:2023 | BOLA - Access other user's video | `GET /identity/api/v2/user/videos/{video_id}` |  `02-api1-bola-video-mutation.yaml` |

## Roles overview

| Role | Description | Token Env Var |
|------|-------------|---------------|
| `admin` | Full system access | `CRAPI_ADMIN_TOKEN` |
| `mechanic` | Service provider | `CRAPI_MECHANIC_TOKEN` |
| `user` | Regular vehicle owner | `CRAPI_USER_TOKEN` |
| `user2` | Second user for BOLA tests | `CRAPI_USER2_TOKEN` |
| `anonymous` | Unauthenticated | (none) |
