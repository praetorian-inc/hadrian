# vulnerable-rest-complex

A deliberately vulnerable multi-resource REST API for testing Hadrian's OWASP API security
capabilities.  Replaces the old crAPI Docker target — runs as a single Go binary with **no
Docker required**, making it usable inside devcontainers.

The server mirrors crAPI's multi-resource shape: vehicles + mechanics + orders + customers,
with intentional cross-tenant authorization bugs.

## Quick Start

```bash
make build
./vulnerable-rest-complex          # listens on :8888
# or
PORT=9000 ./vulnerable-rest-complex
```

## Seed Credentials

| Username   | Password   | Role     | ID |
|------------|------------|----------|----|
| admin      | admin123   | admin    | 1  |
| user1      | user1pass  | user     | 2  |
| user2      | user2pass  | user     | 3  |
| mechanic1  | mech1pass  | mechanic | 4  |

`user1` is the **victim** (higher privilege, level 50).
`user2` is the **attacker** (lower privilege, level 5).

## Endpoints

| Method    | Path                               | OWASP Class           | Notes                                    |
|-----------|------------------------------------|-----------------------|------------------------------------------|
| GET       | /health                            | —                     | Public health check                      |
| POST      | /api/auth/login                    | —                     | Returns HS256 JWT                        |
| POST      | /api/auth/check-otp                | API2 — Rate Limit     | No rate limiting                         |
| POST      | /api/reset                         | —                     | Re-seeds in-memory data                  |
| GET       | /api/dashboard                     | API3 — Excessive Data | Returns role, ssn, payment_card          |
| GET       | /api/customers/{id}                | API1 — BOLA + API3    | No ownership check; exposes ssn, card    |
| GET       | /api/vehicles/{id}                 | API1 — BOLA           | No ownership check                       |
| PUT       | /api/vehicles/{id}                 | API3 — Mass Assignment| Honors id/customer_id/owner_id from body |
| GET       | /api/orders/{id}                   | API1 — BOLA           | No ownership check; exposes card_last4   |
| POST      | /api/orders                        | API3 — Mass Assignment| Honors customer_id/price/status from body|
| POST      | /api/mechanic/service-requests     | API5 — BFLA           | No role check; returns report_id         |
| DELETE    | /api/admin/vehicles/{id}           | API5 — BFLA           | No role check; vehicle removed           |
| GET       | /api/admin/reports                 | — (protected)         | 403 for non-admin (negative control)     |

## Intentional Vulnerabilities

### API1:2023 — BOLA (Broken Object Level Authorization)
- `GET /api/customers/{id}` — any authed user reads any customer's full record
- `GET /api/vehicles/{id}` — any authed user reads any vehicle
- `GET /api/orders/{id}` — any authed user reads any order

### API2:2023 — Broken Authentication (Rate Limiting)
- `POST /api/auth/check-otp` — no rate limiting on OTP verification

### API3:2023 — Broken Object Property Level Authorization
- **Excessive data exposure**: `/api/dashboard` and `/api/customers/{id}` return `ssn`,
  `payment_card`, and `role`
- **Mass assignment**: `PUT /api/vehicles/{id}` honors `id`, `customer_id`, `owner_id` from body
- **Mass assignment**: `POST /api/orders` honors `customer_id`, `price`, `status` from body

### API5:2023 — Broken Function Level Authorization (BFLA)
- `POST /api/mechanic/service-requests` — mechanic-only function, no role check
- `DELETE /api/admin/vehicles/{id}` — admin-only function, no role check

## Running Hadrian Against This Target

```bash
# 1. Start the server
./vulnerable-rest-complex &

# 2. Acquire tokens
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8888/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | jq -r .token)
USER1_TOKEN=$(curl -s -X POST http://localhost:8888/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"user1","password":"user1pass"}' | jq -r .token)
USER2_TOKEN=$(curl -s -X POST http://localhost:8888/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"user2","password":"user2pass"}' | jq -r .token)
MECHANIC_TOKEN=$(curl -s -X POST http://localhost:8888/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"mechanic1","password":"mech1pass"}' | jq -r .token)

# 3. Export env vars for auth-bearer.yaml
export VULN_REST_COMPLEX_ADMIN_TOKEN="$ADMIN_TOKEN"
export VULN_REST_COMPLEX_USER1_TOKEN="$USER1_TOKEN"
export VULN_REST_COMPLEX_USER2_TOKEN="$USER2_TOKEN"
export VULN_REST_COMPLEX_MECHANIC_TOKEN="$MECHANIC_TOKEN"

# 4. Run hadrian
hadrian test rest \
  --api test/vulnerable-rest-complex/openapi.yaml \
  --roles test/vulnerable-rest-complex/roles.yaml \
  --auth test/vulnerable-rest-complex/auth-bearer.yaml \
  --templates test/vulnerable-rest-complex/templates/owasp \
  --verbose
```

## Templates

Templates live in `templates/owasp/` and cover the same OWASP classes as the crAPI templates:

| File | OWASP Class | Test |
|------|-------------|------|
| 01-api1-bola-read.yaml | API1 BOLA | Generic cross-tenant GET with path param |
| 02-api1-bola-vehicle-mutation.yaml | API1 BOLA | Multi-phase: dashboard → vehicle read as attacker |
| 03-api2-otp-bruteforce.yaml | API2 Rate Limit | 35 rapid OTP attempts, expect no 429 |
| 04-api3-bopla-excessive-data-exposure.yaml | API3 Excessive Data | Dashboard returns role/ssn |
| 05-api3-bopla-mass-assignment.yaml | API3 Mass Assignment | PUT vehicle with injected customer_id |
| 06-api5-bfla-admin-delete.yaml | API5 BFLA | Non-admin deletes vehicle via admin endpoint |
