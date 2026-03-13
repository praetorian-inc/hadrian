# Vulnerable API - BOLA Testing

This is an intentionally vulnerable REST API for testing Hadrian's OWASP API security testing capabilities, specifically for detecting **Broken Object Level Authorization (BOLA)** vulnerabilities.

## ⚠️ WARNING

**THIS IS A VULNERABLE APPLICATION FOR TESTING ONLY.**

- Do NOT deploy to production
- Do NOT expose to the internet
- Use only in isolated test environments

## Overview

The API implements authentication but deliberately **omits authorization checks**, allowing any authenticated user to access resources belonging to other users by simply changing the ID in the URL.

## Quick Start

```bash
# Install dependencies
go mod download

# Run with default settings (Bearer JWT auth, port 8889)
go run main.go

# Run with API key authentication
AUTH_METHOD=api_key go run main.go

# Run with Basic auth
AUTH_METHOD=basic go run main.go

# Run on custom port
PORT=9000 go run main.go
```

## Authentication Methods

Configure via `AUTH_METHOD` environment variable:

### 1. Bearer (JWT) - Default

```bash
# Login
curl -X POST http://localhost:8889/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"user1pass"}'

# Response includes token
{"user":{...},"token":"eyJhbGciOiJIUzI1NiIs..."}

# Use token in requests
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  http://localhost:8889/api/users/1
```

### 2. API Key

```bash
AUTH_METHOD=api_key go run main.go

# Login returns API key
curl -X POST http://localhost:8889/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"user1pass"}'

# Response includes api_key
{"user":{...},"api_key":"user1-api-key-67890"}

# Use API key in requests
curl -H "X-API-Key: user1-api-key-67890" \
  http://localhost:8889/api/users/1
```

### 3. Basic Authentication

```bash
AUTH_METHOD=basic go run main.go

# Use Basic Auth in requests (no login needed)
curl -u user1:user1pass http://localhost:8889/api/users/1
```

## Test Users

| Username | Password  | Role  | API Key               |
|----------|-----------|-------|-----------------------|
| admin    | admin123  | admin | admin-api-key-12345   |
| user1    | user1pass | user  | user1-api-key-67890   |
| user2    | user2pass | user  | user2-api-key-abcde   |

## Endpoints

### Public (No Authentication)

- `GET /health` - Health check
- `GET /api/public/documents` - List public documents
- `GET /api/public/documents/{id}` - Get public document

### Authentication

- `POST /api/auth/login` - Login (returns token/API key)
- `GET /api/auth/me` - Get current user

### 🔴 BOLA Vulnerable Endpoints

**These endpoints authenticate the user but do NOT check if the user owns the resource.**

#### Users
- `GET /api/users/{id}` - Get any user's data
- `PUT /api/users/{id}` - Update any user's data
- `DELETE /api/users/{id}` - Delete any user

#### Profiles (SSN Exposure!)
- `GET /api/profiles/{id}` - Access any user's profile (includes SSN!)
- `PUT /api/profiles/{id}` - Modify any user's profile

#### Orders
- `GET /api/orders/{id}` - View any user's orders
- `POST /api/orders` - Create order (can set any user_id)
- `DELETE /api/orders/{id}` - Delete any user's orders

#### Documents
- `GET /api/documents/{id}` - Read any document (including private!)
- `POST /api/documents` - Create document (can set any user_id)
- `PUT /api/documents/{id}` - Modify any document
- `DELETE /api/documents/{id}` - Delete any document

### 🟢 Admin-Only Endpoints (Properly Protected)

- `GET /api/admin/users` - List all users (admin only)
- `GET /api/admin/stats` - Get statistics (admin only)

## BOLA Vulnerability Examples

### Example 1: Access Another User's Profile (SSN Exposure)

```bash
# Login as user1 (ID: 2)
TOKEN=$(curl -s -X POST http://localhost:8889/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"user1pass"}' | jq -r '.token')

# VULNERABILITY: user1 can access user2's profile (ID: 3)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8889/api/profiles/3

# Response includes SSN!
{
  "id": 3,
  "user_id": 3,
  "full_name": "User Two",
  "ssn": "345-67-8901",
  "phone_number": "555-0003",
  "address": "789 User Blvd"
}
```

### Example 2: Delete Another User's Order

```bash
# Login as user2 (ID: 3)
TOKEN=$(curl -s -X POST http://localhost:8889/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user2","password":"user2pass"}' | jq -r '.token')

# VULNERABILITY: user2 can delete user1's order (order ID: 2 belongs to user1)
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:8889/api/orders/2

# Returns 204 No Content - order deleted!
```

### Example 3: Read Private Documents

```bash
# Login as user2
TOKEN=$(curl -s -X POST http://localhost:8889/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user2","password":"user2pass"}' | jq -r '.token')

# VULNERABILITY: user2 can read user1's private document (ID: 4)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8889/api/documents/4

# Response includes private content!
{
  "id": 4,
  "user_id": 2,
  "title": "User1 Private Doc",
  "content": "Private user1 content with SSN",
  "is_private": true,
  "created_at": "..."
}
```

## Seed Data

### Profiles
- Profile ID 1 (admin): SSN `123-45-6789`
- Profile ID 2 (user1): SSN `234-56-7890`
- Profile ID 3 (user2): SSN `345-67-8901`

### Orders
- Order ID 1: admin's order
- Order ID 2-3: user1's orders
- Order ID 4: user2's order

### Documents
- Doc ID 1: admin public
- Doc ID 2: admin private
- Doc ID 3: user1 public
- Doc ID 4: user1 private

## Testing with Hadrian

This API is designed to be tested with Hadrian's OWASP API security scanner.

### Quick Test (All Auth Methods)

```bash
# Run the comprehensive test script
./run-all-auth-tests.sh

# Or use Make targets
make test-all       # All auth methods
make test-bearer    # Bearer JWT only
make test-apikey    # API Key only
make test-basic     # Basic Auth only
```

### Manual Testing

```bash
# Start the API
AUTH_METHOD=api_key ./vulnerable-api &

# Run Hadrian with templates
HADRIAN_TEMPLATES=./templates/rest hadrian test \
  --api openapi.yaml \
  --roles roles.yaml \
  --auth auth-apikey.yaml \
  --verbose

# Reset data after tests
curl -X POST http://localhost:8889/api/reset
```

### Template Execution Order

**Hadrian executes templates in alphabetical order by filename.** The included templates are numbered to ensure proper execution:

| Order | Template | Type |
|-------|----------|------|
| 01-05 | Read tests | Non-destructive |
| 06-07 | Write tests | Modifies data |
| 08-13 | Additional read/write tests | Mixed |
| 14-15 | Delete tests | Destructive |

This ordering ensures read-only tests run first, and destructive deletion tests run last. Use `--reset-between-tests` flag if you need data reset between individual template executions.

### Expected Findings

Hadrian should detect:
- Unauthorized access to other users' data
- SSN exposure through profile endpoints
- Ability to modify/delete other users' resources
- Private document access without ownership checks

## Logging

The API logs BOLA access attempts to stdout:

```
[BOLA] User user1 (ID: 2, Role: user) accessing /api/users/3
[BOLA] SSN Exposure: Profile ID 3 accessed
[BOLA] Private document access: Doc ID 4 accessed
[BOLA] Order deletion: Order ID 2 deleted by unauthorized user
```

## How BOLA Works (The Vulnerability)

**What it SHOULD do:**
```go
func handleUsers(w http.ResponseWriter, r *http.Request, id int) {
    currentUser := getCurrentUser(r)

    // ✅ Proper authorization check
    if user.ID != currentUser.ID && currentUser.Role != "admin" {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Only reached if authorized
    return user
}
```

**What it DOES (vulnerability):**
```go
func handleUsers(w http.ResponseWriter, r *http.Request, id int) {
    // ❌ No authorization check!
    // Any authenticated user can access any user's data
    return user
}
```

The API verifies the user is authenticated (valid token/API key) but never checks if they're authorized to access the specific resource.

## License

MIT (for testing purposes only)
