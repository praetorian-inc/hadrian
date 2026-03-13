# Vulnerable API Implementation Summary

## Overview

This is a Go REST API application intentionally vulnerable to BOLA (Broken Object Level Authorization) for testing Hadrian's OWASP API security testing capabilities.

## Implementation Details

### Files Created

1. **main.go** (19KB) - Single-file Go application implementing:
   - Three authentication methods (Bearer JWT, API Key, Basic Auth)
   - In-memory data store with seed data
   - Public, authenticated, and admin-only endpoints
   - BOLA vulnerabilities (authentication without authorization)
   - Proper admin protection for comparison

2. **go.mod** - Go module definition with jwt/v5 dependency

3. **README.md** (7.1KB) - Comprehensive documentation including:
   - Quick start guide
   - Authentication method details
   - Test user credentials
   - Endpoint documentation
   - BOLA vulnerability examples with curl commands
   - Integration with Hadrian

4. **test-bola.sh** - Automated test script verifying:
   - All three test users can login
   - BOLA vulnerabilities work as expected
   - SSN exposure through profile endpoints
   - Cross-user resource access
   - Admin endpoints properly protected

5. **Makefile** - Build automation with targets:
   - build, run, run-apikey, run-basic, test, clean

6. **.gitignore** - Excludes binaries and build artifacts

## Authentication Methods

Configurable via `AUTH_METHOD` environment variable:

### 1. Bearer (JWT) - Default
- Uses github.com/golang-jwt/jwt/v5
- 24-hour token expiration
- HMAC-SHA256 signing

### 2. API Key
- Fixed API keys per user
- Passed in X-API-Key header

### 3. Basic Authentication
- Standard HTTP Basic Auth
- Base64 encoded username:password

## Data Models

### User
- id, username, email, role (admin/user), password, api_key
- 3 seeded users: admin, user1, user2

### Profile (Sensitive!)
- id, user_id, full_name, **ssn**, phone_number, address
- Contains SSN - critical for testing data exposure

### Order
- id, user_id, product, amount, status, created_at
- 4 seeded orders across all users

### Document
- id, user_id, title, content, is_private, created_at
- Mix of public and private documents

## Endpoint Categories

### Public (No Auth)
- GET /health
- GET /api/public/documents
- GET /api/public/documents/{id}

### Auth Endpoints
- POST /api/auth/login
- GET /api/auth/me

### BOLA Vulnerable Endpoints

**Critical: These authenticate but DO NOT authorize**

- GET/PUT/DELETE /api/users/{id}
- GET/PUT /api/profiles/{id} - **SSN EXPOSURE**
- GET/POST/DELETE /api/orders/{id}
- GET/POST/PUT/DELETE /api/documents/{id} - **PRIVATE DOC ACCESS**

### Admin-Only Endpoints (Properly Protected)

For comparison with vulnerable endpoints:

- GET /api/admin/users
- GET /api/admin/stats

## The BOLA Vulnerability

### What It Does

The `authMiddleware` function:
1. ✅ Validates authentication (token/API key/basic auth)
2. ✅ Loads user from credentials
3. ✅ Stores user in request context
4. ❌ **NEVER checks if user owns the requested resource**

### Example Vulnerable Code

```go
func handleProfiles(w http.ResponseWriter, r *http.Request) {
    id, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/profiles/"))

    // BOLA VULNERABILITY: No ownership check!
    // currentUser := getCurrentUser(r)
    // if profile.UserID != currentUser.ID { return 403 }

    for _, profile := range profiles {
        if profile.ID == id {
            jsonResponse(w, profile, http.StatusOK) // Returns SSN!
            return
        }
    }
}
```

### What's Missing

```go
// This authorization check is intentionally omitted:
currentUser := getCurrentUser(r)
if resource.UserID != currentUser.ID && currentUser.Role != "admin" {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

## Test Results

The `test-bola.sh` script confirms:

✅ user1 can access user2's profile (SSN: 345-67-8901)
✅ user1 can access admin's profile (SSN: 123-45-6789)
✅ user2 can access user1's orders
✅ Any user can read private documents
✅ Admin endpoints properly reject non-admin users

## Logging

All BOLA access attempts are logged:

```
[BOLA] User user1 (ID: 2, Role: user) accessing /api/profiles/3
[BOLA] SSN Exposure: Profile ID 3 accessed
[BOLA] Private document access: Doc ID 4 accessed
[BOLA] Order deletion: Order ID 2 deleted by unauthorized user
```

## Usage for Hadrian Testing

### Start the API

```bash
# Default (Bearer JWT auth)
make run

# Or with API key auth
make run-apikey

# Or with Basic auth
make run-basic
```

### Run Hadrian Tests

```bash
hadrian test owasp-api http://localhost:8889 \
  --auth-username user1 \
  --auth-password user1pass
```

### Expected Hadrian Findings

Hadrian should detect:

1. **BOLA-1**: Unauthorized access to user profiles
   - Severity: CRITICAL (SSN exposure)
   - Evidence: user1 accessing user2's profile

2. **BOLA-2**: Unauthorized order access
   - Severity: HIGH
   - Evidence: Cross-user order viewing/deletion

3. **BOLA-3**: Unauthorized document access
   - Severity: HIGH
   - Evidence: Reading private documents of other users

4. **BOLA-4**: User data modification
   - Severity: CRITICAL
   - Evidence: Updating other users' profiles/data

## Security Boundaries

### Vulnerable (By Design)
- All /api/users/{id} endpoints
- All /api/profiles/{id} endpoints
- All /api/orders/{id} endpoints
- All /api/documents/{id} endpoints

### Protected (For Comparison)
- /api/admin/* endpoints (require admin role)

## Building

```bash
# Standard build
go build -o vulnerable-api main.go

# Build ignoring workspace (if in super-repo)
GOWORK=off go build -o vulnerable-api main.go

# Using Makefile
make build
```

## Dependencies

- Go 1.22+
- github.com/golang-jwt/jwt/v5 v5.2.1

## Port Configuration

Default: 8889
Override: `PORT=9000 go run main.go`

## Architecture Notes

### Single File Design
This is intentionally a single-file application (main.go) because:
- It's a test utility, not production code
- Simplifies deployment and distribution
- Easier to understand the complete vulnerability
- No need for architectural layers

### In-Memory Data
All data is stored in memory and reset on restart:
- Simplifies testing (fresh state each run)
- No database dependencies
- Fast startup and teardown

### CORS Enabled
All origins allowed for local testing convenience

## Integration with Hadrian

This vulnerable API is specifically designed to test Hadrian's ability to detect:

1. **Broken Object Level Authorization (BOLA)**
   - OWASP API Security Top 10 #1
   - Also known as IDOR (Insecure Direct Object Reference)

2. **Sensitive Data Exposure**
   - SSN in profile responses
   - Private documents accessible to unauthorized users

3. **Excessive Data Exposure**
   - No field filtering
   - All user data returned in responses

## Future Enhancements (If Needed)

Potential additions for more comprehensive testing:

- Mass assignment vulnerabilities
- Rate limiting bypass testing
- Function level authorization issues
- Security misconfiguration examples
- Injection vulnerabilities

## Maintainability

The single-file design makes it easy to:
- Add new vulnerable endpoints
- Modify existing vulnerabilities
- Create variants for different OWASP API issues
- Deploy alongside Hadrian tests

## References

- OWASP API Security Top 10: https://owasp.org/API-Security/
- BOLA/IDOR: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- JWT Best Practices: https://tools.ietf.org/html/rfc8725
