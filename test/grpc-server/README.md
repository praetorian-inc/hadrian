# Vulnerable gRPC Server - Security Testing

This is an intentionally vulnerable gRPC server for testing Hadrian's gRPC security scanning capabilities.

## ⚠️ WARNING

**THIS IS A VULNERABLE APPLICATION FOR TESTING ONLY.**

- Do NOT deploy to production
- Do NOT expose to the internet
- Use only in isolated test environments

## Overview

The server implements multiple intentional vulnerabilities aligned with OWASP API Security Top 10:

- **API1: BOLA** (Broken Object Level Authorization) - Read, Write, Delete
- **API2: Broken Authentication** - Some endpoints accept requests without proper validation
- **API3: Sensitive Data Exposure** - Returns SSN, credit scores, internal notes, API secrets
- **API5: BFLA** (Broken Function Level Authorization) - Admin functions accessible to regular users
- **API8: Security Misconfiguration** - Exposes internal configuration
- **Deadline Manipulation** - Streaming endpoints don't respect deadlines
- **Metadata Injection** - Logs and processes x-forwarded-for, x-real-ip headers

## Quick Start

```bash
# Install dependencies and protoc plugins
make install-protoc-gen
make deps

# Generate proto files and build
make

# Run server (default port 50051)
make run

# Or run on custom port
make run-custom PORT=8080
```

## Test Tokens

Use these bearer tokens in the `authorization` metadata header:

| Token               | User ID | Role  | Purpose                      |
| ------------------- | ------- | ----- | ---------------------------- |
| admin-token-12345   | 1       | admin | Admin user for BFLA testing  |
| user1-token-67890   | 2       | user  | Regular user for BOLA tests  |
| user2-token-abcde   | 3       | user  | Victim user for BOLA tests   |

## Services

### UserService - BOLA Vulnerable

```protobuf
service UserService {
    rpc GetUser (GetUserRequest) returns (UserResponse);
    rpc UpdateUser (UpdateUserRequest) returns (UserResponse);
    rpc DeleteUser (DeleteUserRequest) returns (Empty);
    rpc ListUsers (ListUsersRequest) returns (ListUsersResponse);
}
```

**Vulnerabilities:**
- No ownership checks - any authenticated user can access/modify/delete other users
- Returns internal_notes field with sensitive information

### ProfileService - Sensitive Data Exposure

```protobuf
service ProfileService {
    rpc GetProfile (GetProfileRequest) returns (ProfileResponse);
    rpc UpdateProfile (UpdateProfileRequest) returns (ProfileResponse);
}
```

**Vulnerabilities:**
- Returns SSN (Social Security Number)
- Exposes credit_score
- No ownership checks (BOLA)

### AdminService - BFLA Vulnerable

```protobuf
service AdminService {
    rpc GetSystemConfig (Empty) returns (SystemConfigResponse);
    rpc SetSystemConfig (SystemConfigRequest) returns (Empty);
    rpc ListAllUsers (Empty) returns (ListUsersResponse);
    rpc DeleteAnyUser (DeleteUserRequest) returns (Empty);
}
```

**Vulnerabilities:**
- No role checks - regular users can call admin-only functions
- GetSystemConfig exposes database_url and api_secret
- DeleteAnyUser allows unauthorized user deletion

### OrderService - Multiple Vulnerabilities

```protobuf
service OrderService {
    rpc GetOrder (GetOrderRequest) returns (OrderResponse);
    rpc CreateOrder (CreateOrderRequest) returns (OrderResponse);
    rpc StreamOrders (StreamOrdersRequest) returns (stream OrderResponse);
}
```

**Vulnerabilities:**
- GetOrder has BOLA (no ownership check)
- Logs and processes x-forwarded-for and x-real-ip metadata (metadata injection)
- StreamOrders is intentionally slow (2s per order) and doesn't respect deadlines
- Returns payment_card_last4

## Seed Data

### Users

| ID | Username | Role  | Internal Notes                               |
|----|----------|-------|----------------------------------------------|
| 1  | admin    | admin | Root admin account - full privileges         |
| 2  | user1    | user  | Regular user - pending background check      |
| 3  | user2    | user  | Flagged for suspicious activity              |

### Profiles

| User ID | SSN         | Credit Score | Phone       |
|---------|-------------|--------------|-------------|
| 1       | 123-45-6789 | 850          | 555-0001    |
| 2       | 234-56-7890 | 720          | 555-0002    |
| 3       | 345-67-8901 | 680          | 555-0003    |

### Orders

| ID | User ID | Status      | Card Last 4 |
|----|---------|-------------|-------------|
| 1  | 1       | delivered   | 4242        |
| 2  | 2       | shipped     | 5555        |
| 3  | 2       | processing  | 5555        |
| 4  | 3       | pending     | 1234        |

### System Config

- **Database URL**: `postgresql://admin:secret@localhost:5432/prod` (exposed!)
- **API Secret**: `sk_test_EXAMPLE_51HxJKLMNOP123456789` (exposed!)
- **Debug Mode**: true
- **Allowed Origins**: `*`

## Vulnerability Examples

### Example 1: BOLA Read - Access Another User's Profile

```bash
# Using grpcurl (install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)

# user1 (ID 2) accessing user2's profile (ID 3)
grpcurl -plaintext \
  -H "authorization: Bearer user1-token-67890" \
  -d '{"user_id": "3"}' \
  localhost:50051 vulnerable.v1.ProfileService/GetProfile

# Response includes SSN and credit score!
{
  "id": "3",
  "userId": "3",
  "fullName": "User Two",
  "ssn": "345-67-8901",
  "phoneNumber": "555-0003",
  "address": "789 User Boulevard, User City, UC 34567",
  "creditScore": 680
}
```

### Example 2: BOLA Write - Update Another User

```bash
# user2 (ID 3) updating user1's email (ID 2)
grpcurl -plaintext \
  -H "authorization: Bearer user2-token-abcde" \
  -d '{"user_id": "2", "username": "hacked", "email": "hacked@evil.com"}' \
  localhost:50051 vulnerable.v1.UserService/UpdateUser

# Returns updated user (VULNERABILITY!)
```

### Example 3: BOLA Delete - Delete Another User

```bash
# user1 (ID 2) deleting user2 (ID 3)
grpcurl -plaintext \
  -H "authorization: Bearer user1-token-67890" \
  -d '{"user_id": "3"}' \
  localhost:50051 vulnerable.v1.UserService/DeleteUser

# Empty response - user deleted!
```

### Example 4: BFLA - Regular User Accessing Admin Function

```bash
# user1 (regular user) calling admin-only GetSystemConfig
grpcurl -plaintext \
  -H "authorization: Bearer user1-token-67890" \
  localhost:50051 vulnerable.v1.AdminService/GetSystemConfig

# Response exposes database credentials and API secret!
{
  "databaseUrl": "postgresql://admin:secret@localhost:5432/prod",
  "apiSecret": "sk_test_EXAMPLE_51HxJKLMNOP123456789",
  "debugMode": true,
  "maintenanceMode": false,
  "allowedOrigins": ["*"]
}
```

### Example 5: BFLA - Regular User Deleting Any User

```bash
# user2 (regular user) using admin-only DeleteAnyUser
grpcurl -plaintext \
  -H "authorization: Bearer user2-token-abcde" \
  -d '{"user_id": "1"}' \
  localhost:50051 vulnerable.v1.AdminService/DeleteAnyUser

# Empty response - admin deleted by regular user!
```

### Example 6: Metadata Injection

```bash
# Injecting x-forwarded-for header
grpcurl -plaintext \
  -H "authorization: Bearer user1-token-67890" \
  -H "x-forwarded-for: 1.2.3.4" \
  -H "x-real-ip: 5.6.7.8" \
  -d '{"order_id": "1"}' \
  localhost:50051 vulnerable.v1.OrderService/GetOrder

# Server logs process these headers (check server output)
```

### Example 7: Deadline Manipulation

```bash
# StreamOrders is slow (2s per order) and ignores deadlines
grpcurl -plaintext \
  -H "authorization: Bearer user1-token-67890" \
  -d '{"user_id": "2", "limit": 10}' \
  localhost:50051 vulnerable.v1.OrderService/StreamOrders

# Takes 20+ seconds even with short deadline
```

### Example 8: Broken Authentication

```bash
# Some read operations may work without token (broken auth)
# Try accessing methods without authorization header
grpcurl -plaintext \
  -d '{"user_id": "1"}' \
  localhost:50051 vulnerable.v1.UserService/GetUser

# May return data without authentication (inconsistent auth)
```

## Testing with Hadrian

The server includes pre-configured `auth.yaml` and `roles.yaml` files for testing.

### Basic Testing

```bash
# Using test templates (in templates/owasp/)
hadrian grpc \
  --server localhost:50051 \
  --auth auth.yaml \
  --roles roles.yaml \
  --template-dir templates/owasp/ \
  --verbose

# Using production templates (in ../../templates/grpc/)
hadrian grpc \
  --server localhost:50051 \
  --auth auth.yaml \
  --roles roles.yaml \
  --template-dir ../../templates/grpc/ \
  --verbose
```

### Configuration Files

The repository includes these files:

**auth.yaml** (provided):
```yaml
type: bearer
token_source:
  static:
    admin: "admin-token-12345"
    user1: "user1-token-67890"
    user2: "user2-token-abcde"
header_name: "authorization"
prefix: "Bearer "
```

**roles.yaml** (provided):
```yaml
roles:
  admin:
    id: "1"
    permissions: ["read", "write", "delete", "admin"]
  user1:
    id: "2"
    permissions: ["read", "write"]
  user2:
    id: "3"
    permissions: ["read", "write"]

role_hierarchy:
  admin: 3
  user1: 1
  user2: 1
```

### Test Tokens Reference

| Role  | Token               | User ID | Use Case                          |
|-------|---------------------|---------|-----------------------------------|
| admin | admin-token-12345   | 1       | Victim for BFLA tests             |
| user1 | user1-token-67890   | 2       | Attacker for BOLA tests           |
| user2 | user2-token-abcde   | 3       | Victim for BOLA tests             |

## Mutation Testing Templates

The `templates/owasp/` directory contains test templates specifically designed for this vulnerable server, including mutation tests that prove write/delete vulnerabilities.

### Test Template Categories

**Simple Tests** (single request):
- `01-api1-bola-get-user.yaml` - BOLA read vulnerability
- `04-api1-bola-get-profile.yaml` - BOLA profile access
- `05-api1-bola-get-order.yaml` - BOLA order access
- `06-api5-bfla-admin.yaml` - BFLA admin function access
- `07-api3-sensitive-data-profile.yaml` - Sensitive data exposure (SSN, credit_score)
- `08-api3-sensitive-data-config.yaml` - Config exposure (database_url, api_secret)
- `11-api8-metadata-injection.yaml` - Metadata injection
- `12-api8-deadline-manipulation.yaml` - Deadline manipulation

**Mutation Tests** (three-phase: setup/attack/verify):
- `02-api1-bola-update-user.yaml` - BOLA write vulnerability
- `03-api1-bola-delete-user.yaml` - BOLA delete vulnerability
- `09-api1-bola-update-profile.yaml` - BOLA profile modification
- `10-api5-bfla-delete-any-user.yaml` - BFLA unauthorized deletion

### Running Mutation Tests

Mutation tests prove vulnerabilities by tracking resource changes across phases:

```bash
# Run all tests (includes mutation tests)
hadrian grpc \
  --server localhost:50051 \
  --auth auth.yaml \
  --roles roles.yaml \
  --template-dir templates/owasp/ \
  --verbose

# Run only mutation tests (test_pattern: "mutation")
hadrian grpc \
  --server localhost:50051 \
  --auth auth.yaml \
  --roles roles.yaml \
  --template-dir templates/owasp/ \
  --template-filter "mutation" \
  --verbose
```

### Expected Mutation Test Flow

**Example: BOLA Delete Test (03-api1-bola-delete-user.yaml)**

```
Phase 1 (Setup): user1 creates a test user
  → CreateUser with user1 token
  → Response: {"user_id": "99", "username": "test_user_5678"}
  → Store: user_id = "99"

Phase 2 (Attack): user2 attempts to delete user1's resource
  → DeleteUser(user_id: "99") with user2 token
  → Response: Status 0 (OK) ← Server accepted delete!

Phase 3 (Verify): user1 checks if user still exists
  → GetUser(user_id: "99") with user1 token
  → Response: Status 5 (NOT_FOUND) ← User was deleted!

✓ VULNERABILITY CONFIRMED: user2 deleted user1's resource
```

## Expected Findings

Hadrian should detect:

1. **BOLA Read** - user1 accessing user2's profile/orders/data
2. **BOLA Write** - user1 modifying user2's data (proven via mutation tests)
3. **BOLA Delete** - user1 deleting user2's resources (proven via mutation tests)
4. **Sensitive Data Exposure** - SSN, credit scores, internal notes, payment info
5. **BFLA** - Regular users calling admin functions
6. **Security Misconfiguration** - Exposed database URLs, API secrets
7. **Metadata Injection** - Processing of x-forwarded-for headers
8. **Deadline Issues** - Slow streaming without deadline respect

## Server Logs

The server logs vulnerability attempts:

```
[BOLA READ] User 2 accessing user 3
[BOLA WRITE] User 2 updating user 3
[BOLA DELETE] User 2 deleting user 3
[SENSITIVE DATA] User 2 accessing profile 3 (SSN exposed)
[BFLA] User 2 (role: user) accessing system config
[BFLA] User 2 (role: user) deleting user 1
[METADATA INJECTION] X-Forwarded-For: 1.2.3.4
[DEADLINE] User 2 streaming orders (slow, no deadline check)
```

## gRPC Reflection

The server enables gRPC reflection for service discovery:

```bash
# List all services
grpcurl -plaintext localhost:50051 list

# List methods for a service
grpcurl -plaintext localhost:50051 list vulnerable.v1.UserService

# Describe a method
grpcurl -plaintext localhost:50051 describe vulnerable.v1.UserService.GetUser
```

## Development

### Generate Proto Files

```bash
make proto
```

This generates:
- `pb/service.pb.go` - Protocol buffer definitions
- `pb/service_grpc.pb.go` - gRPC service definitions

### Build

```bash
make build
```

### Clean

```bash
make clean
```

## Architecture

```
grpc-server/
├── service.proto          # Proto definitions
├── main.go                # Server implementation
├── go.mod                 # Go dependencies
├── Makefile               # Build automation
├── README.md              # This file
├── auth.yaml              # Auth config for Hadrian
├── roles.yaml             # Role definitions for Hadrian
└── pb/                    # Generated proto code (git-ignored)
    ├── service.pb.go
    └── service_grpc.pb.go
```

## Security Note

This server intentionally implements the following anti-patterns:

1. **No Authorization Checks** - Only verifies authentication, not authorization
2. **Direct Resource Access** - No ownership validation
3. **Excessive Data Exposure** - Returns sensitive fields (SSN, secrets)
4. **Missing Role Checks** - Admin functions accessible to all
5. **Metadata Trust** - Logs and processes client-provided headers
6. **No Rate Limiting** - Vulnerable to abuse
7. **No Deadline Enforcement** - Streaming operations ignore timeouts

These are deliberately included for security testing purposes.

## License

MIT (for testing purposes only)
