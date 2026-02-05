# gRPC Vulnerable Server Test Templates

This directory contains 12 YAML test templates organized by OWASP API Security Top 10 categories for testing the vulnerable gRPC server.

## Test Templates Overview

All templates follow the naming pattern: `{NN}-api{N}-{vuln-type}.yaml`

- **NN** = Two-digit sequence number (01, 02, etc.)
- **N** = OWASP API Security category number (1, 2, 3, 5, 8)
- **vuln-type** = Descriptive vulnerability name

### API1 - BOLA (Broken Object Level Authorization) Tests

1. **01-api1-bola-get-user.yaml** - Tests BOLA on UserService.GetUser
   - User2 token accessing User1's data (user_id: "2")
   - Category: API1:2023 Broken Object Level Authorization
   - Severity: HIGH

2. **02-api1-bola-update-user.yaml** - Tests BOLA on UserService.UpdateUser
   - User2 token updating User1's data
   - Category: API1:2023 Broken Object Level Authorization
   - Severity: CRITICAL

3. **03-api1-bola-delete-user.yaml** - Tests BOLA on UserService.DeleteUser
   - User2 token deleting User1
   - Category: API1:2023 Broken Object Level Authorization
   - Severity: CRITICAL

4. **04-api1-bola-get-profile.yaml** - Tests BOLA on ProfileService.GetProfile
   - User2 token accessing User1's profile (returns SSN and credit_score)
   - Category: API1:2023 Broken Object Level Authorization
   - Severity: CRITICAL

5. **05-api1-bola-get-order.yaml** - Tests BOLA on OrderService.GetOrder
   - User2 accessing User1's order (exposes payment_card_last4)
   - Category: API1:2023 Broken Object Level Authorization
   - Severity: CRITICAL

### API2 - Broken Authentication Tests

6. **06-api2-broken-auth.yaml** - Tests broken auth on protected endpoints
   - Call UserService.GetUser without authorization header
   - Category: API2:2023 Broken Authentication
   - Severity: CRITICAL

### API3 - Sensitive Data Exposure Tests

7. **07-api3-sensitive-data-profile.yaml** - Tests sensitive data exposure
   - Any authenticated user getting profile returns SSN and credit_score
   - Category: API3:2023 Broken Object Property Level Authorization
   - Severity: HIGH

### API5 - BFLA (Broken Function Level Authorization) Tests

8. **08-api5-bfla-get-config.yaml** - Tests BFLA on AdminService.GetSystemConfig
   - Regular user (user1) accessing admin function
   - Returns database_url and api_secret
   - Category: API5:2023 Broken Function Level Authorization
   - Severity: CRITICAL

9. **09-api5-bfla-set-config.yaml** - Tests BFLA on AdminService.SetSystemConfig
   - Regular user modifying system config
   - Category: API5:2023 Broken Function Level Authorization
   - Severity: CRITICAL

10. **10-api5-bfla-delete-any-user.yaml** - Tests BFLA on AdminService.DeleteAnyUser
    - Regular user deleting another user via admin function
    - Category: API5:2023 Broken Function Level Authorization
    - Severity: CRITICAL

### API8 - Security Misconfiguration Tests

11. **11-api8-metadata-injection.yaml** - Tests metadata injection on OrderService.CreateOrder
    - Inject x-forwarded-for, x-real-ip, x-original-url headers
    - Category: API8:2023 Security Misconfiguration
    - Severity: MEDIUM

12. **12-api8-deadline-manipulation.yaml** - Tests deadline issues on OrderService.StreamOrders
    - Stream with short deadline (100ms), server ignores it
    - Category: API8:2023 Security Misconfiguration
    - Severity: LOW

## Test Tokens

```
admin-token-12345 -> user_id: 1, role: admin
user1-token-67890 -> user_id: 2, role: user
user2-token-abcde -> user_id: 3, role: user
```

## Services Tested

- **vulnerable.v1.UserService** - BOLA read/write/delete, broken auth
- **vulnerable.v1.ProfileService** - BOLA, sensitive data exposure (SSN, credit_score)
- **vulnerable.v1.AdminService** - BFLA (privilege escalation to admin functions)
- **vulnerable.v1.OrderService** - BOLA, metadata injection, deadline manipulation

## Template Structure

Each template follows the Hadrian gRPC test format:

```yaml
id: unique-test-id
info:
  name: "Human readable test name"
  category: "OWASP API Security Top 10 category"
  severity: "CRITICAL|HIGH|MEDIUM|LOW"
  author: "hadrian-test"
  tags: [relevant, tags]
  requires_llm_triage: true|false
  test_pattern: "simple"

endpoint_selector:
  requires_auth: true|false
  service: "vulnerable.v1.ServiceName"
  method: "MethodName"

role_selector:
  attacker_permission_level: "none|lower|higher"
  victim_permission_level: "lower|higher" # optional

grpc:
  - method: "MethodName"
    service: "vulnerable.v1.ServiceName"
    message: '{"field": "value"}'
    metadata:
      authorization: "Bearer token"
    deadline_ms: 100  # optional

detection:
  success_indicators:
    - type: "grpc_status"
      code: 0
    - type: "body_field"
      body_field: "field_name"
      exists: true
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]  # PERMISSION_DENIED, UNAUTHENTICATED
  vulnerability_pattern: "pattern_name"
```

## Running Tests

These templates are designed to be run against the vulnerable gRPC server at:
`/workspaces/praetorian-dev/modules/hadrian/testdata/grpc-server/`

Reference the proto file for full service definitions:
`/workspaces/praetorian-dev/modules/hadrian/testdata/grpc-server/service.proto`
