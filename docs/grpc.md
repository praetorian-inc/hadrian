# gRPC Security Testing with Hadrian

Hadrian provides comprehensive security testing for gRPC APIs, supporting both simple single-request tests and advanced three-phase mutation tests to prove write/delete vulnerabilities.

## Table of Contents

- [Overview](#overview)
- [Test Patterns](#test-patterns)
- [Template Structure](#template-structure)
- [Three-Phase Mutation Testing](#three-phase-mutation-testing)
- [Detection Conditions](#detection-conditions)
- [gRPC Status Codes](#grpc-status-codes)
- [Resource Tracking](#resource-tracking)
- [Example Templates](#example-templates)
- [Running Tests](#running-tests)

## Overview

gRPC security testing in Hadrian covers OWASP API Security Top 10 categories with templates designed for the unique characteristics of gRPC:

| Category | Coverage | Templates |
|----------|----------|-----------|
| **API1:2023** (BOLA) | Read, Write, Delete | 3 templates |
| **API2:2023** (Broken Authentication) | Unauthenticated access | 1 template |
| **API3:2023** (Sensitive Data Exposure) | PII exposure | 2 templates |
| **API5:2023** (BFLA) | Admin function access | 1 template |
| **API8:2023** (Security Misconfiguration) | Deadline manipulation, metadata injection | 2 templates |

**Total: 9 gRPC templates in `templates/grpc/`**

## Test Patterns

Hadrian supports two test patterns for gRPC APIs:

### Simple Pattern

**Usage:** `test_pattern: "simple"`

Single gRPC call per test. Used for operations that don't modify state:

- **Read operations**: GET, Read, Fetch, Find methods
- **BFLA checks**: Testing unauthorized access to admin functions
- **Sensitive data exposure**: Detecting PII in responses

**Example:**
```yaml
test_pattern: "simple"

grpc:
  - method: "GetUser"
    service: "UserService"
    message: '{"user_id": "{{victim_id}}"}'
    metadata:
      authorization: "Bearer {{attacker_token}}"
```

### Mutation Pattern

**Usage:** `test_pattern: "mutation"`

Three-phase test to prove write/delete vulnerabilities actually occurred:

1. **Setup**: Victim creates a resource (establishes baseline)
2. **Attack**: Attacker attempts unauthorized modification/deletion
3. **Verify**: Confirm the resource was actually changed/deleted

**Example:**
```yaml
test_pattern: "mutation"

test_phases:
  setup:
    - path: "UserService/CreateUser"
      operation: "create"
      auth: "victim"
      data:
        username: "victim_user_{{random_id}}"
      store_response_field: "user_id"

  attack:
    path: "UserService/DeleteUser"
    operation: "delete"
    auth: "attacker"
    use_stored_field: "user_id"

  verify:
    path: "UserService/GetUser"
    operation: "read"
    auth: "victim"
    use_stored_field: "user_id"
```

**Why three phases?**

A 200 OK response from a delete endpoint doesn't prove the resource was actually deleted. The verify phase confirms the vulnerability by attempting to read the resource back:

- **If verify returns NOT_FOUND (5)**: Resource was deleted → vulnerability confirmed
- **If verify returns OK (0)**: Resource still exists → no vulnerability

## Template Structure

### Complete Template Format

```yaml
id: 03-grpc-api1-bola-delete
info:
  name: "gRPC BOLA - Unauthorized Resource Deletion"
  category: "API1:2023 Broken Object Level Authorization"
  severity: "CRITICAL"
  author: "hadrian"
  description: |
    Tests for Broken Object Level Authorization vulnerabilities on gRPC delete methods.
    Uses three-phase mutation testing to prove unauthorized deletion occurred.
  tags: ["grpc", "bola", "api1", "authorization", "delete", "mutation"]
  requires_llm_triage: true
  test_pattern: "mutation"

# Selects which gRPC methods to test
endpoint_selector:
  requires_auth: true
  methods: ["Delete*", "Remove*", "Destroy*"]

# Defines attacker and victim roles
role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"

# Three-phase mutation test
test_phases:
  # Phase 1: Victim creates a resource
  setup:
    - path: "{{operation.service}}/Create{{operation.resource_type}}"
      operation: "create"
      auth: "victim"
      data:
        name: "victim_resource_{{random_id}}"
      store_response_field: "resource_id"
      expected_status: 0

  # Phase 2: Attacker attempts to delete victim's resource
  attack:
    path: "{{operation.service}}/{{operation.method}}"
    operation: "delete"
    auth: "attacker"
    use_stored_field: "resource_id"
    expected_status: 0

  # Phase 3: Verify resource was actually deleted
  verify:
    path: "{{operation.service}}/Get{{operation.resource_type}}"
    operation: "read"
    auth: "victim"
    use_stored_field: "resource_id"
    expected_status: 5  # NOT_FOUND indicates deletion succeeded

# Detection logic
detection:
  success_indicators:
    - type: "grpc_status"
      code: 0
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]  # PERMISSION_DENIED, UNAUTHENTICATED
  vulnerability_pattern: "grpc_attacker_deleted_victim_resource"
  conditions:
    - attack_phase_status: [0]
      verify_phase_status: [5]  # NOT_FOUND confirms deletion
```

### Field Reference

#### info section
- `name`: Human-readable test name
- `category`: OWASP API Security category (e.g., "API1:2023")
- `severity`: CRITICAL, HIGH, MEDIUM, LOW
- `description`: Detailed explanation of what the test checks
- `tags`: Categorization tags
- `requires_llm_triage`: Whether to use LLM for result analysis
- `test_pattern`: "simple" or "mutation"

#### endpoint_selector
- `requires_auth`: Filter for endpoints requiring authentication
- `service`: Specific gRPC service name (e.g., "vulnerable.v1.UserService")
- `method`: Specific method name or pattern (e.g., "GetUser", "Update*")
- `methods`: Array of method patterns to match

#### role_selector
- `attacker_permission_level`: "lower", "higher", "all", "none"
- `victim_permission_level`: "lower", "higher", "all"

#### test_phases (mutation pattern only)
- `setup`: Array of setup phases (victim creates resources)
- `attack`: Attack phase (attacker attempts unauthorized action)
- `verify`: Verify phase (confirm the attack succeeded)

Each phase contains:
- `path`: gRPC service/method path
- `operation`: "create", "update", "delete", "read"
- `auth`: Which role's credentials to use ("victim" or "attacker")
- `data`: Request message data (map of fields)
- `store_response_field`: JSON path to extract from response (e.g., "user_id", "id")
- `use_stored_field`: Use previously stored field in request
- `expected_status`: Expected gRPC status code

#### detection
- `success_indicators`: Conditions indicating vulnerability found
- `failure_indicators`: Conditions indicating proper protection
- `vulnerability_pattern`: Pattern name for reporting
- `conditions`: Multi-phase conditions for mutation tests

## Three-Phase Mutation Testing

Mutation testing proves that write/delete operations actually succeeded by verifying the state change.

### Phase Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                       MUTATION TEST FLOW                         │
└─────────────────────────────────────────────────────────────────┘

Phase 1: SETUP (Victim)
  ┌───────────────────────────────────────────────────────────┐
  │ Victim creates resource                                    │
  │   POST /api/users                                          │
  │   Authorization: Bearer victim-token                       │
  │   Body: {"username": "victim_123"}                         │
  │                                                            │
  │ Response: {"user_id": "abc-456"}  ← Store resource_id     │
  └───────────────────────────────────────────────────────────┘
                           ↓

Phase 2: ATTACK (Attacker)
  ┌───────────────────────────────────────────────────────────┐
  │ Attacker attempts unauthorized deletion                    │
  │   DELETE /api/users/abc-456  ← Uses stored resource_id    │
  │   Authorization: Bearer attacker-token                     │
  │                                                            │
  │ Response: Status 0 (OK) ← Attack accepted by server       │
  └───────────────────────────────────────────────────────────┘
                           ↓

Phase 3: VERIFY (Victim)
  ┌───────────────────────────────────────────────────────────┐
  │ Victim checks if resource still exists                     │
  │   GET /api/users/abc-456  ← Uses stored resource_id       │
  │   Authorization: Bearer victim-token                       │
  │                                                            │
  │ Response: Status 5 (NOT_FOUND) ← Deletion confirmed!      │
  │                                                            │
  │ ✓ VULNERABILITY: Attacker successfully deleted victim's    │
  │   resource despite lacking permission                      │
  └───────────────────────────────────────────────────────────┘
```

### Why Verify Phase Matters

Without verification, you can't distinguish between:

1. **Server accepted but ignored the request** (no vulnerability)
2. **Server actually performed the unauthorized action** (vulnerability!)

**Example scenario:**

```yaml
# Attack phase returns Status 0 (OK)
attack:
  response:
    status: 0  # Server says "OK"
    body: {}

# But verify phase shows resource still exists
verify:
  response:
    status: 0  # Resource still accessible
    body: {"user_id": "abc-456", "username": "victim_123"}

# Conclusion: No vulnerability (server ignored the delete request)
```

## Detection Conditions

Detection conditions determine when a vulnerability is confirmed.

### Simple Pattern Detection

For simple tests, detection is based on the immediate response:

```yaml
detection:
  success_indicators:
    - type: "grpc_status"
      code: 0  # OK
    - type: "body_field"
      body_field: "username"
      exists: true
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]  # PERMISSION_DENIED, UNAUTHENTICATED
```

**Vulnerability found if:**
- Response matches ALL success_indicators
- Response doesn't match any failure_indicators

### Mutation Pattern Detection

For mutation tests, detection spans multiple phases:

```yaml
detection:
  success_indicators:
    - type: "grpc_status"
      code: 0
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]
  conditions:
    - attack_phase_status: [0]      # Attack returned OK
      verify_phase_status: [5]      # Verify returned NOT_FOUND
      verify_field_changed: true    # (optional) Field value changed
```

**Vulnerability found if:**
- Attack phase matches success_indicators
- Verify phase confirms the state change
- All conditions are satisfied

### Condition Types

#### attack_phase_status
Expected gRPC status codes from attack phase:
```yaml
attack_phase_status: [0]  # Attack must return OK
```

#### verify_phase_status
Expected gRPC status codes from verify phase:
```yaml
verify_phase_status: [5]  # Verify must return NOT_FOUND (deletion confirmed)
```

#### verify_field_changed
Check if a specific field was modified:
```yaml
verify_field_changed: true
check_field: "username"
expected_value: "attacker_modified"
```

## gRPC Status Codes

Hadrian uses standard gRPC status codes for detection conditions:

| Code | Name | Meaning | Detection Usage |
|------|------|---------|-----------------|
| **0** | OK | Success | Vulnerability indicator (unauthorized action succeeded) |
| **3** | INVALID_ARGUMENT | Bad input | Test invalid (not a security issue) |
| **5** | NOT_FOUND | Resource not found | Deletion confirmed (verify phase) |
| **7** | PERMISSION_DENIED | Forbidden | Proper protection (failure indicator) |
| **12** | UNIMPLEMENTED | Method not implemented | Test invalid (method doesn't exist) |
| **16** | UNAUTHENTICATED | Missing/invalid auth | Proper protection (failure indicator) |

### Common Detection Patterns

#### BOLA Read (Simple)
```yaml
detection:
  success_indicators:
    - type: "grpc_status"
      code: 0  # Attacker got OK response
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]  # PERMISSION_DENIED or UNAUTHENTICATED
```

#### BOLA Delete (Mutation)
```yaml
detection:
  success_indicators:
    - type: "grpc_status"
      code: 0
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]
  conditions:
    - attack_phase_status: [0]    # Delete returned OK
      verify_phase_status: [5]    # Resource NOT_FOUND (deleted)
```

#### BFLA (Simple)
```yaml
detection:
  success_indicators:
    - type: "grpc_status"
      code: 0  # Regular user accessed admin function
  failure_indicators:
    - type: "grpc_status"
      code: [7]  # PERMISSION_DENIED (proper RBAC)
```

## Resource Tracking

Resource tracking allows mutation tests to pass resource IDs between phases.

### Storing Resource IDs

The **setup phase** creates resources and stores identifiers for later use:

```yaml
setup:
  - path: "UserService/CreateUser"
    auth: "victim"
    data:
      username: "victim_user_{{random_id}}"
      email: "victim@example.com"
    store_response_field: "user_id"  # Extract user_id from response
```

**Response:**
```json
{
  "user_id": "abc-123",
  "username": "victim_user_5678",
  "email": "victim@example.com"
}
```

**Stored:** `user_id = "abc-123"`

### Using Stored IDs

The **attack and verify phases** use stored IDs in their requests:

```yaml
attack:
  path: "UserService/DeleteUser"
  auth: "attacker"
  use_stored_field: "user_id"  # Use the stored user_id
  data:
    user_id: "{{user_id}}"  # Will be replaced with "abc-123"
```

**Hadrian automatically:**
1. Extracts `user_id` from setup response: `"abc-123"`
2. Substitutes `{{user_id}}` in attack phase with `"abc-123"`
3. Sends the attack request with the victim's resource ID

### Multiple Stored Fields

For complex resources, store multiple fields:

```yaml
setup:
  - path: "VideoService/CreateVideo"
    auth: "victim"
    data:
      title: "My Video"
    store_response_fields:
      video_id: "video.id"
      owner_id: "video.owner_id"

attack:
  path: "CommentService/DeleteComment"
  auth: "attacker"
  use_stored_field: "video_id"
  data:
    video_id: "{{video_id}}"
    comment_id: "{{comment_id}}"
```

## Example Templates

### Example 1: BOLA Read (Simple Pattern)

Test if attackers can read other users' data.

```yaml
id: 01-grpc-api1-bola-read
info:
  name: "gRPC BOLA - Unauthorized Resource Read"
  category: "API1:2023 Broken Object Level Authorization"
  severity: "HIGH"
  test_pattern: "simple"

endpoint_selector:
  requires_auth: true
  methods: ["Get*", "Read*", "Fetch*", "Find*"]

role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"

grpc:
  - method: "{{operation.method}}"
    service: "{{operation.service}}"
    message: '{"{{operation.owner_field}}": "{{victim_id}}"}'
    metadata:
      authorization: "Bearer {{attacker_token}}"

detection:
  success_indicators:
    - type: "grpc_status"
      code: 0
    - type: "body_field"
      body_field: "data"
      exists: true
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]
```

### Example 2: BOLA Write (Mutation Pattern)

Test if attackers can modify other users' resources.

```yaml
id: 02-grpc-api1-bola-write
info:
  name: "gRPC BOLA - Unauthorized Resource Modification"
  category: "API1:2023 Broken Object Level Authorization"
  severity: "HIGH"
  test_pattern: "mutation"

endpoint_selector:
  requires_auth: true
  methods: ["Update*", "Set*", "Modify*", "Put*", "Edit*"]

role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"

test_phases:
  setup:
    - path: "{{operation.service}}/Create{{operation.resource_type}}"
      operation: "create"
      auth: "victim"
      data:
        name: "victim_resource_{{random_id}}"
        description: "Resource created by victim"
      store_response_field: "resource_id"
      expected_status: 0

  attack:
    path: "{{operation.service}}/{{operation.method}}"
    operation: "update"
    auth: "attacker"
    use_stored_field: "resource_id"
    data:
      name: "attacker_modified_resource"
      description: "Modified by unauthorized user"
    expected_status: 0

  verify:
    path: "{{operation.service}}/Get{{operation.resource_type}}"
    operation: "read"
    auth: "victim"
    use_stored_field: "resource_id"
    check_field: "name"
    expected_value: "attacker_modified_resource"
    expected_status: 0

detection:
  success_indicators:
    - type: "grpc_status"
      code: 0
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]
  conditions:
    - attack_phase_status: [0]
      verify_phase_status: [0]
      verify_field_changed: true
```

### Example 3: BOLA Delete (Mutation Pattern)

Test if attackers can delete other users' resources.

```yaml
id: 03-grpc-api1-bola-delete
info:
  name: "gRPC BOLA - Unauthorized Resource Deletion"
  category: "API1:2023 Broken Object Level Authorization"
  severity: "CRITICAL"
  test_pattern: "mutation"

endpoint_selector:
  requires_auth: true
  methods: ["Delete*", "Remove*", "Destroy*"]

role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"

test_phases:
  setup:
    - path: "{{operation.service}}/Create{{operation.resource_type}}"
      operation: "create"
      auth: "victim"
      data:
        name: "victim_resource_{{random_id}}"
      store_response_field: "resource_id"
      expected_status: 0

  attack:
    path: "{{operation.service}}/{{operation.method}}"
    operation: "delete"
    auth: "attacker"
    use_stored_field: "resource_id"
    expected_status: 0

  verify:
    path: "{{operation.service}}/Get{{operation.resource_type}}"
    operation: "read"
    auth: "victim"
    use_stored_field: "resource_id"
    expected_status: 5  # NOT_FOUND confirms deletion

detection:
  success_indicators:
    - type: "grpc_status"
      code: 0
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]
  conditions:
    - attack_phase_status: [0]
      verify_phase_status: [5]  # Resource not found (deleted)
```

### Example 4: BFLA (Simple Pattern)

Test if regular users can access admin functions.

```yaml
id: 06-grpc-api5-bfla
info:
  name: "gRPC BFLA - Unauthorized Admin Function Access"
  category: "API5:2023 Broken Function Level Authorization"
  severity: "HIGH"
  test_pattern: "simple"

endpoint_selector:
  requires_auth: true
  methods: ["*Admin*", "*System*", "*Config*"]

role_selector:
  attacker_permission_level: "lower"  # Regular user
  victim_permission_level: "higher"   # Admin

grpc:
  - method: "{{operation.method}}"
    service: "{{operation.service}}"
    message: '{}'
    metadata:
      authorization: "Bearer {{attacker_token}}"

detection:
  success_indicators:
    - type: "grpc_status"
      code: 0
  failure_indicators:
    - type: "grpc_status"
      code: [7]  # PERMISSION_DENIED
```

### Example 5: Sensitive Data Exposure (Simple Pattern)

Test if responses expose PII like SSN, credit scores, etc.

```yaml
id: 07-grpc-api3-sensitive-data
info:
  name: "gRPC API3 - Sensitive Data Exposure"
  category: "API3:2023 Broken Object Property Level Authorization"
  severity: "HIGH"
  test_pattern: "simple"

endpoint_selector:
  requires_auth: true
  methods: ["Get*", "Read*"]

role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"

grpc:
  - method: "{{operation.method}}"
    service: "{{operation.service}}"
    message: '{"{{operation.owner_field}}": "{{attacker_id}}"}'
    metadata:
      authorization: "Bearer {{attacker_token}}"

detection:
  success_indicators:
    - type: "body_contains"
      pattern: '"ssn":'
    - type: "body_contains"
      pattern: '"credit_score":'
    - type: "body_contains"
      pattern: '"api_secret":'
  failure_indicators:
    - type: "grpc_status"
      code: [7, 16]
```

## Running Tests

### Basic Usage

```bash
# Test a gRPC server
hadrian grpc \
  --server localhost:50051 \
  --templates templates/grpc/ \
  --auth auth.yaml \
  --roles roles.yaml
```

### With Verbose Output

```bash
hadrian grpc \
  --server localhost:50051 \
  --templates templates/grpc/ \
  --auth auth.yaml \
  --roles roles.yaml \
  --verbose
```

### Filter by OWASP Category

```bash
# Test only BOLA (API1)
hadrian grpc \
  --server localhost:50051 \
  --templates templates/grpc/ \
  --auth auth.yaml \
  --roles roles.yaml \
  --owasp API1

# Test BOLA and BFLA (API1, API5)
hadrian grpc \
  --server localhost:50051 \
  --templates templates/grpc/ \
  --auth auth.yaml \
  --roles roles.yaml \
  --owasp API1,API5
```

### Output to JSON

```bash
hadrian grpc \
  --server localhost:50051 \
  --templates templates/grpc/ \
  --auth auth.yaml \
  --roles roles.yaml \
  --output json \
  --output-file results.json
```

### Dry Run (Show What Would Be Tested)

```bash
hadrian grpc \
  --server localhost:50051 \
  --templates templates/grpc/ \
  --auth auth.yaml \
  --roles roles.yaml \
  --dry-run
```

### Configuration Files

**auth.yaml:**
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

**roles.yaml:**
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

## Testing Against the Vulnerable Server

Hadrian includes an intentionally vulnerable gRPC server for testing:

```bash
# Start the vulnerable server
cd test/grpc-server
make run

# In another terminal, run Hadrian
hadrian grpc \
  --server localhost:50051 \
  --templates test/grpc-server/templates/owasp/ \
  --auth test/grpc-server/auth.yaml \
  --roles test/grpc-server/roles.yaml \
  --verbose
```

For complete details on the vulnerable server, test data, and expected findings, see [test/grpc-server/README.md](../test/grpc-server/README.md).
