# Hadrian API Security Tester - Architecture

This document provides an overview of how the Hadrian API security testing framework works, including its components, data flow, and testing methodology.

## Overview

Hadrian is a security testing framework designed to identify OWASP API Top 10 vulnerabilities through role-based authorization testing. It combines API specification parsing, template-driven security testing, mutation-based attack patterns, and optional LLM-powered analysis.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INPUT FILES                                     │
├─────────────────┬─────────────────┬─────────────────┬───────────────────────┤
│   api.yaml      │   roles.yaml    │   auth.yaml     │   templates/*.yaml    │
│   (OpenAPI 3.0) │   (Permissions) │   (Credentials) │   (Security Tests)    │
└────────┬────────┴────────┬────────┴────────┬────────┴───────────┬───────────┘
         │                 │                 │                    │
         ▼                 ▼                 ▼                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PHASE 1: INITIALIZATION                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │ REST Plugin  │    │ Role Parser  │    │ Auth Loader  │    │  Template  │ │
│  │   (OpenAPI   │    │ (permission  │    │  (Bearer,    │    │   Parser   │ │
│  │   parser)    │    │  strings)    │    │  API Key)    │    │   (YAML)   │ │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └─────┬──────┘ │
│         │                   │                   │                  │        │
│         ▼                   ▼                   ▼                  ▼        │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │  Operations  │    │    Roles     │    │   Tokens     │    │  Compiled  │ │
│  │  (endpoints, │    │ (admin,user, │    │ (per-role    │    │  Templates │ │
│  │   methods)   │    │  guest,etc)  │    │  auth)       │    │  (regex)   │ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       PHASE 2: TEMPLATE MATCHING                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   For each Operation (e.g., GET /api/users/{id}):                           │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                     ENDPOINT SELECTOR                                │   │
│   │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │   │
│   │  │ has_path_param? │  │ requires_auth?  │  │ method matches?     │  │   │
│   │  │     {id}        │  │    (yes/no)     │  │ GET,POST,PUT,DELETE │  │   │
│   │  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘  │   │
│   │           │                    │                      │             │   │
│   │           └────────────────────┼──────────────────────┘             │   │
│   │                                ▼                                    │   │
│   │                    ┌───────────────────────┐                        │   │
│   │                    │  Matching Templates   │                        │   │
│   │                    │  (api1-bola-read,     │                        │   │
│   │                    │   api5-method-override)│                       │   │
│   │                    └───────────────────────┘                        │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHASE 3: TEST EXECUTION                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────┐    ┌─────────────────────────────────────┐ │
│  │     SIMPLE TESTS            │    │      MUTATION TESTS (3-phase)       │ │
│  │     (single request)        │    │      (stateful attacks)             │ │
│  ├─────────────────────────────┤    ├─────────────────────────────────────┤ │
│  │                             │    │                                     │ │
│  │  For each role pair:        │    │  ┌─────────────────────────────┐   │ │
│  │  (attacker → victim)        │    │  │ 1. SETUP (as victim)        │   │ │
│  │                             │    │  │    POST /api/resource       │   │ │
│  │  ┌───────────────────────┐  │    │  │    → store resource_id      │   │ │
│  │  │ 1. Build request      │  │    │  └─────────────┬───────────────┘   │ │
│  │  │    - substitute vars  │  │    │                │                   │ │
│  │  │    - inject attacker  │  │    │                ▼                   │ │
│  │  │      auth token       │  │    │  ┌─────────────────────────────┐   │ │
│  │  └───────────┬───────────┘  │    │  │ 2. ATTACK (as attacker)     │   │ │
│  │              │              │    │  │    GET /api/resource/{id}   │   │ │
│  │              ▼              │    │  │    using victim's ID        │   │ │
│  │  ┌───────────────────────┐  │    │  │    → check if accessible    │   │ │
│  │  │ 2. Execute HTTP       │  │    │  └─────────────┬───────────────┘   │ │
│  │  │    request            │  │    │                │                   │ │
│  │  └───────────┬───────────┘  │    │                ▼                   │ │
│  │              │              │    │  ┌─────────────────────────────┐   │ │
│  │              ▼              │    │  │ 3. VERIFY (as victim)       │   │ │
│  │  ┌───────────────────────┐  │    │  │    GET /api/resource/{id}   │   │ │
│  │  │ 3. Evaluate matchers  │  │    │  │    → confirm still owned    │   │ │
│  │  │    - status code      │  │    │  └─────────────────────────────┘   │ │
│  │  │    - body content     │  │    │                                     │ │
│  │  │    - regex patterns   │  │    │                                     │ │
│  │  └───────────────────────┘  │    └─────────────────────────────────────┘ │
│  └─────────────────────────────┘                                            │
│                                                                              │
│                         If matchers pass = VULNERABILITY FOUND               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHASE 4: FINDINGS & TRIAGE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                            FINDING                                      │ │
│  │  ┌──────────────┬──────────────┬─────────────────┬───────────────────┐ │ │
│  │  │ Category     │ Severity     │ Endpoint        │ Evidence          │ │ │
│  │  │ (API1-BOLA)  │ (HIGH)       │ GET /users/{id} │ (request/response)│ │ │
│  │  └──────────────┴──────────────┴─────────────────┴───────────────────┘ │ │
│  │                                                                         │ │
│  │                    (optional)                                           │ │
│  │                        │                                                │ │
│  │                        ▼                                                │ │
│  │  ┌────────────────────────────────────────────────────────────────┐    │ │
│  │  │                    LLM TRIAGE                                   │    │ │
│  │  │   Claude / OpenAI / Ollama                                      │    │ │
│  │  │   → is_vulnerability: true/false                               │    │ │
│  │  │   → confidence: 0.95                                           │    │ │
│  │  │   → recommendations: [...]                                     │    │ │
│  │  └────────────────────────────────────────────────────────────────┘    │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PHASE 5: OUTPUT                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│     ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐       │
│     │    TERMINAL     │    │      JSON       │    │    MARKDOWN     │       │
│     │  (colored CLI)  │    │  (structured)   │    │  (reports)      │       │
│     └─────────────────┘    └─────────────────┘    └─────────────────┘       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Components

### Input Files

| File | Purpose |
|------|---------|
| **api.yaml** | OpenAPI 3.0 specification defining endpoints, parameters, and auth requirements |
| **roles.yaml** | Role definitions with permission strings (`action:object:scope`) and explicit `level` values for privilege ordering |
| **auth.yaml** | Authentication credentials (Bearer tokens, API keys) for each role |
| **templates/*.yaml** | Security test templates with endpoint selectors, matchers, and attack patterns |

### Core Packages

```
hadrian-api-tester/
├── cmd/hadrian/main.go      # CLI entry point
├── pkg/
│   ├── runner/              # Orchestration, rate limiting, test execution
│   │   ├── run.go           # CLI commands and main loop
│   │   ├── ratelimit.go     # Rate limiter configuration
│   │   ├── ratelimit_client.go  # HTTP client with reactive backoff
│   │   ├── execution.go     # Template execution logic
│   │   └── ...
│   ├── model/               # Data structures (Operation, Finding)
│   ├── templates/           # Template parsing, compilation, execution
│   ├── auth/                # Authentication handling
│   ├── roles/               # Role-based authorization logic
│   ├── owasp/               # OWASP-specific runners and mutation tests
│   ├── plugins/             # API spec format plugins (REST/OpenAPI)
│   ├── reporter/            # Output formatting (terminal, JSON, markdown)
│   ├── llm/                 # LLM integration (Claude, OpenAI, Ollama)
│   └── matchers/            # Detection matchers
├── internal/http/           # HTTP client with proxy support
└── templates/owasp/         # Built-in OWASP security templates
```

## How Testing Works

### Template Execution Order

Templates are loaded and executed in **alphabetical order by filename**. The template loader (`pkg/owasp/loader.go` and `pkg/runner/run.go`) explicitly sorts files to ensure deterministic, reproducible test execution across all platforms.

**Best Practice**: Prefix template filenames with numbers to control execution order:
- `01-*` to `05-*`: Non-destructive read tests
- `06-*` to `07-*`: Write/modification tests
- `08-*` to `09-*`: Destructive delete tests

This ensures read-only tests run before tests that modify or delete data.

### Template Structure

Each template defines:

1. **Endpoint Selector** - Which operations to test:
   ```yaml
   endpoint_selector:
     has_path_parameter: true      # Only test {id} endpoints
     requires_auth: true           # Only authenticated endpoints
     methods: ["GET", "PUT", "DELETE"]
   ```

2. **Role Selector** - Which role pairs to test:
   ```yaml
   role_selector:
     attacker_permission_level: "lower"   # Less privileged attacker
     victim_permission_level: "higher"    # More privileged victim
   ```

3. **Detection Logic** - What indicates a vulnerability:
   ```yaml
   detection:
     success_indicators:
       - type: status_code
         status_code: 200
       - type: body_field
         body_field: "user_data"
         exists: true
   ```

### Test Types

#### Simple Tests (Single Request)

1. Build HTTP request with variable substitution
2. Inject attacker's authentication token
3. Execute request against victim's resource
4. Check matchers against response
5. If matched → vulnerability found

#### Mutation Tests (Three-Phase)

Used for stateful attacks where resources must be created first:

1. **Setup Phase** (as victim): Create a resource, store its ID
2. **Attack Phase** (as attacker): Try to access victim's resource using stored ID
3. **Verify Phase** (as victim): Confirm resource still exists and is owned by victim

## OWASP Categories

Hadrian includes templates for OWASP API Top 10 vulnerabilities:

| Category | Description |
|----------|-------------|
| **API1** | Broken Object Level Authorization (BOLA) |
| **API2** | Broken Authentication |
| **API3** | Broken Object Property Level Authorization |
| **API4** | Unrestricted Resource Consumption |
| **API5** | Broken Function Level Authorization |
| **API6** | Unrestricted Access to Sensitive Business Flows |
| **API7** | Server Side Request Forgery |
| **API8** | Security Misconfiguration |
| **API9** | Improper Inventory Management |
| **API10** | Unsafe Consumption of APIs |

## Security Safeguards

- **Production URL Blocking**: Requires `--allow-production` flag
- **Internal IP Blocking**: Requires `--allow-internal` flag
- **Adaptive Rate Limiting**:
  - Proactive: Limits requests to configured rate (default 5 req/s)
  - Reactive: Detects 429/503 responses and implements backoff
  - Exponential backoff: 1s → 2s → 4s → 8s... (capped at max)
  - Fixed backoff: Constant wait between retries
  - Honors `Retry-After` header from server
  - Max retries: 5 (configurable)
- **Concurrency Control**: Maximum 10 concurrent requests
- **YAML Bomb Protection**: 1MB size limit, 20-depth limit
- **TLS 1.3 Enforcement**: No legacy TLS
- **Credential Validation**: Warns on insecure configurations
- **LLM Data Redaction**: Redacts sensitive data before LLM processing

## Example Workflow

```bash
hadrian test \
  --api crapi-openapi.yaml \
  --roles crapi-roles.yaml \
  --auth crapi-auth.yaml \
  --owasp API1,API2,API5 \
  --output json \
  --output-file report.json
```

This command:
1. Loads the crAPI OpenAPI spec
2. Loads role definitions and auth tokens
3. Filters to API1, API2, and API5 templates
4. Tests cross-role access for each matching endpoint
5. Outputs findings to JSON report
