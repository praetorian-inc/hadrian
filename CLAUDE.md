# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Hadrian is an API security testing framework for REST, GraphQL, and gRPC APIs that tests for OWASP API vulnerabilities using role-based authorization testing and YAML-driven templates.

## Claude Code Skill

This repo includes a Claude Code skill at `skills/hadrian-openapi-authz/` that generates `auth.yaml` and `roles.yaml` from API specifications (OpenAPI, GraphQL SDL, gRPC proto). When loaded as a plugin (`claude --plugin-dir .`), you can ask "Generate Hadrian config from my API spec" and it will produce valid configuration files.

## Build and Test Commands

```bash
# Build
go build -o hadrian ./cmd/hadrian

# Run all tests
go test ./...

# Run tests with race detection
go test -race ./...

# Run integration tests
go test -tags=integration ./...

# Run tests for a specific package
go test ./pkg/runner/...

# Run a single test
go test -run TestFunctionName ./pkg/package/...
```

## Architecture

### Core Flow

The CLI (`cmd/hadrian`) delegates to `pkg/runner.Run()` which orchestrates:
1. Parse OpenAPI spec → `model.Operation` list
2. Load roles configuration → `roles.RoleConfig` with parsed permissions
3. Load YAML templates → `templates.CompiledTemplate` list
4. For each operation × template × role combination:
   - Check if `EndpointSelector` matches the operation
   - Execute HTTP test using `templates.Executor`
   - Evaluate `Detection` rules to determine vulnerability
5. Optionally triage findings with LLM
6. Generate report (terminal/JSON/markdown)

### Key Packages

- **pkg/runner**: CLI commands, test orchestration, rate limiting (`ratelimit.go`, `ratelimit_client.go`), and execution logic
- **pkg/templates**: YAML template parsing (`parse.go`), compilation (`compile.go`), and HTTP execution (`execute.go`)
- **pkg/orchestrator**: Test orchestration, endpoint/role selectors, and mutation testing
- **pkg/roles**: Permission model with `<action>:<object>:<scope>` format and role-based filtering
- **pkg/model**: Data structures for `Finding`, `Operation`, `Evidence`, `Severity`
- **pkg/matchers**: Response matching (status codes, word/regex patterns)
- **pkg/reporter**: Output formatters (terminal, JSON, markdown) with finding redaction
- **pkg/llm**: LLM triage integration (Ollama)

### Template System

Templates in `templates/rest/` define security tests with:
- `endpoint_selector`: Filters which operations to test (methods, path params, auth requirements)
- `role_selector`: Defines attacker/victim role combinations by permission level (lower/higher/all/none)
- `http`: HTTP request definition with template variables (`{{operation.method}}`, `{{attacker_token}}`)
- `detection`: Success/failure indicators to determine if vulnerability exists

Templates support both simple single-phase tests and multi-phase mutation tests (setup → attack → verify).

#### Multi-Phase Mutation Tests

For complex vulnerability patterns like BFLA and BOPLA, templates use `test_phases`:

```yaml
test_phases:
  setup:
    # Single phase (backwards compatible)
    - path: "/api/user/dashboard"
      auth: "victim"
      store_response_fields:
        victim_id: "id"
        victim_video_id: "video_id"
    # Multiple setup phases supported (array syntax)
    - path: "/api/user/dashboard"
      auth: "attacker"
      store_response_fields:
        attacker_video_id: "video_id"
  attack:
    path: "/api/resource/{victim_id}"
    auth: "attacker"
    use_stored_field: "victim_id"
  verify:
    path: "/api/resource/{victim_id}"
    auth: "victim"
    check_field: "status"
    expected_value: "deleted"
```

Key features:
- **`store_response_fields`**: Map of `alias: json_path` to extract and store multiple fields from setup responses
- **`setup` as array**: Supports multiple sequential setup phases (e.g., get attacker's data, then victim's data)
- **Placeholder substitution**: Use `{alias}` in paths and data fields to reference stored values

### Permission Format

Permissions follow `<action>:<object>:<scope>`:
- Actions: `read`, `write`, `delete`, `execute`, `*`
- Scopes: `public`, `own`, `org`, `all`, `*`

### Rate Limiting

Built-in safeguards in `pkg/runner/ratelimit_client.go`:
- Proactive rate limiting (default 5 req/s) via `RateLimiter`
- Reactive backoff on 429/503 responses via `RateLimitingClient`
- Audit logging to `.hadrian/audit.log`

## Testing with crAPI

The `test/crapi/` directory contains a complete example for testing [OWASP crAPI](https://github.com/OWASP/crAPI), an intentionally vulnerable API. See `test/crapi/README.md` for full setup instructions.

Quick start:
```bash
# Start crAPI (note: compose file is in deploy/docker/)
git clone https://github.com/OWASP/crAPI.git && cd crAPI/deploy/docker && docker-compose up -d

# Run Hadrian (after setting up test users and tokens per the README)
HADRIAN_TEMPLATES=test/crapi/templates/rest ./hadrian test \
  --api test/crapi/crapi-openapi-spec.json \
  --roles test/crapi/roles.yaml \
  --auth test/crapi/auth.yaml \
  --verbose
```

## LLM-Assisted Planner

The planner (`pkg/planner/`) uses an LLM to generate a prioritized attack plan before execution. Instead of brute-forcing every operation × template × role combination, the LLM analyzes the API spec and selects the most likely vulnerability targets.

### Usage

```bash
# Plan + brute-force (recommended): LLM steps first, then remaining combos
./hadrian test rest --api spec.json --roles roles.yaml --auth auth.yaml --planner

# Plan only: run ONLY what the LLM chose
./hadrian test rest --api spec.json --roles roles.yaml --auth auth.yaml --planner --planner-only

# Steer the planner with custom context
./hadrian test rest ... --planner --planner-context "Focus on BOLA attacks on payment endpoints"
```

### Providers

Set the appropriate env var and use `--planner-provider`:

| Provider | Flag | Env Var | Default Model |
|----------|------|---------|---------------|
| OpenAI | `--planner-provider openai` (default) | `OPENAI_API_KEY` | gpt-4o |
| Anthropic | `--planner-provider anthropic` | `ANTHROPIC_API_KEY` | claude-sonnet-4-20250514 |
| Ollama | `--planner-provider ollama` | `OLLAMA_HOST` (optional) | llama3.2:latest |

### Programmatic Usage

For platform integration, inject an `LLMClient` via `Config.PlannerLLMClient`:

```go
config := runner.Config{
    PlannerEnabled:   true,
    PlannerLLMClient: myPlatformLLMClient, // implements planner.LLMClient
}
```

## Environment Variables

- `HADRIAN_TEMPLATES`: Custom templates directory path
- `OLLAMA_HOST`: Ollama host for LLM triage and planner
- `OPENAI_API_KEY`: OpenAI API key for planner
- `ANTHROPIC_API_KEY`: Anthropic API key for planner
