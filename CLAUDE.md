# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Hadrian is an API security testing framework for REST APIs that tests for OWASP API vulnerabilities using role-based authorization testing and YAML-driven templates.

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

- **pkg/runner**: CLI commands and main test orchestration loop
- **pkg/templates**: YAML template parsing (`parse.go`), compilation (`compile.go`), and HTTP execution (`execute.go`)
- **pkg/owasp**: OWASP-specific test runner, endpoint/role selectors, and mutation testing
- **pkg/roles**: Permission model with `<action>:<object>:<scope>` format and role-based filtering
- **pkg/model**: Data structures for `Finding`, `Operation`, `Evidence`, `Severity`
- **pkg/matchers**: Response matching (status codes, word/regex patterns)
- **pkg/reporter**: Output formatters (terminal, JSON, markdown) with finding redaction
- **pkg/llm**: LLM triage integration (Claude, OpenAI, Ollama) with fallback chain

### Template System

Templates in `templates/owasp/` define security tests with:
- `endpoint_selector`: Filters which operations to test (methods, path params, auth requirements)
- `role_selector`: Defines attacker/victim role combinations by permission level (lower/higher/all)
- `http`: HTTP request definition with template variables (`{{operation.method}}`, `{{attacker_token}}`)
- `detection`: Success/failure indicators to determine if vulnerability exists

Templates support both simple single-phase tests and multi-phase mutation tests (setup → attack → verify).

### Permission Format

Permissions follow `<action>:<object>:<scope>`:
- Actions: `read`, `write`, `delete`, `execute`, `*`
- Scopes: `public`, `own`, `org`, `all`, `*`

### Production Safety

Built-in safeguards in `pkg/runner/production.go`:
- Blocks production URLs by default (requires `--allow-production`)
- Blocks internal/private IPs (requires `--allow-internal`)
- Rate limiting (default 5 req/s)
- Audit logging to `.hadrian/audit.log`

## Testing with crAPI

The `testdata/crapi/` directory contains a complete example for testing [OWASP crAPI](https://github.com/OWASP/crAPI), an intentionally vulnerable API. See `testdata/crapi/README.md` for full setup instructions.

Quick start:
```bash
# Start crAPI (note: compose file is in deploy/docker/)
git clone https://github.com/OWASP/crAPI.git && cd crAPI/deploy/docker && docker-compose up -d

# Run Hadrian (after setting up test users and tokens per the README)
HADRIAN_TEMPLATES=testdata/crapi/templates/owasp ./hadrian test \
  --api testdata/crapi/crapi-openapi-spec.json \
  --roles testdata/crapi/roles.yaml \
  --auth testdata/crapi/auth.yaml \
  --allow-internal \
  --verbose
```

## Environment Variables

- `HADRIAN_TEMPLATES`: Custom templates directory path
- `ANTHROPIC_API_KEY`: Claude API key for LLM triage (preferred)
- `OPENAI_API_KEY`: OpenAI API key for LLM triage (fallback)
- `OLLAMA_HOST`: Ollama host for local LLM triage (final fallback)
