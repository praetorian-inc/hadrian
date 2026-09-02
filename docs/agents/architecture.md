# Hadrian architecture (agent reference)

Relocated from `AGENTS.md` (ENG-6805). Package-level detail also lives in `docs/architecture.md`.

## Overview

Hadrian is an API security testing framework for REST, GraphQL, and gRPC APIs that tests for OWASP API vulnerabilities using role-based authorization testing and YAML-driven templates.

## Core Flow

The CLI (`cmd/hadrian`) delegates to `pkg/runner.Run()` which orchestrates:
1. Parse OpenAPI spec → `model.Operation` list
2. Load roles configuration → `roles.RoleConfig` with parsed permissions
3. Load YAML templates → `templates.CompiledTemplate` list
4. For each operation × template × role combination:
   - Check if `EndpointSelector` matches the operation
   - Execute HTTP test using `templates.Executor`
   - Evaluate `Detection` rules to determine vulnerability
5. Optionally triage findings with LLM
6. Generate report (terminal/JSON/markdown/SARIF)

## Key Packages

- **pkg/runner**: CLI commands, test orchestration, rate limiting (`ratelimit.go`, `ratelimit_client.go`), and execution logic
- **pkg/templates**: YAML template parsing (`parse.go`), compilation (`compile.go`), and HTTP execution (`execute.go`)
- **pkg/orchestrator**: Test orchestration, endpoint/role selectors, and mutation testing
- **pkg/roles**: Permission model with `<action>:<object>:<scope>` format and role-based filtering
- **pkg/model**: Data structures for `Finding`, `Operation`, `Evidence`, `Severity`
- **pkg/matchers**: Response matching (status codes, word/regex patterns)
- **pkg/reporter**: Output formatters (terminal, JSON, markdown) with finding redaction. SARIF v2.1.0 output lives at `pkg/runner/sarif.go` (it depends on the templates list, which is only available inside `pkg/runner`).
- **pkg/llm**: LLM triage integration (Ollama, OpenAI, Anthropic)

Also present in the tree and not described above: `pkg/auth`, `pkg/graphql`, `pkg/log`, `pkg/plugins` (REST, GraphQL, and gRPC protocol plugins), `pkg/planner` (see `docs/agents/planner.md`), `pkg/util`, and `internal/http`. This list is a partial map; the tree is authoritative.

## Rate Limiting

Built-in safeguards in `pkg/runner/ratelimit_client.go` and `pkg/runner/ratelimit.go`:
- Proactive rate limiting (default 5 req/s) via `RateLimiter`
- Reactive backoff on 429/503 responses via `RateLimitingClient` (exponential by default, 1s initial, 60s max, 5 retries)
- Audit logging via the `--audit-log` flag on the REST subcommand (default path is a gitignored `.hadrian` file)
