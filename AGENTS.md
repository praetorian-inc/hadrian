# AGENTS.md

Canonical agent instruction file for this repository; every coding agent loads it. `CLAUDE.md` is a one-line pointer to this file and `.gemini/settings.json` names it. Reference material that used to live here is under `docs/agents/`.

Hadrian is an API security testing framework for REST, GraphQL, and gRPC APIs: OWASP API Top 10 checks driven by role-based authorization testing and YAML templates. Architecture, package layout, and rate-limiting safeguards: `docs/agents/architecture.md`.

## Config-generation skill

`skills/hadrian-openapi-authz/SKILL.md` generates `auth.yaml` and `roles.yaml` from an API specification (OpenAPI, GraphQL SDL, gRPC proto). Loading this repo as a plugin directory so that skill is available is documented in `README.md` (plugin integration section) and `docs/configuration.md`.

## Build and Test Commands

```bash
go build -o hadrian ./cmd/hadrian   # root ./hadrian (gitignored) — what the live-target scripts build and call
make build                          # writes bin/hadrian instead; the two outputs are different paths
go test ./...                       # unit tests
go test -race ./...                 # same as `make test`
go test -tags=integration ./...     # in-process integration tests — no Docker, no live target
go test ./pkg/runner/...            # one package
go test -run TestFunctionName ./pkg/<package>/...
make check                          # gofmt + go vet + golangci-lint (v2 config in .golangci.yml) + race tests
```

The PR template asks for `make test` and `make lint` to pass; `make check` covers both.

### Integration tests (no Docker)

The `integration`-tagged tests are fully in-process and need no Docker daemon or external target. `pkg/runner/fixtures_test.go` builds an `httptest`-backed vulnerable REST API (opaque static bearer tokens, no JWT) that seeds BOLA/IDOR (API1), broken authentication (API2), excessive data exposure / BOPLA (API3), and BFLA (API5); `pkg/runner/integration_test.go` runs the real `templates/rest/` templates against it via `runner.RunTest(...)` and asserts findings per OWASP category. `pkg/runner/web_cache_deception_test.go` and `pkg/runner/cache_deception_test.go` add Web Cache Deception (API8) coverage — the former exercises the passive `templates/rest/` detection, the latter the active two-phase self-priming executor (`test_pattern: "cache-deception"`) against a stateful cache mock. `pkg/plugins/graphql/integration_test.go` stands up an in-process GraphQL service (introspection + DVGA-style queries/mutations). `pkg/plugins/grpc/integration_test.go` parses the `.proto` fixtures under `test/grpc/`, and its assertions are deliberately drift-sensitive: renaming a service, method, or owner field in `test/grpc/sample.proto` or `test/grpc/complex.proto` breaks them by design. The live targets under `test/` (below) are for optional end-to-end testing only, never for the Go suite.

## Templates — non-obvious behavior

- `--category` (REST subcommand only) defaults to `owasp` and matches **exactly**, case-insensitively, against a template's `info.category` and `info.tags`. The parameter-scoped BOLA examples under `examples/param-scoped-bola/` are `API1:2023` / `owasp-api-top10`, so they are not selected unless you pass `--category all` and point `HADRIAN_TEMPLATES` at that directory.
- `--template-dir` resolves flag, then `HADRIAN_TEMPLATES`, then the per-protocol default (`templates/rest/`, `templates/graphql/`, `templates/grpc/`).
- Template schema, endpoint/role selectors, multi-phase mutation tests, body escaping rules, and the permission format: `docs/agents/templates.md`.

## Live Test Targets

Optional end-to-end harnesses against four locally built vulnerable Go binaries under `test/` (`vulnerable-api`, `vulnerable-graphql`, `grpc-server`, `vulnerable-rest-complex`; each has its own `go.mod`, no Docker). They are **not** part of the Go test suite. **Do not wire them into CI on untrusted or fork PRs**: `vulnerable-graphql` performs real OS command execution and arbitrary file writes as the invoking user while it runs. Full CI safety note: `test/README.md`. `test/ratelimit-demo/` is a separate rate-limit demo server, not one of the four.

```bash
./test/setup-live-targets.sh              # builds ./hadrian + the four targets, writes test/.live-test-config
./test/run-live-tests.sh                  # every target, or --targets a,b to subset
./test/setup-live-targets.sh --teardown   # stop running targets, remove the generated config
./test/test-llm-planner.sh openai         # LLM-gated, standalone (not in the default run); provider arg defaults to openai
./test/test-llm-triage.sh  openai
```

Per-target coverage table, direct `hadrian test rest` invocation against the crAPI-shape target, port helpers, and the regression harness: `docs/agents/live-targets.md`.

## LLM planner and triage

- Planner flags (`--planner`, `--planner-only` which requires `--planner`, `--planner-provider`, `--planner-context`) exist on `hadrian test rest` only. Triage (`--llm-provider`) exists on `test rest` and `test graphql`; `test grpc` has neither.
- Defaults are asymmetric: the planner defaults to `openai`, triage defaults to `ollama`. The Anthropic default model also differs (planner `claude-sonnet-4-20250514`, triage `claude-sonnet-4-6`).
- Planner usage, provider table, and platform injection via `Config.PlannerLLMClient`: `docs/agents/planner.md`.

## Environment Variables

- `HADRIAN_TEMPLATES`: custom templates directory (see resolution order above)
- `OLLAMA_HOST`: Ollama host for triage and planner (default `http://localhost:11434`)
- `OLLAMA_MODEL`: Ollama model name (default `llama3.2:latest`)
- `OPENAI_API_KEY`: OpenAI key for triage (`--llm-provider openai`) and planner
- `ANTHROPIC_API_KEY`: Anthropic key for triage (`--llm-provider anthropic`) and planner
