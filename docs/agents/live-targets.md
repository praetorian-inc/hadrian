# Hadrian live test targets (agent reference)

Relocated from `AGENTS.md` (ENG-6805). The operational guide is `test/README.md`.

## Live Test Targets

> These are **optional** end-to-end harnesses against locally-built vulnerable
> targets and are **not** part of the Go test suite (`go test -tags=integration`
> needs no live targets). Do **not** wire them into CI on untrusted/fork PRs — see
> the CI safety note in `test/README.md`: `vulnerable-graphql` runs real OS command
> execution and arbitrary file writes as the invoking user while it is up.

The `test/` directory ships four in-house vulnerable targets, each a self-contained
Go binary with its own `go.mod` (no Docker daemon, image pull, or repo clone required —
the full suite runs in a fresh devcontainer). `test/ratelimit-demo/` is a fifth,
separate rate-limit demo server that is not part of this suite.

| Target | Protocol | Replaces | Covers |
|--------|----------|----------|--------|
| `vulnerable-api` | REST | — | BOLA, broken auth (bearer/apikey/basic/cookie) |
| `vulnerable-graphql` | GraphQL | DVGA (Docker) | introspection, BOLA, BFLA, alias-DoS, field-duplication, error disclosure, command injection, path traversal |
| `grpc-server` | gRPC | — | BOLA, BFLA, metadata injection |
| `vulnerable-rest-complex` | REST | OWASP crAPI (Docker) | cross-tenant BOLA, BFLA, mass-assignment, excessive data exposure, no-rate-limit OTP (customers/vehicles/mechanics/orders) |

The supported flow is the wrapper scripts under `test/`:

```bash
# One-time setup: builds ./hadrian + the four Go target binaries, writes test/.live-test-config.
./test/setup-live-targets.sh

# Run hadrian against every target (or pass --targets to subset).
./test/run-live-tests.sh

# Stop any running target processes and remove the generated config.
./test/setup-live-targets.sh --teardown

# Optional: exercise the LLM planner / triage against vulnerable-rest-complex.
# Standalone, LLM-gated scripts (not part of the default run); pass the provider
# (defaults to openai).
export OPENAI_API_KEY=sk-...    # set once in your shell
./test/test-llm-planner.sh openai
./test/test-llm-triage.sh  openai
```

Programmatic invocation (without the wrapper), e.g. the crAPI-shape REST target:
```bash
./hadrian test rest \
  --api test/vulnerable-rest-complex/openapi.yaml \
  --roles test/vulnerable-rest-complex/roles.yaml \
  --auth test/vulnerable-rest-complex/auth-bearer.yaml \
  --template-dir test/vulnerable-rest-complex/templates/owasp \
  --verbose
```

Generic port helpers shared by all targets live in `test/lib/port-helpers.sh`
(rest-complex-specific helpers in `test/lib/rest-complex-helpers.sh`).
A Docker-free regression harness lives at `test/regression/lab-2750-regression-tests.sh`.
