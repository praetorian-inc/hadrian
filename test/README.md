# Hadrian Live Test Suite

Automated security testing against four intentionally vulnerable applications
covering REST, GraphQL, and gRPC protocols.

**Every target is an in-house Go binary — no Docker daemon, image pull, or
repository clone is required.** The full suite runs in a fresh devcontainer.

## Targets

| Target | Protocol | Description | Infrastructure |
|--------|----------|-------------|----------------|
| **vulnerable-api** | REST | Custom vulnerable API with BOLA/broken-auth endpoints (tested with 4 auth methods) | Go binary (local) |
| **vulnerable-graphql** | GraphQL | Custom vulnerable GraphQL app — introspection, BOLA, BFLA, alias-DoS, field duplication, error disclosure, command injection, path traversal | Go binary (local) |
| **grpc-server** | gRPC | Custom vulnerable gRPC service | Go binary (local) |
| **vulnerable-rest-complex** | REST | crAPI-shape multi-resource API (customers/vehicles/mechanics/orders) — cross-tenant BOLA, BFLA, mass-assignment, excessive data exposure, no-rate-limit OTP | Go binary (local) |

> `vulnerable-graphql` replaces the former Docker-based **DVGA** target and
> `vulnerable-rest-complex` replaces the former Docker-based **OWASP crAPI**
> target (LAB-2750). They are intentionally vulnerable and **FOR TESTING
> ONLY** — `vulnerable-graphql` performs real command execution and file
> writes by design.

## Quick Start

### 1. Setup (one-time)

```bash
# Build hadrian + all four Go target binaries, write .live-test-config
./test/setup-live-targets.sh

# Or set up specific targets only
./test/setup-live-targets.sh --targets vulnerable-api,grpc

# Skip rebuild on re-runs (useful when iterating)
./test/setup-live-targets.sh --no-build
```

The setup script handles:
- Installing prerequisites (protoc, protoc-gen-go plugins — only for grpc)
- Building Go binaries (hadrian and the four targets)
- Generating protobuf code for the gRPC server
- Auto-resolving port conflicts: walks forward from each target's default
  port and skips ports already claimed by another target in the same run. If
  discovery still picks badly, set `<TARGET>_PORT_OVERRIDE` (see
  [Configuration](#configuration)).
- Writing a config file (`.live-test-config`) with the resolved ports

### 2. Run Tests

```bash
# Run all targets
./test/run-live-tests.sh

# Run specific targets
./test/run-live-tests.sh --targets vulnerable-api,grpc
./test/run-live-tests.sh --targets vulnerable-graphql
./test/run-live-tests.sh --targets vulnerable-rest-complex

# Verbose output
./test/run-live-tests.sh --verbose

# Skip rebuild (faster re-runs)
./test/run-live-tests.sh --no-build

# Skip service start/stop (services already running)
./test/run-live-tests.sh --no-start --no-build
```

### 3. Teardown

```bash
# Stop any running target processes and remove the generated config
./test/setup-live-targets.sh --teardown
```

Teardown simply kills the local Go processes by name and removes
`.live-test-config` / `.live-test-cache` — there are no containers or volumes
to clean up.

## What the Test Runner Does

For each target, `run-live-tests.sh` automatically:

1. **Builds** hadrian and target binaries (unless `--no-build`)
2. **Starts** the target Go binary (unless `--no-start`)
3. **Sets up auth** — acquires JWT tokens via the target's login endpoint
4. **Runs hadrian** security tests with the target's templates
5. **Collects results** as JSON in `test/.results/`
6. **Prints summary** table with findings count and duration
7. **Cleans up** — stops the launched processes

### Auth Setup Per Target

| Target | Auth Setup |
|--------|-----------|
| vulnerable-api | Tests all 4 auth methods sequentially (see below) |
| vulnerable-graphql | Logs in as admin/user1/user2 via the `login` mutation; seed pastes/users are created at server startup |
| grpc-server | Uses pre-configured static tokens |
| vulnerable-rest-complex | Logs in as admin/user1/user2/mechanic1 via `POST /api/auth/login`; seed data is created at server startup |

The GraphQL target runs **without** `--skip-builtin-checks`, so hadrian's
built-in checks (introspection, alias-based DoS, field duplication) fire
alongside the template-driven BOLA/BFLA/data-exposure tests.

### vulnerable-api Multi-Auth Testing

The vulnerable-api is tested four times, once per authentication method:

| Sub-target | Auth Method | How It Works |
|------------|------------|--------------|
| vulnerable-api-bearer | Bearer JWT | Logs in as admin/user1/user2 to get JWT tokens, writes dynamic auth config |
| vulnerable-api-apikey | API Key | Uses static API keys (`X-API-Key` header) |
| vulnerable-api-basic | Basic Auth | Uses username/password (HTTP Basic) |
| vulnerable-api-cookie | Cookie | Uses static session IDs (`session_id` cookie) |

The server is restarted with each `AUTH_METHOD` and API data is reset between
runs to ensure consistent results.

## Configuration

### Environment Variables

**At setup time** (binds services to specific ports), set `*_PORT_OVERRIDE`:

```bash
VULN_API_PORT_OVERRIDE=9080        ./test/setup-live-targets.sh --targets vulnerable-api
VULN_REST_COMPLEX_PORT_OVERRIDE=8895 ./test/setup-live-targets.sh --targets vulnerable-rest-complex
```

**At run time** (when services are already running on non-default ports),
set the bare `*_PORT` env var so `run-live-tests.sh` connects to the right place:

```bash
VULN_API_PORT=9080         ./test/run-live-tests.sh --targets vulnerable-api
VULN_REST_COMPLEX_PORT=8895 ./test/run-live-tests.sh --targets vulnerable-rest-complex
```

Normally you don't need either — `setup-live-targets.sh` writes
`.live-test-config` with the resolved ports and `run-live-tests.sh` reads
that automatically.

### Default Ports

| Target | Default Port |
|--------|-------------|
| vulnerable-api | 9889 |
| vulnerable-graphql | 5013 |
| grpc-server | 50051 |
| vulnerable-rest-complex | 8888 |

## Output

Test results are saved as JSON files in `test/.results/`:

```
test/.results/
  vulnerable-api-bearer-results.json
  vulnerable-api-apikey-results.json
  vulnerable-api-basic-results.json
  vulnerable-api-cookie-results.json
  vulnerable-graphql-results.json
  grpc-results.json
  vulnerable-rest-complex-results.json
```

## Prerequisites

| Requirement | Needed For | Install |
|------------|-----------|---------|
| Go 1.21+ | All targets | [go.dev/dl](https://go.dev/dl/) |
| protoc | grpc-server | `brew install protobuf` (auto-installed by setup script) |
| python3 | Result parsing / token extraction in the harness | usually preinstalled |

No Docker is required for any target.

## Troubleshooting

### Port conflicts

`setup-live-targets.sh` walks forward from each target's default port and
skips ports already claimed by another target in the same run, so common
dev-machine collisions (e.g. something already on 8888) resolve
automatically.

If the auto-pick still picks badly, use the override env var:

```bash
VULN_REST_COMPLEX_PORT_OVERRIDE=8895 ./test/setup-live-targets.sh --targets vulnerable-rest-complex
```

Override env vars: `VULN_API_PORT_OVERRIDE`, `VULN_GRAPHQL_PORT_OVERRIDE`,
`GRPC_PORT_OVERRIDE`, `VULN_REST_COMPLEX_PORT_OVERRIDE`. They're
collision-checked against both the host and other targets in the same run.

To inspect what's holding a port:
```bash
lsof -i :8888
```

### grpc-server build fails

The gRPC server needs protobuf code generation. The setup script handles
this, but you can also run manually:
```bash
cd test/grpc-server
make proto
make build
```

### Re-running after teardown

```bash
./test/setup-live-targets.sh     # Full setup
./test/run-live-tests.sh         # Run tests
./test/setup-live-targets.sh --teardown  # Clean up
```

## Regression harness

`test/regression/lab-2750-regression-tests.sh` is a fast, dependency-free
harness that asserts the **shape** of the LAB-2750 change: no Docker/crAPI/DVGA
references survive in the harness scripts, the four Go targets exist and are
wired into the defaults, the generic port helpers (relocated to
`test/lib/port-helpers.sh`) still behave correctly, and `.live-test-config`
still matches the safety regex.

```bash
bash test/regression/lab-2750-regression-tests.sh
# Ran: 31, Failed: 0
```

> This harness supersedes the retired `lab-2247-regression-tests.sh`, whose
> assertions targeted crAPI compose-patching, crAPI user provisioning, and
> Docker teardown — all removed by LAB-2750.

Add a new assertion when you change any of: the safety regex in
`run-live-tests.sh` / `test-llm-planner.sh`, the heredoc in
`setup-live-targets.sh`, or the port helpers in `lib/port-helpers.sh`.

## Directory Structure

```
test/
  setup-live-targets.sh    # One-time build/setup
  run-live-tests.sh        # End-to-end test runner
  test-llm-planner.sh      # LLM-planner test (vs vulnerable-rest-complex)
  test-llm-triage.sh       # LLM-triage test (vs vulnerable-rest-complex)
  README.md                # This file
  .live-test-config        # Auto-generated port config (gitignored)
  .live-test-cache/        # Patched OpenAPI specs (gitignored)
  .results/                # JSON test results (gitignored)
  lib/
    port-helpers.sh        # Shared generic port helpers (sourced by the scripts)
  regression/
    lab-2750-regression-tests.sh   # Shape harness for the LAB-2750 change
  vulnerable-api/          # REST vulnerable API (Go) + templates
  vulnerable-graphql/      # GraphQL vulnerable app (Go) + templates
  grpc-server/             # gRPC server (Go) + templates
  vulnerable-rest-complex/ # crAPI-shape REST app (Go) + templates
```

## Expected result

After running the e2e test shell script, you will see a table similar to the
following (run in a devcontainer with no Docker daemon):

```
TARGET                      STATUS     FINDINGS     DURATION
--------------------------- ---------- ------------ ----------
vulnerable-api-bearer       PASS       61           20s
vulnerable-api-apikey       PASS       61           20s
vulnerable-api-basic        PASS       61           20s
vulnerable-api-cookie       PASS       61           20s
vulnerable-graphql          PASS       10           4s
grpc                        PASS       8            1s
vulnerable-rest-complex     PASS       25           22s
```
