# Hadrian Live Test Suite

Automated security testing against four intentionally vulnerable applications covering REST, GraphQL, and gRPC protocols.

## Targets

| Target | Protocol | Description | Infrastructure |
|--------|----------|-------------|----------------|
| **vulnerable-api** | REST | Custom vulnerable API with BOLA/BFLA endpoints (tested with 3 auth methods) | Go binary (local) |
| **dvga** | GraphQL | [Damn Vulnerable GraphQL Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | Docker container |
| **grpc-server** | gRPC | Custom vulnerable gRPC service | Go binary (local) |
| **crapi** | REST | [OWASP crAPI](https://github.com/OWASP/crAPI) (Completely Ridiculous API) | Docker Compose (8 containers) |

## Quick Start

### 1. Setup (one-time)

```bash
# Set up all four targets (pulls images, clones repos, builds binaries, starts services)
./test/setup-live-targets.sh

# Or set up specific targets only
./test/setup-live-targets.sh --targets vulnerable-api,grpc

# Skip rebuild on re-runs (useful when iterating)
./test/setup-live-targets.sh --no-build
```

The setup script handles:
- Installing prerequisites (protoc, protoc-gen-go plugins)
- Building Go binaries (hadrian, vulnerable-api, grpc-server)
- Generating protobuf code for gRPC server
- Pulling Docker images (dvga)
- Cloning and starting crAPI (8 Docker containers)
- Auto-resolving port conflicts: walks forward from each target's
  default port and skips ports already claimed by another target in
  the same run. If discovery still picks badly, set
  `<TARGET>_PORT_OVERRIDE` (see [Configuration](#configuration)).
- Signing up the canonical crAPI users (see
  [test/crapi/README.md](crapi/README.md))
- Writing the patched OpenAPI spec to `.live-test-cache/`
- Writing a config file (`.live-test-config`) with resolved ports and
  the patched-spec path
- Hard-failing (`exit 1`) if crAPI does not become ready within 180s,
  so CI doesn't treat a partial setup as success

### 2. Run Tests

```bash
# Run all targets
./test/run-live-tests.sh

# Run specific targets
./test/run-live-tests.sh --targets vulnerable-api,grpc
./test/run-live-tests.sh --targets dvga
./test/run-live-tests.sh --targets crapi

# Run crAPI + LLM planner (opt-in; requires OPENAI_API_KEY, ANTHROPIC_API_KEY,
# or a running ollama instance — SKIPped cleanly when no provider is available).
OPENAI_API_KEY=sk-... ./test/run-live-tests.sh --targets crapi,crapi-planner

# Verbose output
./test/run-live-tests.sh --verbose

# Skip rebuild (faster re-runs)
./test/run-live-tests.sh --no-build

# Skip service start/stop (services already running)
./test/run-live-tests.sh --no-start --no-build
```

### 3. Teardown

```bash
# Stop all services and clean up
./test/setup-live-targets.sh --teardown

# Also remove the cached crAPI clone (forces a fresh re-clone next setup)
./test/setup-live-targets.sh --teardown --purge
```

`--teardown` runs `docker compose down -v --remove-orphans` for crAPI, so
named Postgres/Mongo volumes are dropped along with the containers.
Without `-v`, leftover state would cause "phone number already
registered" errors on the next setup. Stderr from the docker calls is
surfaced (not swallowed) so failures are visible.

## What the Test Runner Does

For each target, `run-live-tests.sh` automatically:

1. **Builds** hadrian and target binaries (unless `--no-build`)
2. **Starts** services (unless `--no-start`)
3. **Sets up auth** - acquires JWT tokens, creates test data
4. **Runs hadrian** security tests with appropriate flags
5. **Collects results** as JSON in `test/.results/`
6. **Prints summary** table with findings count and duration
7. **Cleans up** - stops processes and containers

### Auth Setup Per Target

| Target | Auth Setup |
|--------|-----------|
| vulnerable-api | Tests all 4 auth methods sequentially (see below) |
| dvga | Logs in as admin, creates private pastes for BOLA testing |
| grpc-server | Uses pre-configured static tokens |
| crapi | Creates 4 users (admin, user1, user2, mechanic), gets tokens, uploads test videos |

Canonical crAPI user identities (emails, mechanic code, default
password) and the `crapi_signup`/`crapi_login`/`crapi_setup_users`/
`crapi_patch_openapi_spec` helpers live in
[`crapi/crapi-helpers.sh`](crapi/crapi-helpers.sh). Both
`run-live-tests.sh` and `test-llm-planner.sh` source it so all crAPI
test paths share the same accounts and spec-patching logic.

### vulnerable-api Multi-Auth Testing

The vulnerable-api is tested four times, once per authentication method:

| Sub-target | Auth Method | How It Works |
|------------|------------|--------------|
| vulnerable-api-bearer | Bearer JWT | Logs in as admin/user1/user2 to get JWT tokens, writes dynamic auth config |
| vulnerable-api-apikey | API Key | Uses static API keys (`X-API-Key` header) |
| vulnerable-api-basic | Basic Auth | Uses username/password (HTTP Basic) |
| vulnerable-api-cookie | Cookie | Uses cookie session identifiers (configurable cookie name) |

The server is restarted with each `AUTH_METHOD` and API data is reset between runs to ensure consistent results.

## Configuration

### Environment Variables

**At setup time** (binds services to specific ports), set `*_PORT_OVERRIDE`:

```bash
VULN_API_PORT_OVERRIDE=9080 ./test/setup-live-targets.sh --targets vulnerable-api
CRAPI_PORT_OVERRIDE=8895    ./test/setup-live-targets.sh --targets crapi
```

**At run time** (when services are already running on non-default ports),
set the bare `*_PORT` env var so `run-live-tests.sh` connects to the right place:

```bash
VULN_API_PORT=9080 ./test/run-live-tests.sh --targets vulnerable-api
CRAPI_PORT=8895    ./test/run-live-tests.sh --targets crapi
```

Normally you don't need either — `setup-live-targets.sh` writes
`.live-test-config` with the resolved ports and `run-live-tests.sh` reads
that automatically.

### Config File

`setup-live-targets.sh` writes `.live-test-config` with resolved ports. The test runner reads this automatically - no environment variables needed.

### Default Ports

| Target | Default Port |
|--------|-------------|
| vulnerable-api | 9889 |
| dvga | 5013 |
| grpc-server | 50051 |
| crapi | 8888 |

## Output

Test results are saved as JSON files in `test/.results/`:

```
test/.results/
  vulnerable-api-bearer-results.json
  vulnerable-api-apikey-results.json
  vulnerable-api-basic-results.json
  dvga-results.json
  grpc-results.json
  crapi-results.json
```

## Prerequisites

| Requirement | Needed For | Install |
|------------|-----------|---------|
| Go 1.21+ | All targets | [go.dev/dl](https://go.dev/dl/) |
| Docker | dvga, crapi | [docker.com](https://www.docker.com/get-started/) |
| protoc | grpc-server | `brew install protobuf` (auto-installed by setup script) |

## Troubleshooting

### Port conflicts

`setup-live-targets.sh` walks forward from each target's default port
and skips ports already claimed by another target in the same run, so
common dev-machine collisions (e.g. VS Code Live Preview on 8888)
resolve automatically.

If the auto-pick still picks badly — for instance, you want crAPI on a
specific port — use the override env var:

```bash
CRAPI_PORT_OVERRIDE=8895 ./test/setup-live-targets.sh --targets crapi
```

Override env vars: `VULN_API_PORT_OVERRIDE`, `DVGA_PORT_OVERRIDE`,
`GRPC_PORT_OVERRIDE`, `CRAPI_PORT_OVERRIDE`. They're collision-checked
against both the host and other targets in the same run.

To inspect what's holding a port:
```bash
lsof -i :8888
```

### dvga not responding

DVGA needs `WEB_HOST=0.0.0.0` to be reachable via Docker port mapping. The scripts handle this automatically.

### crapi slow to start

crAPI runs 8 containers and can take 1-2 minutes on first start. The setup script waits up to 3 minutes.

### grpc-server build fails

The gRPC server needs protobuf code generation. The setup script handles this, but you can also run manually:
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

`test/regression/lab-2247-regression-tests.sh` is a fast, Docker-free
harness that asserts the **shape** of every fix from LAB-2247. Run it
in CI before the end-to-end flow — it catches a regression of any
individual bug fix in seconds without needing a live crAPI:

```bash
bash test/regression/lab-2247-regression-tests.sh
# Tests run: 101, Tests failed: 0
```

Add a new assertion when you change any of: the safety regex in
`run-live-tests.sh` / `test-llm-planner.sh`, the heredoc in
`setup-live-targets.sh`, or any helper in `crapi-helpers.sh`. Same idea
as a unit test in a language with one — bash has none, this is the
substitute.

## Directory Structure

```
test/
  setup-live-targets.sh    # One-time setup
  run-live-tests.sh        # End-to-end test runner
  test-llm-planner.sh      # LLM-planner regression tests
  test_detect_planner_provider.sh  # Unit test for detect_planner_provider
  README.md                # This file
  .live-test-config        # Auto-generated port + path config (gitignored)
  .live-test-cache/        # Patched OpenAPI specs (gitignored)
  .results/                # JSON test results (gitignored)
  .crapi-repo/             # Cloned crAPI repo (gitignored, --purge to remove)
  regression/
    lab-2247-regression-tests.sh   # Shape harness for LAB-2247 fixes
  vulnerable-api/          # REST vulnerable API source + templates
  dvga/                    # GraphQL test config + templates
  grpc-server/             # gRPC server source + templates
  llm-helpers.sh           # LLM provider detection helper
  crapi/                   # crAPI test config + templates
    crapi-helpers.sh       # Shared signup/login/spec-patch helpers
    test_crapi_resolve_spec.sh        # Unit test for crapi_resolve_spec
    test_crapi_patch_openapi_spec.sh  # Unit test for crapi_patch_openapi_spec
```

## Expected result

After running the e2e test shell script, you will see a table similar to the following.

```
TARGET                    STATUS     FINDINGS     DURATION
------------------------- ---------- ------------ ----------
vulnerable-api-bearer     PASS       61           21s
vulnerable-api-apikey     PASS       61           20s
vulnerable-api-basic      PASS       61           20s
vulnerable-api-cookie     PASS       61           20s
dvga                      PASS       6            3s
grpc                      PASS       8            1s
crapi                     PASS       26           37s
crapi-planner             SKIP       0            0s
```
