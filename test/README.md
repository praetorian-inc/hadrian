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
```

The setup script handles:
- Installing prerequisites (protoc, protoc-gen-go plugins)
- Building Go binaries (hadrian, vulnerable-api, grpc-server)
- Generating protobuf code for gRPC server
- Pulling Docker images (dvga)
- Cloning and starting crAPI (8 Docker containers)
- Auto-resolving port conflicts (finds next available port)
- Writing a config file (`.live-test-config`) with resolved ports

### 2. Run Tests

```bash
# Run all targets
./test/run-live-tests.sh

# Run specific targets
./test/run-live-tests.sh --targets vulnerable-api,grpc
./test/run-live-tests.sh --targets dvga
./test/run-live-tests.sh --targets crapi

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
```

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
| vulnerable-api | Tests all 3 auth methods sequentially (see below) |
| dvga | Logs in as admin, creates private pastes for BOLA testing |
| grpc-server | Uses pre-configured static tokens |
| crapi | Creates 4 users (admin, user1, user2, mechanic), gets tokens, uploads test videos |

### vulnerable-api Multi-Auth Testing

The vulnerable-api is tested three times, once per authentication method:

| Sub-target | Auth Method | How It Works |
|------------|------------|--------------|
| vulnerable-api-bearer | Bearer JWT | Logs in as admin/user1/user2 to get JWT tokens, writes dynamic auth config |
| vulnerable-api-apikey | API Key | Uses static API keys (`X-API-Key` header) |
| vulnerable-api-basic | Basic Auth | Uses username/password (HTTP Basic) |

The server is restarted with each `AUTH_METHOD` and API data is reset between runs to ensure consistent results.

## Configuration

### Environment Variables

All ports can be overridden via environment variables:

```bash
VULN_API_PORT=9080 ./test/run-live-tests.sh --targets vulnerable-api
DVGA_PORT=5014 ./test/run-live-tests.sh --targets dvga
GRPC_PORT=50052 ./test/run-live-tests.sh --targets grpc
CRAPI_PORT=8889 ./test/run-live-tests.sh --targets crapi
```

### Config File

`setup-live-targets.sh` writes `.live-test-config` with resolved ports. The test runner reads this automatically - no environment variables needed.

### Default Ports

| Target | Default Port |
|--------|-------------|
| vulnerable-api | 8080 |
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

The setup script auto-resolves port conflicts by finding the next available port. If you see issues, check:
```bash
lsof -i :8888  # Check what's using a port
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

## Directory Structure

```
test/
  setup-live-targets.sh    # One-time setup (this file)
  run-live-tests.sh        # Test runner
  README.md                # This file
  .live-test-config        # Auto-generated port config (gitignored)
  .results/                # JSON test results (gitignored)
  .crapi-repo/             # Cloned crAPI repo (gitignored)
  vulnerable-api/          # REST vulnerable API source + templates
  dvga/                    # GraphQL test config + templates
  grpc-server/             # gRPC server source + templates
  crapi/                   # crAPI test config + templates
```
