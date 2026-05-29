#!/usr/bin/env bash
# =============================================================================
# run-live-tests.sh
#
# Runs Hadrian security tests against all four vulnerable targets:
#   1. vulnerable-api (REST - Bearer/APIKey/Basic auth)
#   2. dvga (GraphQL - Damn Vulnerable GraphQL Application)
#   3. grpc-server (gRPC - vulnerable gRPC service)
#   4. crapi (REST - OWASP crAPI, requires external setup)
#
# Prerequisites:
#   - Run ./test/setup-live-targets.sh first (one-time setup)
#   - Or manually: Go 1.21+, Docker (for dvga/crapi), hadrian binary
#
# Usage:
#   ./test/run-live-tests.sh [options]
#
# Options:
#   --targets <list>      Comma-separated targets to test (default: all)
#                         Valid: vulnerable-api,dvga,grpc,crapi,crapi-planner
#                         crapi-planner is opt-in and requires an LLM credential
#                         (OPENAI_API_KEY, ANTHROPIC_API_KEY, or running ollama);
#                         it is SKIPped cleanly when no provider is available.
#   --verbose             Enable verbose Hadrian output
#   --no-build            Skip building hadrian and target binaries
#   --no-start            Don't start/stop services (assume already running)
#   --output-dir <dir>    Directory for JSON results (default: test/.results)
#   --help                Show this help message
#
# Examples:
#   ./test/run-live-tests.sh                          # Run all targets
#   ./test/run-live-tests.sh --targets vulnerable-api # Just vulnerable-api
#   ./test/run-live-tests.sh --targets dvga,grpc      # GraphQL + gRPC
#   ./test/run-live-tests.sh --verbose --no-build     # Verbose, skip build
# =============================================================================

set -euo pipefail

# ==== Configuration ====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HADRIAN_BIN="${HADRIAN_BIN:-${REPO_ROOT}/hadrian}"
OUTPUT_DIR="${SCRIPT_DIR}/.results"
CONFIG_FILE="${SCRIPT_DIR}/.live-test-config"

# Load config from setup script if it exists (ports, paths).
# The regex requires every value to be double-quoted so `source` can't
# word-split a path containing whitespace into a command (the previous
# regex permitted unquoted values with spaces, which made
# `--crapi-dir '/tmp/foo bar'` exec `bar`). Quoted form is what
# setup-live-targets.sh writes; an old/loose config will be rejected
# loudly — re-run setup to regenerate.
if [ -f "$CONFIG_FILE" ]; then
    if grep -qvE '^[[:space:]]*(#.*)?$|^[A-Za-z_][A-Za-z0-9_]*="[A-Za-z0-9_./:@,+ -]*"$' "$CONFIG_FILE"; then
        echo "ERROR: $CONFIG_FILE contains unsafe content. Expected only comments, blank lines, or KEY=\"VALUE\" assignments. Re-run setup-live-targets.sh to regenerate." >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

# Default ports — the single source of truth for "what port does target X
# bind by default". Conditionals later in the script reference these
# constants instead of hardcoded literals so a future port move only has
# to touch one place per target.
VULN_API_DEFAULT_PORT=9889
DVGA_DEFAULT_PORT=5013
GRPC_DEFAULT_PORT=50051
# CRAPI default port comes from crapi-helpers.sh
# (CRAPI_OPENAPI_SPEC_DEFAULT_PORT, sourced below).

# Target ports (env vars > config file > defaults)
VULN_API_PORT="${VULN_API_PORT:-$VULN_API_DEFAULT_PORT}"
DVGA_PORT="${DVGA_PORT:-$DVGA_DEFAULT_PORT}"
GRPC_PORT="${GRPC_PORT:-$GRPC_DEFAULT_PORT}"

# Shared crAPI helpers (canonical users, signup/login, spec patcher).
# shellcheck source=test/crapi/crapi-helpers.sh
. "${SCRIPT_DIR}/crapi/crapi-helpers.sh"

# Provider-agnostic LLM helpers (detect_planner_provider).
# shellcheck source=test/llm-helpers.sh
. "${SCRIPT_DIR}/llm-helpers.sh"

# CRAPI_PORT default tracks the helper's CRAPI_OPENAPI_SPEC_DEFAULT_PORT.
CRAPI_PORT="${CRAPI_PORT:-$CRAPI_OPENAPI_SPEC_DEFAULT_PORT}"

# Require Bash 4+ for associative arrays
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "ERROR: This script requires Bash 4+ (found ${BASH_VERSION}). On macOS: brew install bash" >&2
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Defaults
TARGETS="vulnerable-api,dvga,grpc,crapi"
VERBOSE=""
DO_BUILD=true
DO_START=true

# Track results per target using associative arrays
declare -A STATUS FINDINGS DURATION
for _t in vulnerable-api-bearer vulnerable-api-apikey vulnerable-api-basic vulnerable-api-cookie dvga grpc crapi crapi-planner; do
    STATUS["$_t"]="NOT_RUN"
    FINDINGS["$_t"]="0"
    DURATION["$_t"]="0"
done

PIDS_TO_CLEANUP=""

# ==== Argument parsing ====
while [ $# -gt 0 ]; do
    case $1 in
        --targets)
            TARGETS="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE="--verbose"
            shift
            ;;
        --no-build)
            DO_BUILD=false
            shift
            ;;
        --no-start)
            DO_START=false
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help)
            sed -n '2,/^# =====/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# ==== Result helpers (associative arrays) ====
set_status() { STATUS["$1"]="$2"; }
get_status() { echo "${STATUS[$1]:-NOT_RUN}"; }
set_findings() { FINDINGS["$1"]="$2"; }
get_findings() { echo "${FINDINGS[$1]:-0}"; }
set_duration() { DURATION["$1"]="$2"; }
get_duration() { echo "${DURATION[$1]:-0}"; }

# ==== Helper functions ====

# All log_* helpers write to stderr so they don't collide with values
# captured from `$(...)`. Same convention as setup-live-targets.sh.
log_header() {
    echo "" >&2
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}" >&2
    echo -e "${BOLD}${BLUE}  $1${NC}" >&2
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}" >&2
}

log_info() { echo -e "${CYAN}[INFO]${NC} $1" >&2; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" >&2; }

wait_for_http() {
    local url=$1
    local name=$2
    local max_wait=${3:-30}
    local elapsed=0

    while ! curl -sf -o /dev/null "$url" 2>/dev/null; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [ $elapsed -ge $max_wait ]; then
            log_fail "$name did not respond at $url within ${max_wait}s"
            return 1
        fi
    done
    log_ok "$name is ready at $url"
    return 0
}

cleanup() {
    log_header "Cleanup"
    for pid in $PIDS_TO_CLEANUP; do
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping process $pid"
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done

    # Stop dvga container if we started it
    if [ "$DO_START" = true ] && command -v docker >/dev/null 2>&1; then
        if docker ps -q --filter "name=hadrian-dvga" 2>/dev/null | grep -q .; then
            log_info "Stopping dvga container"
            docker rm -f hadrian-dvga 2>/dev/null || true
        fi
    fi
}

trap cleanup EXIT

extract_finding_count() {
    local json_file=$1
    if [ -f "$json_file" ]; then
        python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('stats',{}).get('findings',len(d.get('findings',[]))))" "$json_file" 2>/dev/null || echo "?"
    else
        echo "?"
    fi
}

run_hadrian() {
    local name=$1
    shift
    local start_time
    start_time=$(date +%s)

    log_info "Running: $HADRIAN_BIN $*"

    local exit_code=0
    "$HADRIAN_BIN" "$@" 2>&1 || exit_code=$?

    # Exit code 0 or 1 (findings detected) are both success
    if [ $exit_code -le 1 ]; then
        set_status "$name" "PASS"
    else
        set_status "$name" "ERROR"
    fi

    local end_time
    end_time=$(date +%s)
    set_duration "$name" $(( end_time - start_time ))
}

# ==== Build phase ====
if [ "$DO_BUILD" = true ]; then
    log_header "Building Hadrian and Targets"

    log_info "Building hadrian..."
    (cd "$REPO_ROOT" && go build -o hadrian ./cmd/hadrian)
    log_ok "hadrian built: $HADRIAN_BIN"

    if echo "$TARGETS" | grep -q "vulnerable-api"; then
        log_info "Building vulnerable-api..."
        (cd "${SCRIPT_DIR}/vulnerable-api" && go build -o vulnerable-api .)
        log_ok "vulnerable-api built"
    fi

    if echo "$TARGETS" | grep -q "grpc"; then
        log_info "Building grpc-server..."
        (cd "${SCRIPT_DIR}/grpc-server" && {
            # Check for actual generated files, not just directory existence
            # This handles the case where pb/ exists but is empty from a failed run
            if [ ! -f pb/service.pb.go ] || [ ! -f pb/service_grpc.pb.go ]; then
                printf "[?] gRPC server requires generated protobuf code.\n"
                printf "    This will run protoc to generate Go code from service.proto.\n"
                printf "    Generate protobuf code now? [y/N] "
                read -r REPLY
                if [ "$REPLY" = "y" ] || [ "$REPLY" = "Y" ]; then
                    if command -v protoc >/dev/null 2>&1; then
                        log_info "Generating protobuf code..."
                        # Clean up any empty/corrupted pb directory from previous failed runs
                        rm -rf pb
                        mkdir -p pb
                        if ! protoc --go_out=pb --go_opt=paths=source_relative \
                            --go-grpc_out=pb --go-grpc_opt=paths=source_relative \
                            service.proto; then
                            log_fail "protoc failed to generate Go code"
                            rm -rf pb  # Clean up on failure
                            exit 1
                        fi
                        log_ok "Protobuf code generated"
                    else
                        log_fail "protoc not found. Install with: brew install protobuf"
                        log_fail "Then install Go plugins:"
                        log_fail "  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
                        log_fail "  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"
                        exit 1
                    fi
                else
                    log_fail "Skipping grpc-server (protobuf files required). Run 'make proto' in test/grpc-server/ first."
                    exit 1
                fi
            fi
            go build -o grpc-server .
        })
        log_ok "grpc-server built"
    fi
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# ==== Test: vulnerable-api ====
if echo "$TARGETS" | grep -q "vulnerable-api"; then
    # Test all four auth methods: bearer, api_key, basic, cookie
    VULN_API_AUTH_METHODS="bearer api_key basic cookie"
    VULN_API_SKIP_ALL=false

    # If using a non-default port, patch the OpenAPI spec's server URL.
    # Default and the substitution target both come from
    # VULN_API_DEFAULT_PORT so a future port move is a single-line edit.
    VULN_API_SPEC="${SCRIPT_DIR}/vulnerable-api/openapi.yaml"
    if [ "$VULN_API_PORT" != "$VULN_API_DEFAULT_PORT" ]; then
        VULN_API_SPEC="${OUTPUT_DIR}/vulnerable-api-openapi.yaml"
        sed "s|http://localhost:${VULN_API_DEFAULT_PORT}|http://localhost:${VULN_API_PORT}|g" \
            "${SCRIPT_DIR}/vulnerable-api/openapi.yaml" > "$VULN_API_SPEC"
        log_info "Patched OpenAPI spec to use port $VULN_API_PORT"
    fi

    for auth_method in $VULN_API_AUTH_METHODS; do
        # Map auth_method to target name suffix (api_key -> apikey for variable names)
        case "$auth_method" in
            bearer)  target_suffix="bearer" ; auth_label="Bearer JWT" ;;
            api_key) target_suffix="apikey" ; auth_label="API Key" ;;
            basic)   target_suffix="basic"  ; auth_label="Basic Auth" ;;
            cookie)  target_suffix="cookie" ; auth_label="Cookie Auth" ;;
        esac

        target_name="vulnerable-api-${target_suffix}"
        log_header "Target 1: vulnerable-api (REST - ${auth_label})"

        if [ "$VULN_API_SKIP_ALL" = true ]; then
            set_status "$target_name" "SKIP"
            continue
        fi

        if [ "$DO_START" = true ]; then
            # Kill any existing instance
            pkill -f "vulnerable-api$" 2>/dev/null || true
            sleep 1

            log_info "Starting vulnerable-api on port $VULN_API_PORT (auth: ${auth_method})..."
            (cd "${SCRIPT_DIR}/vulnerable-api" && AUTH_METHOD="${auth_method}" PORT="${VULN_API_PORT}" ./vulnerable-api) &
            LAST_PID=$!
            PIDS_TO_CLEANUP="$PIDS_TO_CLEANUP $LAST_PID"
            wait_for_http "http://localhost:${VULN_API_PORT}/health" "vulnerable-api" 15 || {
                set_status "$target_name" "SKIP"
                log_warn "Skipping vulnerable-api ${auth_label} tests"
                VULN_API_SKIP_ALL=true
                continue
            }
        fi

        # Reset API data between auth method runs
        curl -sf -X POST "http://localhost:${VULN_API_PORT}/api/reset" >/dev/null 2>&1 || true

        AUTH_FILE="${OUTPUT_DIR}/vuln-api-auth-${target_suffix}.yaml"

        if [ "$auth_method" = "bearer" ]; then
            log_info "Acquiring JWT tokens..."
            ADMIN_TOKEN=$(curl -sf -X POST "http://localhost:${VULN_API_PORT}/api/auth/login" \
                -H "Content-Type: application/json" \
                --data-binary @- <<< '{"username":"admin","password":"admin123"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])" 2>/dev/null || echo "")
            USER1_TOKEN=$(curl -sf -X POST "http://localhost:${VULN_API_PORT}/api/auth/login" \
                -H "Content-Type: application/json" \
                --data-binary @- <<< '{"username":"user1","password":"user1pass"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])" 2>/dev/null || echo "")
            USER2_TOKEN=$(curl -sf -X POST "http://localhost:${VULN_API_PORT}/api/auth/login" \
                -H "Content-Type: application/json" \
                --data-binary @- <<< '{"username":"user2","password":"user2pass"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])" 2>/dev/null || echo "")

            if [ -z "$ADMIN_TOKEN" ] || [ -z "$USER1_TOKEN" ] || [ -z "$USER2_TOKEN" ]; then
                log_fail "Failed to acquire JWT tokens"
                set_status "$target_name" "ERROR"
                continue
            fi
            log_ok "Tokens acquired for admin, user1, user2"

            # Emit ${VAR} env-var refs (single-quoted heredoc) rather than
            # inline JWTs so hadrian's expandEnvSafe resolves them at load
            # and detectHardcodedSecret does not flag them — same pattern as
            # the crapi block. Keeps the harness free of SECURITY warnings.
            export ADMIN_TOKEN USER1_TOKEN USER2_TOKEN
            (umask 077; cat > "$AUTH_FILE" <<'EOF'
method: bearer
location: header
key_name: Authorization
roles:
  admin:
    token: "${ADMIN_TOKEN}"
  user1:
    token: "${USER1_TOKEN}"
  user2:
    token: "${USER2_TOKEN}"
  anonymous:
    token: ""
  no_header:
    no_auth: true
EOF
            )
        elif [ "$auth_method" = "api_key" ]; then
            log_info "Using static API keys..."
            (umask 077; cat > "$AUTH_FILE" <<EOF
method: api_key
location: header
key_name: X-API-Key
roles:
  admin:
    api_key: "admin-api-key-12345"
  user1:
    api_key: "user1-api-key-67890"
  user2:
    api_key: "user2-api-key-abcde"
  anonymous:
    api_key: ""
  no_header:
    no_auth: true
EOF
            )
        elif [ "$auth_method" = "basic" ]; then
            log_info "Using basic auth credentials..."
            (umask 077; cat > "$AUTH_FILE" <<EOF
method: basic
roles:
  admin:
    username: "admin"
    password: "admin123"
  user1:
    username: "user1"
    password: "user1pass"
  user2:
    username: "user2"
    password: "user2pass"
  anonymous:
    username: ""
    password: ""
  empty_basic:
    credentials: ""
  no_header:
    no_auth: true
EOF
            )
        elif [ "$auth_method" = "cookie" ]; then
            log_info "Using cookie session IDs..."
            (umask 077; cat > "$AUTH_FILE" <<EOF
method: cookie
cookie_name: session_id
roles:
  admin:
    cookie: "admin-session-xyz789"
  user1:
    cookie: "user1-session-abc123"
  user2:
    cookie: "user2-session-def456"
  anonymous:
    cookie: ""
  no_header:
    no_auth: true
EOF
            )
        fi

        RESULT_FILE="${OUTPUT_DIR}/vulnerable-api-${target_suffix}-results.json"
        run_hadrian "$target_name" test rest \
            --api "$VULN_API_SPEC" \
            --roles "${SCRIPT_DIR}/vulnerable-api/roles.yaml" \
            --auth "$AUTH_FILE" \
            --template-dir "${SCRIPT_DIR}/vulnerable-api/templates/owasp" \
            --output json \
            --output-file "$RESULT_FILE" \
            $VERBOSE

        set_findings "$target_name" "$(extract_finding_count "$RESULT_FILE")"
        log_ok "vulnerable-api (${auth_label}): $(get_findings "$target_name") findings in $(get_duration "$target_name")s"
    done
fi

# ==== Test: dvga (GraphQL) ====
if echo "$TARGETS" | grep -q "dvga"; then
    log_header "Target 2: dvga (GraphQL)"

    if [ "$DO_START" = true ]; then
        if ! command -v docker >/dev/null 2>&1; then
            log_warn "Docker not available, skipping dvga"
            set_status "dvga" "SKIP"
        else
            docker rm -f hadrian-dvga 2>/dev/null || true
            log_info "Starting dvga container on port $DVGA_PORT..."
            docker run -d -p "${DVGA_PORT}:5013" -e WEB_HOST=0.0.0.0 --name hadrian-dvga dolevf/dvga:latest 2>/dev/null || {
                log_warn "Failed to start dvga container (image may not be pulled)"
                log_info "Pull with: docker pull dolevf/dvga:latest"
                set_status "dvga" "SKIP"
            }

            if [ "$(get_status dvga)" != "SKIP" ]; then
                wait_for_http "http://localhost:${DVGA_PORT}/" "dvga" 60 || {
                    log_warn "dvga container logs:"
                    docker logs hadrian-dvga 2>&1 | tail -20
                    set_status "dvga" "SKIP"
                    log_warn "Skipping dvga tests"
                }
            fi
        fi
    fi

    if [ "$(get_status dvga)" != "SKIP" ]; then
        DVGA_ENDPOINT="http://localhost:${DVGA_PORT}/graphql"

        # ---- Setup: Acquire auth tokens for BOLA testing ----
        log_info "Setting up dvga auth tokens..."

        dvga_get_token() {
            local username="$1"
            local password="$2"
            local result
            result=$(curl -sf -X POST "$DVGA_ENDPOINT" \
                -H "Content-Type: application/json" \
                --data-raw "{\"query\":\"mutation { login(username: \\\"$username\\\", password: \\\"$password\\\") { accessToken } }\"}" 2>/dev/null)
            echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['login']['accessToken'])" 2>/dev/null || echo ""
        }

        DVGA_ADMIN_TOKEN=""
        for pass in "changeme" "admin" "password" "admin123"; do
            DVGA_ADMIN_TOKEN=$(dvga_get_token "admin" "$pass")
            if [ -n "$DVGA_ADMIN_TOKEN" ]; then
                log_ok "dvga admin token acquired"
                break
            fi
        done

        DVGA_OPERATOR_TOKEN=""
        for pass in "changeme" "operator" "password"; do
            DVGA_OPERATOR_TOKEN=$(dvga_get_token "operator" "$pass")
            if [ -n "$DVGA_OPERATOR_TOKEN" ]; then
                log_ok "dvga operator token acquired"
                break
            fi
        done
        if [ -z "$DVGA_OPERATOR_TOKEN" ]; then
            DVGA_OPERATOR_TOKEN="$DVGA_ADMIN_TOKEN"
            log_info "operator token unavailable, using admin token"
        fi

        if [ -z "$DVGA_ADMIN_TOKEN" ]; then
            log_warn "Failed to acquire dvga tokens, running without auth"
        else
            log_info "Creating dvga test data (pastes for BOLA)..."
            curl -sf -X POST "$DVGA_ENDPOINT" \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer $DVGA_ADMIN_TOKEN" \
                -d '{"query": "mutation { createPaste(title: \"Admin Confidential\", content: \"Secret admin data - DO NOT ACCESS\", public: false) { paste { id } } }"}' >/dev/null 2>&1 && \
                log_ok "Created admin private paste" || log_warn "Failed to create admin paste"
            curl -sf -X POST "$DVGA_ENDPOINT" \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer $DVGA_ADMIN_TOKEN" \
                -d '{"query": "mutation { createPaste(title: \"Victim PII\", content: \"SSN: 123-45-6789, Credit Card: 4111-1111-1111-1111\", public: false) { paste { id } } }"}' >/dev/null 2>&1 && \
                log_ok "Created victim PII paste" || log_warn "Failed to create victim paste"

            DVGA_AUTH_FILE="${OUTPUT_DIR}/dvga-auth.yaml"
            # Emit ${VAR} env-var refs (single-quoted heredoc) rather than
            # inline JWTs so hadrian's expandEnvSafe resolves them at load and
            # detectHardcodedSecret does not flag them — same pattern as the
            # crapi block. Keeps the harness free of SECURITY warnings.
            export DVGA_ADMIN_TOKEN DVGA_OPERATOR_TOKEN
            (umask 077; cat > "$DVGA_AUTH_FILE" <<'EOF'
method: bearer
location: header
key_name: Authorization
roles:
  admin:
    token: "${DVGA_ADMIN_TOKEN}"
  operator:
    token: "${DVGA_OPERATOR_TOKEN}"
  attacker:
    token: "${DVGA_OPERATOR_TOKEN}"
  victim:
    token: "${DVGA_ADMIN_TOKEN}"
EOF
            )
            log_ok "dvga auth config written"
        fi

        # ---- Run tests ----
        RESULT_FILE="${OUTPUT_DIR}/dvga-results.json"

        DVGA_AUTH_FLAGS=""
        if [ -n "${DVGA_ADMIN_TOKEN:-}" ]; then
            DVGA_AUTH_FLAGS="--auth ${DVGA_AUTH_FILE} --roles ${SCRIPT_DIR}/dvga/dvga-roles.yaml"
        fi

        # shellcheck disable=SC2086
        run_hadrian "dvga" test graphql \
            --target "http://localhost:${DVGA_PORT}" \
            --schema "${SCRIPT_DIR}/dvga/schema.graphql" \
            --template-dir "${SCRIPT_DIR}/dvga/templates/owasp" \
            --skip-builtin-checks \
            --output json \
            --output-file "$RESULT_FILE" \
            $DVGA_AUTH_FLAGS \
            $VERBOSE

        set_findings "dvga" "$(extract_finding_count "$RESULT_FILE")"
        log_ok "dvga: $(get_findings dvga) findings in $(get_duration dvga)s"
    fi
fi

# ==== Test: grpc-server ====
if echo "$TARGETS" | grep -q "grpc"; then
    log_header "Target 3: grpc-server (gRPC)"

    if [ "$DO_START" = true ]; then
        pkill -f "grpc-server$" 2>/dev/null || true
        sleep 1

        log_info "Starting grpc-server on port $GRPC_PORT..."
        (cd "${SCRIPT_DIR}/grpc-server" && GRPC_PORT="${GRPC_PORT}" ./grpc-server) &
        LAST_PID=$!
        PIDS_TO_CLEANUP="$PIDS_TO_CLEANUP $LAST_PID"
        # gRPC servers may not respond to raw TCP probes; wait briefly then check process
        sleep 3
        if kill -0 "$LAST_PID" 2>/dev/null; then
            log_ok "grpc-server started (pid $LAST_PID)"
        else
            log_fail "grpc-server process died"
            set_status "grpc" "SKIP"
            log_warn "Skipping gRPC tests"
        fi
    fi

    if [ "$(get_status grpc)" != "SKIP" ]; then
        RESULT_FILE="${OUTPUT_DIR}/grpc-results.json"

        run_hadrian "grpc" test grpc \
            --target "localhost:${GRPC_PORT}" \
            --proto "${SCRIPT_DIR}/grpc-server/service.proto" \
            --plaintext \
            --roles "${SCRIPT_DIR}/grpc-server/roles.yaml" \
            --auth "${SCRIPT_DIR}/grpc-server/auth.yaml" \
            --template-dir "${SCRIPT_DIR}/grpc-server/templates/owasp" \
            --output json \
            --output-file "$RESULT_FILE" \
            $VERBOSE

        set_findings "grpc" "$(extract_finding_count "$RESULT_FILE")"
        log_ok "grpc: $(get_findings grpc) findings in $(get_duration grpc)s"
    fi
fi

# ==== Test: crapi ====
if echo "$TARGETS" | grep -q "crapi"; then
    log_header "Target 4: crapi (REST)"

    CRAPI_URL="http://localhost:${CRAPI_PORT}"

    if ! curl -s -o /dev/null -w "%{http_code}" "${CRAPI_URL}/identity/api/auth/login" 2>/dev/null | grep -qE "^[2-4]"; then
        log_warn "crapi not detected on port $CRAPI_PORT"
        log_info "To set up crapi:"
        log_info "  git clone https://github.com/OWASP/crAPI.git"
        log_info "  cd crAPI/deploy/docker && docker compose up -d"
        set_status "crapi" "SKIP"
    fi

    if [ "$(get_status crapi)" != "SKIP" ]; then
        # ---- Setup: Auto-create users and acquire tokens ----
        # Canonical user identities, signup, and login come from
        # crapi-helpers.sh (sourced at the top of this script). That file
        # is the single source of truth for credentials so this script and
        # test-llm-planner.sh can't drift.
        log_info "Setting up crapi test users and tokens..."

        if ! crapi_setup_users "$CRAPI_URL"; then
            log_fail "crapi user provisioning failed (see error above)"
            set_status "crapi" "ERROR"
        fi
    fi

    # Re-check status: skip the test phase if provisioning errored.
    if [ "$(get_status crapi)" != "SKIP" ] && [ "$(get_status crapi)" != "ERROR" ]; then
        log_ok "crapi users created/verified"

        CRAPI_ADMIN_TOKEN=$(crapi_login    "$CRAPI_URL" "$CRAPI_ADMIN_EMAIL"    "$CRAPI_PASSWORD")
        CRAPI_USER_TOKEN=$(crapi_login     "$CRAPI_URL" "$CRAPI_USER_EMAIL"     "$CRAPI_PASSWORD")
        CRAPI_USER2_TOKEN=$(crapi_login    "$CRAPI_URL" "$CRAPI_USER2_EMAIL"    "$CRAPI_PASSWORD")
        CRAPI_MECHANIC_TOKEN=$(crapi_login "$CRAPI_URL" "$CRAPI_MECHANIC_EMAIL" "$CRAPI_PASSWORD")

        # All four tokens must be acquired — admin and mechanic are used by
        # role-specific templates (BFLA admin-video-delete, mechanic
        # workflows). A missing token here would silently produce
        # `token: ""` in the auth file and degrade those tests to anonymous
        # requests. Fail loudly instead.
        if [ -z "$CRAPI_ADMIN_TOKEN" ] || [ -z "$CRAPI_USER_TOKEN" ] \
                || [ -z "$CRAPI_USER2_TOKEN" ] || [ -z "$CRAPI_MECHANIC_TOKEN" ]; then
            log_fail "Failed to acquire crapi tokens (admin/user1/user2/mechanic must all be non-empty)"
            set_status "crapi" "ERROR"
        else
            log_ok "crapi tokens acquired"

            # Upload test videos for BFLA/BOPLA tests
            log_info "Setting up crapi test videos..."
            TMP_VIDEO=$(mktemp "${TMPDIR:-/tmp}/hadrian_test_video.XXXXXXXXXX.mp4")
            echo "test video content for hadrian security testing" > "$TMP_VIDEO"

            for token in "$CRAPI_USER_TOKEN" "$CRAPI_USER2_TOKEN" "$CRAPI_MECHANIC_TOKEN"; do
                if [ -n "$token" ]; then
                    curl -sf -X POST "${CRAPI_URL}/identity/api/v2/user/videos" \
                        -H "Authorization: Bearer $token" \
                        -F "file=@$TMP_VIDEO" \
                        -F "videoName=hadrian_test_video" >/dev/null 2>&1 || true
                fi
            done
            rm -f "$TMP_VIDEO"
            log_ok "crapi test videos uploaded"

            CRAPI_AUTH_FILE="${OUTPUT_DIR}/crapi-auth.yaml"
            # See test-llm-planner.sh for the env-var-rather-than-inline-token
            # rationale. Same fix applies here.
            export CRAPI_ADMIN_TOKEN CRAPI_MECHANIC_TOKEN CRAPI_USER_TOKEN CRAPI_USER2_TOKEN
            (umask 077; cat > "$CRAPI_AUTH_FILE" <<'EOF'
method: bearer
location: header
key_name: Authorization
roles:
  admin:
    token: "${CRAPI_ADMIN_TOKEN}"
  mechanic:
    token: "${CRAPI_MECHANIC_TOKEN}"
  user:
    token: "${CRAPI_USER_TOKEN}"
  user2:
    token: "${CRAPI_USER2_TOKEN}"
  anonymous:
    token: ""
EOF
            )

            RESULT_FILE="${OUTPUT_DIR}/crapi-results.json"

            SPEC_CACHE_DIR="${SCRIPT_DIR}/.live-test-cache"
            if ! CRAPI_SPEC=$(crapi_resolve_spec \
                    "${SCRIPT_DIR}/crapi/crapi-openapi-spec.json" \
                    "$CRAPI_PORT" \
                    "$SPEC_CACHE_DIR"); then
                log_fail "Could not resolve crAPI OpenAPI spec"
                set_status "crapi" "ERROR"
            else
                run_hadrian "crapi" test rest \
                    --api "$CRAPI_SPEC" \
                    --roles "${SCRIPT_DIR}/crapi/roles.yaml" \
                    --auth "$CRAPI_AUTH_FILE" \
                    --template-dir "${SCRIPT_DIR}/crapi/templates/owasp" \
                    --output json \
                    --output-file "$RESULT_FILE" \
                    $VERBOSE

                set_findings "crapi" "$(extract_finding_count "$RESULT_FILE")"
                log_ok "crapi: $(get_findings crapi) findings in $(get_duration crapi)s"
            fi
        fi
    fi
fi

# ==== Test: crapi-planner ====
# Runs the LLM-assisted planner against crAPI. The crapi block always runs
# first when "crapi-planner" is in TARGETS (because the grep -q "crapi"
# gate matches the "crapi" substring of "crapi-planner"), so by the time
# this block executes, CRAPI_AUTH_FILE and CRAPI_SPEC have already been
# produced by that prior block — no additional signup, spec patching, or
# cleanup is needed here. Gated on LLM provider availability: OpenAI key
# wins, Anthropic key next, local ollama as fallback, otherwise SKIP cleanly.
#
# Note on the crapi-prefix substring match: the crapi block gate above
# uses `grep -q "crapi"`, which also matches "crapi-planner". That is
# intentional — the planner depends on the crapi block having produced
# CRAPI_AUTH_FILE and CRAPI_SPEC, so `--targets crapi-planner` implicitly
# runs the crapi block too. The STATUS[crapi]=="PASS" check below is the
# actual safety gate; the substring match is the desired pre-requisite
# coupling.
if echo "$TARGETS" | grep -q "crapi-planner"; then
    log_header "Target 5: crapi-planner (REST + LLM planner)"

    # Inherit crapi status — if crapi didn't produce CRAPI_AUTH_FILE /
    # CRAPI_SPEC (because crapi wasn't in TARGETS, or it SKIPPED, or it
    # ERRORED), we have nothing to plan against. SKIP rather than ERROR
    # because the operator's choice of TARGETS, not a code fault, is the
    # cause.
    if [ "$(get_status crapi)" != "PASS" ] \
            || [ -z "${CRAPI_AUTH_FILE:-}" ] || [ ! -f "${CRAPI_AUTH_FILE:-/nonexistent}" ] \
            || [ -z "${CRAPI_SPEC:-}" ]      || [ ! -f "${CRAPI_SPEC:-/nonexistent}" ]; then
        log_info "crapi-planner requires the crapi target to have run successfully first; skipping"
        set_status "crapi-planner" "SKIP"
    else
        PLANNER_PROVIDER=$(detect_planner_provider)
        if [ -z "$PLANNER_PROVIDER" ]; then
            log_info "no LLM provider available (set OPENAI_API_KEY, ANTHROPIC_API_KEY, or run ollama), skipping crapi-planner"
            set_status "crapi-planner" "SKIP"
        else
            log_info "Using LLM provider: ${PLANNER_PROVIDER}"
            CRAPI_PLANNER_RESULT_FILE="${OUTPUT_DIR}/crapi-planner-${PLANNER_PROVIDER}-results.json"
            run_hadrian "crapi-planner" test rest \
                --api "$CRAPI_SPEC" \
                --roles "${SCRIPT_DIR}/crapi/roles.yaml" \
                --auth "$CRAPI_AUTH_FILE" \
                --template-dir "${SCRIPT_DIR}/crapi/templates/owasp" \
                --planner --planner-provider "$PLANNER_PROVIDER" \
                --output json \
                --output-file "$CRAPI_PLANNER_RESULT_FILE" \
                $VERBOSE

            set_findings "crapi-planner" "$(extract_finding_count "$CRAPI_PLANNER_RESULT_FILE")"
            log_ok "crapi-planner: $(get_findings crapi-planner) findings in $(get_duration crapi-planner)s"
        fi
    fi
fi

# ==== Summary ====
log_header "Test Summary"

echo ""
printf "${BOLD}%-25s %-10s %-12s %-10s${NC}\n" "TARGET" "STATUS" "FINDINGS" "DURATION"
printf "%-25s %-10s %-12s %-10s\n" "-------------------------" "----------" "------------" "----------"

TOTAL_FINDINGS=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

ALL_TARGETS=""
if echo "$TARGETS" | grep -q "vulnerable-api"; then
    ALL_TARGETS="vulnerable-api-bearer vulnerable-api-apikey vulnerable-api-basic vulnerable-api-cookie"
fi
for extra in dvga grpc crapi crapi-planner; do
    if echo "$TARGETS" | grep -q "${extra}"; then
        ALL_TARGETS="$ALL_TARGETS $extra"
    fi
done

for target in $ALL_TARGETS; do

    status="$(get_status "$target")"
    findings="$(get_findings "$target")"
    duration="$(get_duration "$target")"

    case "$status" in
        PASS)
            status_color="${GREEN}"
            TOTAL_PASS=$((TOTAL_PASS + 1))
            if [ "$findings" != "?" ]; then
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + findings))
            fi
            ;;
        ERROR)
            status_color="${RED}"
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
            ;;
        SKIP)
            status_color="${YELLOW}"
            findings="-"
            duration="-"
            TOTAL_SKIP=$((TOTAL_SKIP + 1))
            ;;
        *)
            status_color="${NC}"
            TOTAL_SKIP=$((TOTAL_SKIP + 1))
            ;;
    esac

    duration_str="${duration}s"
    if [ "$duration" = "-" ] || [ "$duration" = "0" ]; then
        duration_str="-"
    fi

    printf "${status_color}%-25s %-10s %-12s %-10s${NC}\n" "$target" "$status" "$findings" "$duration_str"
done

echo ""
echo -e "${BOLD}Total: ${TOTAL_PASS} passed, ${TOTAL_FAIL} failed, ${TOTAL_SKIP} skipped, ${TOTAL_FINDINGS} findings${NC}"
echo -e "Results saved to: ${OUTPUT_DIR}/"
echo ""

# Exit with failure if any target failed
if [ $TOTAL_FAIL -gt 0 ]; then
    exit 1
fi
