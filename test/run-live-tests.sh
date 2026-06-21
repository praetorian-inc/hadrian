#!/usr/bin/env bash
# =============================================================================
# run-live-tests.sh
#
# Runs Hadrian security tests against all four in-house vulnerable targets:
#   1. vulnerable-api          (REST  - Bearer/APIKey/Basic/Cookie auth)
#   2. vulnerable-graphql      (GraphQL - in-house vulnerable GraphQL target)
#   3. grpc-server             (gRPC  - vulnerable gRPC service)
#   4. vulnerable-rest-complex (REST  - multi-resource: customers/vehicles/mechanics/orders)
#
# Every target is a local Go binary — no container runtime is required, so the
# full suite runs in a fresh devcontainer (LAB-2750).
#
# !! CI SAFETY !!
#   `vulnerable-graphql` runs real OS command execution and arbitrary file
#   writes (as the invoking user) by design — Hadrian needs them live to detect
#   the RCE/path-traversal. Do NOT run this suite in CI on untrusted or
#   fork-triggered PRs: a job that executes it runs attacker-influenceable shell
#   on the runner. If you must wire it into CI, use an ephemeral, isolated,
#   trusted-PR-only runner with no secrets in the environment. Intended for
#   local/devcontainer use, not as a default CI gate. See test/README.md.
#
# Prerequisites:
#   - Run ./test/setup-live-targets.sh first (one-time build), or
#   - Go 1.21+ and a built hadrian binary (this script can build them).
#
# Usage:
#   ./test/run-live-tests.sh [options]
#
# Options:
#   --targets <list>      Comma-separated targets to test (default: all)
#                         Valid: vulnerable-api,vulnerable-graphql,grpc,vulnerable-rest-complex
#   --verbose             Enable verbose Hadrian output
#   --no-build            Skip building hadrian and target binaries
#   --no-start            Don't start/stop services (assume already running)
#   --output-dir <dir>    Directory for JSON results (default: test/.results)
#   --help                Show this help message
#
# Examples:
#   ./test/run-live-tests.sh                                  # Run all targets
#   ./test/run-live-tests.sh --targets vulnerable-api         # Just vulnerable-api
#   ./test/run-live-tests.sh --targets vulnerable-graphql,grpc # GraphQL + gRPC
#   ./test/run-live-tests.sh --verbose --no-build             # Verbose, skip build
# =============================================================================

set -euo pipefail

# ==== Configuration ====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HADRIAN_BIN="${HADRIAN_BIN:-${REPO_ROOT}/hadrian}"
OUTPUT_DIR="${SCRIPT_DIR}/.results"
CONFIG_FILE="${SCRIPT_DIR}/.live-test-config"

# Load config from setup script if it exists (port assignments).
# The regex requires every value to be double-quoted so `source` can't
# word-split a path containing whitespace into a command. Quoted form is
# what setup-live-targets.sh writes; an old/loose config will be rejected
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
VULN_GRAPHQL_DEFAULT_PORT=5013
GRPC_DEFAULT_PORT=50051
VULN_REST_COMPLEX_DEFAULT_PORT=8888

# Target ports (env vars > config file > defaults)
VULN_API_PORT="${VULN_API_PORT:-$VULN_API_DEFAULT_PORT}"
VULN_GRAPHQL_PORT="${VULN_GRAPHQL_PORT:-$VULN_GRAPHQL_DEFAULT_PORT}"
GRPC_PORT="${GRPC_PORT:-$GRPC_DEFAULT_PORT}"
VULN_REST_COMPLEX_PORT="${VULN_REST_COMPLEX_PORT:-$VULN_REST_COMPLEX_DEFAULT_PORT}"

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
TARGETS="vulnerable-api,vulnerable-graphql,grpc,vulnerable-rest-complex"
VERBOSE=""
DO_BUILD=true
DO_START=true

# Track results per target using associative arrays
declare -A STATUS FINDINGS DURATION
for _t in vulnerable-api-bearer vulnerable-api-apikey vulnerable-api-basic vulnerable-api-cookie vulnerable-graphql grpc vulnerable-rest-complex; do
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

# finding_floor — minimum findings each target must produce. This is the
# detection-regression guard for AC2 ("detection baseline preserved"): a PASS
# is downgraded to FAIL if a target silently drops below its floor, so a
# regression to ~0 findings cannot pass on exit-code alone. Values track the
# documented baseline in test/README.md; raise them only when the baseline
# genuinely increases.
finding_floor() {
    case "$1" in
        vulnerable-api-*)        echo 61 ;;
        vulnerable-graphql)      echo 10 ;;
        grpc)                    echo 8  ;;
        vulnerable-rest-complex) echo 25 ;;
        *)                       echo 1  ;;
    esac
}

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

    if echo "$TARGETS" | grep -q "vulnerable-graphql"; then
        log_info "Building vulnerable-graphql..."
        (cd "${SCRIPT_DIR}/vulnerable-graphql" && go build -o vulnerable-graphql .)
        log_ok "vulnerable-graphql built"
    fi

    if echo "$TARGETS" | grep -q "vulnerable-rest-complex"; then
        log_info "Building vulnerable-rest-complex..."
        (cd "${SCRIPT_DIR}/vulnerable-rest-complex" && go build -o vulnerable-rest-complex .)
        log_ok "vulnerable-rest-complex built"
    fi

    if echo "$TARGETS" | grep -q "grpc"; then
        log_info "Building grpc-server..."
        (cd "${SCRIPT_DIR}/grpc-server" && {
            # Check for actual generated files, not just directory existence
            # (handles a pb/ left empty by a previously failed run). Generate
            # non-interactively — setup-live-targets.sh is the documented
            # prerequisite, so a missing pb/ here means the operator ran the
            # runner directly; do NOT prompt (a `read` would hang CI).
            if [ ! -f pb/service.pb.go ] || [ ! -f pb/service_grpc.pb.go ]; then
                if command -v protoc >/dev/null 2>&1; then
                    log_info "Generating protobuf code (run ./test/setup-live-targets.sh to pre-generate)..."
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
                    log_fail "grpc-server needs generated protobuf code and protoc is not installed."
                    log_fail "Run ./test/setup-live-targets.sh first, or 'make proto' in test/grpc-server/."
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
            pkill -f "/vulnerable-api$" 2>/dev/null || true
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

            (umask 077; cat > "$AUTH_FILE" <<EOF
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

# ==== Test: vulnerable-graphql (GraphQL) ====
if echo "$TARGETS" | grep -q "vulnerable-graphql"; then
    log_header "Target 2: vulnerable-graphql (GraphQL)"

    if [ "$DO_START" = true ]; then
        pkill -f "/vulnerable-graphql$" 2>/dev/null || true
        sleep 1

        log_info "Starting vulnerable-graphql on port $VULN_GRAPHQL_PORT..."
        (cd "${SCRIPT_DIR}/vulnerable-graphql" && PORT="${VULN_GRAPHQL_PORT}" ./vulnerable-graphql) &
        LAST_PID=$!
        PIDS_TO_CLEANUP="$PIDS_TO_CLEANUP $LAST_PID"
        wait_for_http "http://localhost:${VULN_GRAPHQL_PORT}/health" "vulnerable-graphql" 15 || {
            set_status "vulnerable-graphql" "SKIP"
            log_warn "Skipping vulnerable-graphql tests"
        }
    fi

    if [ "$(get_status vulnerable-graphql)" != "SKIP" ]; then
        GRAPHQL_ENDPOINT="http://localhost:${VULN_GRAPHQL_PORT}/graphql"

        # ---- Acquire auth tokens via the login mutation ----
        # Seed users (admin/user1/user2) and their pastes are created at
        # server startup, so unlike the old containerized flow we don't need
        # to provision data over the wire — just log in.
        log_info "Acquiring vulnerable-graphql JWT tokens..."

        graphql_get_token() {
            local username="$1"
            local password="$2"
            curl -sf -X POST "$GRAPHQL_ENDPOINT" \
                -H "Content-Type: application/json" \
                --data-raw "{\"query\":\"mutation { login(username: \\\"$username\\\", password: \\\"$password\\\") { accessToken } }\"}" 2>/dev/null \
                | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['login']['accessToken'])" 2>/dev/null || echo ""
        }

        GRAPHQL_ADMIN_TOKEN=$(graphql_get_token "admin" "admin123")
        GRAPHQL_USER1_TOKEN=$(graphql_get_token "user1" "user1pass")
        GRAPHQL_USER2_TOKEN=$(graphql_get_token "user2" "user2pass")

        GRAPHQL_AUTH_FLAGS=""
        if [ -n "$GRAPHQL_ADMIN_TOKEN" ] && [ -n "$GRAPHQL_USER1_TOKEN" ] && [ -n "$GRAPHQL_USER2_TOKEN" ]; then
            log_ok "vulnerable-graphql tokens acquired (admin, user1, user2)"
            GRAPHQL_AUTH_FILE="${OUTPUT_DIR}/vulnerable-graphql-auth.yaml"
            # attacker -> user2 (lower priv), victim -> user1 (higher priv).
            (umask 077; cat > "$GRAPHQL_AUTH_FILE" <<EOF
method: bearer
location: header
key_name: Authorization
roles:
  admin:
    token: "${GRAPHQL_ADMIN_TOKEN}"
  user1:
    token: "${GRAPHQL_USER1_TOKEN}"
  user2:
    token: "${GRAPHQL_USER2_TOKEN}"
  attacker:
    token: "${GRAPHQL_USER2_TOKEN}"
  victim:
    token: "${GRAPHQL_USER1_TOKEN}"
EOF
            )
            GRAPHQL_AUTH_FLAGS="--auth ${GRAPHQL_AUTH_FILE} --roles ${SCRIPT_DIR}/vulnerable-graphql/roles.yaml"
        else
            log_warn "Failed to acquire vulnerable-graphql tokens, running without auth"
        fi

        # ---- Run tests ----
        # NOTE: unlike the old containerized flow we do NOT pass --skip-builtin-checks.
        # The in-house target deliberately enables introspection and applies
        # no depth/alias limits, so hadrian's built-in GraphQL checks
        # (introspection, alias-based DoS, field duplication) fire alongside
        # the template-driven BOLA/BFLA/data-exposure tests (LAB-2750).
        RESULT_FILE="${OUTPUT_DIR}/vulnerable-graphql-results.json"

        # shellcheck disable=SC2086
        run_hadrian "vulnerable-graphql" test graphql \
            --target "http://localhost:${VULN_GRAPHQL_PORT}" \
            --schema "${SCRIPT_DIR}/vulnerable-graphql/schema.graphql" \
            --template-dir "${SCRIPT_DIR}/vulnerable-graphql/templates/owasp" \
            --output json \
            --output-file "$RESULT_FILE" \
            $GRAPHQL_AUTH_FLAGS \
            $VERBOSE

        set_findings "vulnerable-graphql" "$(extract_finding_count "$RESULT_FILE")"
        log_ok "vulnerable-graphql: $(get_findings vulnerable-graphql) findings in $(get_duration vulnerable-graphql)s"
    fi
fi

# ==== Test: grpc-server ====
if echo "$TARGETS" | grep -q "grpc"; then
    log_header "Target 3: grpc-server (gRPC)"

    if [ "$DO_START" = true ]; then
        pkill -f "/grpc-server$" 2>/dev/null || true
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

# ==== Test: vulnerable-rest-complex ====
if echo "$TARGETS" | grep -q "vulnerable-rest-complex"; then
    log_header "Target 4: vulnerable-rest-complex (REST)"

    if [ "$DO_START" = true ]; then
        pkill -f "/vulnerable-rest-complex$" 2>/dev/null || true
        sleep 1

        log_info "Starting vulnerable-rest-complex on port $VULN_REST_COMPLEX_PORT..."
        (cd "${SCRIPT_DIR}/vulnerable-rest-complex" && PORT="${VULN_REST_COMPLEX_PORT}" ./vulnerable-rest-complex) &
        LAST_PID=$!
        PIDS_TO_CLEANUP="$PIDS_TO_CLEANUP $LAST_PID"
        wait_for_http "http://localhost:${VULN_REST_COMPLEX_PORT}/health" "vulnerable-rest-complex" 15 || {
            set_status "vulnerable-rest-complex" "SKIP"
            log_warn "Skipping vulnerable-rest-complex tests"
        }
    fi

    if [ "$(get_status vulnerable-rest-complex)" != "SKIP" ]; then
        REST_COMPLEX_URL="http://localhost:${VULN_REST_COMPLEX_PORT}"

        # Reset data to a known seeded state before testing.
        curl -sf -X POST "${REST_COMPLEX_URL}/api/reset" >/dev/null 2>&1 || true

        # ---- Acquire tokens via login ----
        log_info "Acquiring vulnerable-rest-complex JWT tokens..."

        rest_complex_get_token() {
            local username="$1"
            local password="$2"
            curl -sf -X POST "${REST_COMPLEX_URL}/api/auth/login" \
                -H "Content-Type: application/json" \
                --data-binary @- <<EOF | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])" 2>/dev/null || echo ""
{"username":"${username}","password":"${password}"}
EOF
        }

        RC_ADMIN_TOKEN=$(rest_complex_get_token "admin" "admin123")
        RC_USER1_TOKEN=$(rest_complex_get_token "user1" "user1pass")
        RC_USER2_TOKEN=$(rest_complex_get_token "user2" "user2pass")
        RC_MECHANIC_TOKEN=$(rest_complex_get_token "mechanic1" "mech1pass")

        # All four tokens must be acquired — admin and mechanic drive the
        # role-specific BFLA templates. A missing token would silently
        # degrade those tests to anonymous requests, so fail loudly.
        if [ -z "$RC_ADMIN_TOKEN" ] || [ -z "$RC_USER1_TOKEN" ] \
                || [ -z "$RC_USER2_TOKEN" ] || [ -z "$RC_MECHANIC_TOKEN" ]; then
            log_fail "Failed to acquire vulnerable-rest-complex tokens (admin/user1/user2/mechanic must all be non-empty)"
            set_status "vulnerable-rest-complex" "ERROR"
        else
            log_ok "vulnerable-rest-complex tokens acquired"

            REST_COMPLEX_AUTH_FILE="${OUTPUT_DIR}/vulnerable-rest-complex-auth.yaml"
            (umask 077; cat > "$REST_COMPLEX_AUTH_FILE" <<EOF
method: bearer
location: header
key_name: Authorization
roles:
  admin:
    token: "${RC_ADMIN_TOKEN}"
  mechanic:
    token: "${RC_MECHANIC_TOKEN}"
  user1:
    token: "${RC_USER1_TOKEN}"
  user2:
    token: "${RC_USER2_TOKEN}"
  anonymous:
    token: ""
  no_header:
    no_auth: true
EOF
            )

            # If using a non-default port, patch the OpenAPI spec's server URL.
            REST_COMPLEX_SPEC="${SCRIPT_DIR}/vulnerable-rest-complex/openapi.yaml"
            if [ "$VULN_REST_COMPLEX_PORT" != "$VULN_REST_COMPLEX_DEFAULT_PORT" ]; then
                REST_COMPLEX_SPEC="${OUTPUT_DIR}/vulnerable-rest-complex-openapi.yaml"
                sed "s|http://localhost:${VULN_REST_COMPLEX_DEFAULT_PORT}|http://localhost:${VULN_REST_COMPLEX_PORT}|g" \
                    "${SCRIPT_DIR}/vulnerable-rest-complex/openapi.yaml" > "$REST_COMPLEX_SPEC"
                log_info "Patched OpenAPI spec to use port $VULN_REST_COMPLEX_PORT"
            fi

            RESULT_FILE="${OUTPUT_DIR}/vulnerable-rest-complex-results.json"
            run_hadrian "vulnerable-rest-complex" test rest \
                --api "$REST_COMPLEX_SPEC" \
                --roles "${SCRIPT_DIR}/vulnerable-rest-complex/roles.yaml" \
                --auth "$REST_COMPLEX_AUTH_FILE" \
                --template-dir "${SCRIPT_DIR}/vulnerable-rest-complex/templates/owasp" \
                --output json \
                --output-file "$RESULT_FILE" \
                $VERBOSE

            set_findings "vulnerable-rest-complex" "$(extract_finding_count "$RESULT_FILE")"
            log_ok "vulnerable-rest-complex: $(get_findings vulnerable-rest-complex) findings in $(get_duration vulnerable-rest-complex)s"
        fi
    fi
fi

# ==== Summary ====
log_header "Test Summary"

echo ""
printf "${BOLD}%-27s %-10s %-12s %-10s${NC}\n" "TARGET" "STATUS" "FINDINGS" "DURATION"
printf "%-27s %-10s %-12s %-10s\n" "---------------------------" "----------" "------------" "----------"

TOTAL_FINDINGS=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

ALL_TARGETS=""
if echo "$TARGETS" | grep -q "vulnerable-api"; then
    ALL_TARGETS="vulnerable-api-bearer vulnerable-api-apikey vulnerable-api-basic vulnerable-api-cookie"
fi
if echo "$TARGETS" | grep -q "vulnerable-graphql"; then
    ALL_TARGETS="$ALL_TARGETS vulnerable-graphql"
fi
if echo "$TARGETS" | grep -q "grpc"; then
    ALL_TARGETS="$ALL_TARGETS grpc"
fi
if echo "$TARGETS" | grep -q "vulnerable-rest-complex"; then
    ALL_TARGETS="$ALL_TARGETS vulnerable-rest-complex"
fi

for target in $ALL_TARGETS; do

    status="$(get_status "$target")"
    findings="$(get_findings "$target")"
    duration="$(get_duration "$target")"

    case "$status" in
        PASS)
            floor="$(finding_floor "$target")"
            if [ "$findings" != "?" ] && [ "$findings" -lt "$floor" ]; then
                # Detection regressed below the documented baseline (AC2).
                status="FAIL"
                status_color="${RED}"
                TOTAL_FAIL=$((TOTAL_FAIL + 1))
                echo -e "${RED}[REGRESSION] ${target}: ${findings} findings is below the baseline floor of ${floor} — detection degraded.${NC}" >&2
            else
                status_color="${GREEN}"
                TOTAL_PASS=$((TOTAL_PASS + 1))
                if [ "$findings" != "?" ]; then
                    TOTAL_FINDINGS=$((TOTAL_FINDINGS + findings))
                fi
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

    printf "${status_color}%-27s %-10s %-12s %-10s${NC}\n" "$target" "$status" "$findings" "$duration_str"
done

echo ""
echo -e "${BOLD}Total: ${TOTAL_PASS} passed, ${TOTAL_FAIL} failed, ${TOTAL_SKIP} skipped, ${TOTAL_FINDINGS} findings${NC}"
echo -e "Results saved to: ${OUTPUT_DIR}/"
echo ""

# Exit with failure if any target failed
if [ $TOTAL_FAIL -gt 0 ]; then
    exit 1
fi
