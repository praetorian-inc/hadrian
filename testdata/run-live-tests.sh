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
#   - Go 1.21+ installed
#   - Docker installed (for dvga)
#   - hadrian binary built (or will be built automatically)
#
# Usage:
#   ./testdata/run-live-tests.sh [options]
#
# Options:
#   --targets <list>      Comma-separated targets to test (default: all)
#                         Valid: vulnerable-api,dvga,grpc,crapi
#   --verbose             Enable verbose Hadrian output
#   --no-build            Skip building hadrian and target binaries
#   --no-start            Don't start/stop services (assume already running)
#   --output-dir <dir>    Directory for JSON results (default: testdata/.results)
#   --help                Show this help message
#
# Examples:
#   ./testdata/run-live-tests.sh                          # Run all targets
#   ./testdata/run-live-tests.sh --targets vulnerable-api # Just vulnerable-api
#   ./testdata/run-live-tests.sh --targets dvga,grpc      # GraphQL + gRPC
#   ./testdata/run-live-tests.sh --verbose --no-build     # Verbose, skip build
# =============================================================================

set -euo pipefail

# ==== Configuration ====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HADRIAN_BIN="${HADRIAN_BIN:-${REPO_ROOT}/hadrian}"
OUTPUT_DIR="${SCRIPT_DIR}/.results"

# Target ports
VULN_API_PORT="${VULN_API_PORT:-8080}"
DVGA_PORT="${DVGA_PORT:-5013}"
GRPC_PORT="${GRPC_PORT:-50051}"
CRAPI_PORT="${CRAPI_PORT:-8888}"

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

# Track results per target (plain variables, no associative arrays)
STATUS_vulnerable_api="NOT_RUN"
STATUS_dvga="NOT_RUN"
STATUS_grpc="NOT_RUN"
STATUS_crapi="NOT_RUN"
FINDINGS_vulnerable_api="0"
FINDINGS_dvga="0"
FINDINGS_grpc="0"
FINDINGS_crapi="0"
DURATION_vulnerable_api="0"
DURATION_dvga="0"
DURATION_grpc="0"
DURATION_crapi="0"

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

# ==== Result helpers (no associative arrays) ====
set_status() { eval "STATUS_$(echo "$1" | tr '-' '_')=$2"; }
get_status() { eval "echo \${STATUS_$(echo "$1" | tr '-' '_')}"; }
set_findings() { eval "FINDINGS_$(echo "$1" | tr '-' '_')=$2"; }
get_findings() { eval "echo \${FINDINGS_$(echo "$1" | tr '-' '_')}"; }
set_duration() { eval "DURATION_$(echo "$1" | tr '-' '_')=$2"; }
get_duration() { eval "echo \${DURATION_$(echo "$1" | tr '-' '_')}"; }

# ==== Helper functions ====

log_header() {
    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

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
        python3 -c "import json,sys; d=json.load(open('$json_file')); print(d.get('stats',{}).get('findings',len(d.get('findings',[]))))" 2>/dev/null || echo "?"
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
        (cd "${SCRIPT_DIR}/grpc-server" && go build -o grpc-server .)
        log_ok "grpc-server built"
    fi
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# ==== Test: vulnerable-api ====
if echo "$TARGETS" | grep -q "vulnerable-api"; then
    log_header "Target 1: vulnerable-api (REST)"

    if [ "$DO_START" = true ]; then
        # Kill any existing instance
        pkill -f "vulnerable-api$" 2>/dev/null || true
        sleep 1

        log_info "Starting vulnerable-api on port $VULN_API_PORT..."
        (cd "${SCRIPT_DIR}/vulnerable-api" && PORT="${VULN_API_PORT}" ./vulnerable-api) &
        PIDS_TO_CLEANUP="$PIDS_TO_CLEANUP $!"
        wait_for_http "http://localhost:${VULN_API_PORT}/health" "vulnerable-api" 15 || {
            set_status "vulnerable-api" "SKIP"
            log_warn "Skipping vulnerable-api tests"
        }
    fi

    if [ "$(get_status vulnerable-api)" != "SKIP" ]; then
        log_info "Acquiring JWT tokens..."
        ADMIN_TOKEN=$(curl -sf -X POST "http://localhost:${VULN_API_PORT}/api/auth/login" \
            -H "Content-Type: application/json" \
            -d '{"username":"admin","password":"admin123"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])" 2>/dev/null || echo "")
        USER1_TOKEN=$(curl -sf -X POST "http://localhost:${VULN_API_PORT}/api/auth/login" \
            -H "Content-Type: application/json" \
            -d '{"username":"user1","password":"user1pass"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])" 2>/dev/null || echo "")
        USER2_TOKEN=$(curl -sf -X POST "http://localhost:${VULN_API_PORT}/api/auth/login" \
            -H "Content-Type: application/json" \
            -d '{"username":"user2","password":"user2pass"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])" 2>/dev/null || echo "")

        if [ -z "$ADMIN_TOKEN" ] || [ -z "$USER1_TOKEN" ] || [ -z "$USER2_TOKEN" ]; then
            log_fail "Failed to acquire JWT tokens"
            set_status "vulnerable-api" "ERROR"
        else
            log_ok "Tokens acquired for admin, user1, user2"

            AUTH_FILE="${OUTPUT_DIR}/vuln-api-auth.yaml"
            cat > "$AUTH_FILE" <<EOF
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
EOF

            RESULT_FILE="${OUTPUT_DIR}/vulnerable-api-results.json"
            run_hadrian "vulnerable-api" test rest \
                --api "${SCRIPT_DIR}/vulnerable-api/openapi.yaml" \
                --roles "${SCRIPT_DIR}/vulnerable-api/roles.yaml" \
                --auth "$AUTH_FILE" \
                --template-dir "${SCRIPT_DIR}/vulnerable-api/templates/owasp" \
                --allow-internal \
                --output json \
                --output-file "$RESULT_FILE" \
                --concurrency 1 \
                $VERBOSE

            set_findings "vulnerable-api" "$(extract_finding_count "$RESULT_FILE")"
            log_ok "vulnerable-api: $(get_findings vulnerable-api) findings in $(get_duration vulnerable-api)s"
        fi
    fi
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
            docker run -d -p "${DVGA_PORT}:5013" --name hadrian-dvga dolevf/dvga:latest 2>/dev/null || {
                log_warn "Failed to start dvga container (image may not be pulled)"
                log_info "Pull with: docker pull dolevf/dvga:latest"
                set_status "dvga" "SKIP"
            }

            if [ "$(get_status dvga)" != "SKIP" ]; then
                wait_for_http "http://localhost:${DVGA_PORT}/graphql" "dvga" 30 || {
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
            cat > "$DVGA_AUTH_FILE" <<EOF
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
            --templates "${SCRIPT_DIR}/dvga/templates/owasp" \
            --skip-builtin-checks \
            --allow-internal \
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
            --allow-internal \
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

    if ! curl -sf -o /dev/null "${CRAPI_URL}/identity/api/auth/signup" 2>/dev/null; then
        log_warn "crapi not detected on port $CRAPI_PORT"
        log_info "To set up crapi:"
        log_info "  git clone https://github.com/OWASP/crAPI.git"
        log_info "  cd crAPI/deploy/docker && docker-compose up -d"
        set_status "crapi" "SKIP"
    fi

    if [ "$(get_status crapi)" != "SKIP" ]; then
        # ---- Setup: Auto-create users and acquire tokens ----
        log_info "Setting up crapi test users and tokens..."

        crapi_signup() {
            local email="$1" name="$2" number="$3" password="$4"
            curl -sf -X POST "${CRAPI_URL}/identity/api/auth/signup" \
                -H "Content-Type: application/json" \
                -d "{\"email\":\"$email\",\"name\":\"$name\",\"number\":\"$number\",\"password\":\"$password\"}" 2>/dev/null || true
        }

        crapi_login() {
            local email="$1" password="$2"
            curl -sf -X POST "${CRAPI_URL}/identity/api/auth/login" \
                -H "Content-Type: application/json" \
                -d "{\"email\":\"$email\",\"password\":\"$password\"}" 2>/dev/null | \
                python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo ""
        }

        crapi_mechanic_signup() {
            local email="$1" name="$2" number="$3" password="$4" code="$5"
            curl -sf -X POST "${CRAPI_URL}/workshop/api/mechanic/signup" \
                -H "Content-Type: application/json" \
                -d "{\"email\":\"$email\",\"name\":\"$name\",\"number\":\"$number\",\"password\":\"$password\",\"mechanic_code\":\"$code\"}" 2>/dev/null || true
        }

        CRAPI_ADMIN_EMAIL="hadrian-admin@test.com"
        CRAPI_USER_EMAIL="hadrian-user1@test.com"
        CRAPI_USER2_EMAIL="hadrian-user2@test.com"
        CRAPI_MECHANIC_EMAIL="hadrian-mechanic@test.com"
        CRAPI_PASSWORD="HadrianTest123!"

        crapi_signup "$CRAPI_ADMIN_EMAIL" "Hadrian Admin" "1111111111" "$CRAPI_PASSWORD"
        crapi_signup "$CRAPI_USER_EMAIL" "Hadrian User1" "2222222222" "$CRAPI_PASSWORD"
        crapi_signup "$CRAPI_USER2_EMAIL" "Hadrian User2" "3333333333" "$CRAPI_PASSWORD"
        crapi_mechanic_signup "$CRAPI_MECHANIC_EMAIL" "Hadrian Mechanic" "4444444444" "$CRAPI_PASSWORD" "TRAC_MECH1"
        log_ok "crapi users created/verified"

        CRAPI_ADMIN_TOKEN=$(crapi_login "$CRAPI_ADMIN_EMAIL" "$CRAPI_PASSWORD")
        CRAPI_USER_TOKEN=$(crapi_login "$CRAPI_USER_EMAIL" "$CRAPI_PASSWORD")
        CRAPI_USER2_TOKEN=$(crapi_login "$CRAPI_USER2_EMAIL" "$CRAPI_PASSWORD")
        CRAPI_MECHANIC_TOKEN=$(crapi_login "$CRAPI_MECHANIC_EMAIL" "$CRAPI_PASSWORD")

        if [ -z "$CRAPI_USER_TOKEN" ] || [ -z "$CRAPI_USER2_TOKEN" ]; then
            log_fail "Failed to acquire crapi tokens"
            set_status "crapi" "ERROR"
        else
            log_ok "crapi tokens acquired"

            # Upload test videos for BFLA/BOPLA tests
            log_info "Setting up crapi test videos..."
            TMP_VIDEO="/tmp/hadrian_test_video.mp4"
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
            cat > "$CRAPI_AUTH_FILE" <<EOF
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

            RESULT_FILE="${OUTPUT_DIR}/crapi-results.json"

            run_hadrian "crapi" test rest \
                --api "${SCRIPT_DIR}/crapi/crapi-openapi-spec.json" \
                --roles "${SCRIPT_DIR}/crapi/roles.yaml" \
                --auth "$CRAPI_AUTH_FILE" \
                --template-dir "${SCRIPT_DIR}/crapi/templates/owasp" \
                --allow-internal \
                --output json \
                --output-file "$RESULT_FILE" \
                $VERBOSE

            set_findings "crapi" "$(extract_finding_count "$RESULT_FILE")"
            log_ok "crapi: $(get_findings crapi) findings in $(get_duration crapi)s"
        fi
    fi
fi

# ==== Summary ====
log_header "Test Summary"

echo ""
printf "${BOLD}%-20s %-10s %-12s %-10s${NC}\n" "TARGET" "STATUS" "FINDINGS" "DURATION"
printf "%-20s %-10s %-12s %-10s\n" "--------------------" "----------" "------------" "----------"

TOTAL_FINDINGS=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

for target in vulnerable-api dvga grpc crapi; do
    if ! echo "$TARGETS" | grep -q "${target}"; then
        continue
    fi

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

    printf "${status_color}%-20s %-10s %-12s %-10s${NC}\n" "$target" "$status" "$findings" "$duration_str"
done

echo ""
echo -e "${BOLD}Total: ${TOTAL_PASS} passed, ${TOTAL_FAIL} failed, ${TOTAL_SKIP} skipped, ${TOTAL_FINDINGS} findings${NC}"
echo -e "Results saved to: ${OUTPUT_DIR}/"
echo ""

# Exit with failure if any target failed
if [ $TOTAL_FAIL -gt 0 ]; then
    exit 1
fi
