#!/usr/bin/env bash
# =============================================================================
# test-llm-planner.sh
#
# Tests LLM-assisted attack planner against crAPI.
# Verifies the planner generates a valid attack plan and executes it.
#
# Prerequisites:
#   - crAPI running on localhost:8888
#   - OPENAI_API_KEY or ANTHROPIC_API_KEY set
#   - hadrian binary built
#
# Usage:
#   ./test/test-llm-planner.sh [openai|anthropic|ollama]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HADRIAN_BIN="${HADRIAN_BIN:-${REPO_ROOT}/hadrian}"
OUTPUT_DIR="${SCRIPT_DIR}/.results"
CRAPI_PORT="${CRAPI_PORT:-8888}"
CRAPI_URL="http://localhost:${CRAPI_PORT}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

# Parse provider argument
PROVIDER="${1:-openai}"
case "$PROVIDER" in
    openai)
        [ -z "${OPENAI_API_KEY:-}" ] && { log_fail "OPENAI_API_KEY not set"; exit 1; }
        ;;
    anthropic)
        [ -z "${ANTHROPIC_API_KEY:-}" ] && { log_fail "ANTHROPIC_API_KEY not set"; exit 1; }
        ;;
    ollama)
        ;;
    *)
        echo "Usage: $0 [openai|anthropic|ollama]"
        exit 1
        ;;
esac

# Check prerequisites
if [ ! -f "$HADRIAN_BIN" ]; then
    log_info "Building hadrian..."
    (cd "$REPO_ROOT" && go build -o hadrian ./cmd/hadrian)
fi

if ! curl -sf -o /dev/null "$CRAPI_URL" 2>/dev/null; then
    log_fail "crAPI not running on $CRAPI_URL"
    exit 1
fi

# Setup crAPI tokens
log_info "Setting up crAPI tokens..."

crapi_login() {
    printf '{"email":"%s","password":"%s"}' "$1" "$2" | \
        curl -sf -X POST "${CRAPI_URL}/identity/api/auth/login" \
            -H "Content-Type: application/json" \
            --data-binary @- 2>/dev/null | \
        python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo ""
}

USER_TOKEN=$(crapi_login "user1@test.com" "Testpass123!")
USER2_TOKEN=$(crapi_login "user2@test.com" "Testpass123!")
MECH_TOKEN=$(crapi_login "mechanic1@test.com" "Testpass123!")

if [ -z "$USER_TOKEN" ] || [ -z "$USER2_TOKEN" ]; then
    log_fail "Failed to get crAPI tokens"
    exit 1
fi
log_ok "Tokens acquired"

mkdir -p "$OUTPUT_DIR"
AUTH_FILE="${OUTPUT_DIR}/planner-auth.yaml"
(umask 077; cat > "$AUTH_FILE" <<EOF
method: bearer
location: header
roles:
  admin:
    token: "${USER_TOKEN}"
  mechanic:
    token: "${MECH_TOKEN}"
  user:
    token: "${USER_TOKEN}"
  user2:
    token: "${USER2_TOKEN}"
  anonymous:
    token: ""
EOF
)

PASSED=0
FAILED=0

run_test() {
    local name="$1"
    shift
    log_info "Test: $name"
    if "$@" 2>&1; then
        log_ok "$name"
        PASSED=$((PASSED + 1))
    else
        log_fail "$name"
        FAILED=$((FAILED + 1))
    fi
}

# Test 1: Planner generates a plan and prints it
RESULT_FILE="${OUTPUT_DIR}/planner-${PROVIDER}-results.json"
log_info "Running planner with --planner-provider ${PROVIDER}..."
run_test "planner generates plan" \
    "$HADRIAN_BIN" test rest \
        --api "${SCRIPT_DIR}/crapi/crapi-openapi-spec.json" \
        --roles "${SCRIPT_DIR}/crapi/roles.yaml" \
        --auth "$AUTH_FILE" \
        --template-dir "${SCRIPT_DIR}/crapi/templates/owasp" \
        --planner --planner-provider "$PROVIDER" \
        --output json --output-file "$RESULT_FILE"

# Test 2: Planner-only mode produces findings
RESULT_FILE_ONLY="${OUTPUT_DIR}/planner-only-${PROVIDER}-results.json"
run_test "planner-only mode runs" \
    "$HADRIAN_BIN" test rest \
        --api "${SCRIPT_DIR}/crapi/crapi-openapi-spec.json" \
        --roles "${SCRIPT_DIR}/crapi/roles.yaml" \
        --auth "$AUTH_FILE" \
        --template-dir "${SCRIPT_DIR}/crapi/templates/owasp" \
        --planner --planner-only --planner-provider "$PROVIDER" \
        --output json --output-file "$RESULT_FILE_ONLY"

# Test 3: Custom context steers the planner
RESULT_FILE_CTX="${OUTPUT_DIR}/planner-context-${PROVIDER}-results.json"
run_test "planner-context steers plan" \
    "$HADRIAN_BIN" test rest \
        --api "${SCRIPT_DIR}/crapi/crapi-openapi-spec.json" \
        --roles "${SCRIPT_DIR}/crapi/roles.yaml" \
        --auth "$AUTH_FILE" \
        --template-dir "${SCRIPT_DIR}/crapi/templates/owasp" \
        --planner --planner-only --planner-provider "$PROVIDER" \
        --planner-context "Only test the orders endpoint" \
        --output json --output-file "$RESULT_FILE_CTX"

# Summary
echo ""
echo -e "${BOLD}=== LLM Planner Test Results (${PROVIDER}) ===${NC}"
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
