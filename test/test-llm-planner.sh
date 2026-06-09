#!/usr/bin/env bash
# =============================================================================
# test-llm-planner.sh
#
# Tests LLM-assisted attack planner against the in-house
# vulnerable-rest-complex target. Verifies the planner generates a valid
# attack plan and executes it.
#
# Prerequisites:
#   - vulnerable-rest-complex running on the port resolved by
#     setup-live-targets.sh (default 8888; override via
#     VULN_REST_COMPLEX_PORT env var or .live-test-config). No Docker needed.
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
CONFIG_FILE="${SCRIPT_DIR}/.live-test-config"

# Load setup config (port assignments) if it exists. Without this, we'd
# reach for a different default port than setup-live-targets.sh used.
if [ -f "$CONFIG_FILE" ]; then
    # Quoted-value-only regex; matches setup-live-targets.sh's heredoc
    # format. See run-live-tests.sh for the rationale (path-with-space
    # injection on source).
    if grep -qvE '^[[:space:]]*(#.*)?$|^[A-Za-z_][A-Za-z0-9_]*="[A-Za-z0-9_./:@,+ -]*"$' "$CONFIG_FILE"; then
        echo "ERROR: $CONFIG_FILE contains unsafe content. Expected only comments, blank lines, or KEY=\"VALUE\" assignments. Re-run setup-live-targets.sh to regenerate." >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

REST_COMPLEX_PORT="${VULN_REST_COMPLEX_PORT:-8888}"
REST_COMPLEX_URL="http://localhost:${REST_COMPLEX_PORT}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# All log_* helpers write to stderr so they don't pollute the stdout
# values of `$(...)` callers (consistent with setup-live-targets.sh).
log_info() { echo -e "${CYAN}[INFO]${NC} $1" >&2; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $1" >&2; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" >&2; }

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

if ! curl -sf -o /dev/null "${REST_COMPLEX_URL}/health" 2>/dev/null; then
    log_fail "vulnerable-rest-complex not running on $REST_COMPLEX_URL"
    log_info "Start it with: ./test/setup-live-targets.sh --targets vulnerable-rest-complex"
    exit 1
fi

# Setup tokens. Seed users (admin/user1/user2/mechanic1) are created at
# server startup, so we just log in — no provisioning step required.
log_info "Setting up vulnerable-rest-complex tokens..."

# shellcheck source=test/lib/rest-complex-helpers.sh
. "${SCRIPT_DIR}/lib/rest-complex-helpers.sh"

ADMIN_TOKEN=$(rest_complex_login "admin" "admin123")
USER_TOKEN=$(rest_complex_login  "user1" "user1pass")
USER2_TOKEN=$(rest_complex_login "user2" "user2pass")
MECH_TOKEN=$(rest_complex_login  "mechanic1" "mech1pass")

# All four tokens must be acquired so role-specific templates (BFLA admin
# delete, mechanic workflows) run with the correct identity.
if [ -z "$ADMIN_TOKEN" ] || [ -z "$USER_TOKEN" ] \
        || [ -z "$USER2_TOKEN" ] || [ -z "$MECH_TOKEN" ]; then
    log_fail "Failed to get vulnerable-rest-complex tokens (admin/user1/user2/mechanic must all be non-empty)"
    exit 1
fi
log_ok "Tokens acquired"

mkdir -p "$OUTPUT_DIR"

# Resolve the OpenAPI spec path. The in-house target ships a static spec
# pinned to the default port; if the operator runs on a non-default port,
# patch the server URL into a copy under the results dir.
REST_COMPLEX_SPEC="${SCRIPT_DIR}/vulnerable-rest-complex/openapi.yaml"
if [ "$REST_COMPLEX_PORT" != "8888" ]; then
    REST_COMPLEX_SPEC="${OUTPUT_DIR}/planner-rest-complex-openapi.yaml"
    sed "s|http://localhost:8888|http://localhost:${REST_COMPLEX_PORT}|g" \
        "${SCRIPT_DIR}/vulnerable-rest-complex/openapi.yaml" > "$REST_COMPLEX_SPEC"
    log_info "Patched OpenAPI spec to use port $REST_COMPLEX_PORT"
fi
if [ ! -f "$REST_COMPLEX_SPEC" ]; then
    log_fail "Could not resolve vulnerable-rest-complex OpenAPI spec ($REST_COMPLEX_SPEC)"
    exit 1
fi

AUTH_FILE="${OUTPUT_DIR}/planner-auth.yaml"
(umask 077; cat > "$AUTH_FILE" <<EOF
method: bearer
location: header
roles:
  admin:
    token: "${ADMIN_TOKEN}"
  mechanic:
    token: "${MECH_TOKEN}"
  user1:
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
        --api "$REST_COMPLEX_SPEC" \
        --roles "${SCRIPT_DIR}/vulnerable-rest-complex/roles.yaml" \
        --auth "$AUTH_FILE" \
        --template-dir "${SCRIPT_DIR}/vulnerable-rest-complex/templates/owasp" \
        --planner --planner-provider "$PROVIDER" \
        --output json --output-file "$RESULT_FILE"

# Test 2: Planner-only mode produces findings
RESULT_FILE_ONLY="${OUTPUT_DIR}/planner-only-${PROVIDER}-results.json"
run_test "planner-only mode runs" \
    "$HADRIAN_BIN" test rest \
        --api "$REST_COMPLEX_SPEC" \
        --roles "${SCRIPT_DIR}/vulnerable-rest-complex/roles.yaml" \
        --auth "$AUTH_FILE" \
        --template-dir "${SCRIPT_DIR}/vulnerable-rest-complex/templates/owasp" \
        --planner --planner-only --planner-provider "$PROVIDER" \
        --output json --output-file "$RESULT_FILE_ONLY"

# Test 3: Custom context steers the planner
RESULT_FILE_CTX="${OUTPUT_DIR}/planner-context-${PROVIDER}-results.json"
run_test "planner-context steers plan" \
    "$HADRIAN_BIN" test rest \
        --api "$REST_COMPLEX_SPEC" \
        --roles "${SCRIPT_DIR}/vulnerable-rest-complex/roles.yaml" \
        --auth "$AUTH_FILE" \
        --template-dir "${SCRIPT_DIR}/vulnerable-rest-complex/templates/owasp" \
        --planner --planner-only --planner-provider "$PROVIDER" \
        --planner-context "Only test the orders endpoint" \
        --output json --output-file "$RESULT_FILE_CTX"

# Validate result contents (not just exit status)
assert_findings() {
    local label="$1" file="$2" min_count="$3"
    if [ ! -f "$file" ]; then
        log_fail "$label: result file not found"
        FAILED=$((FAILED + 1))
        return
    fi
    local count
    if ! count=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get('findings',[])))" "$file" 2>/dev/null); then
        log_fail "$label: result file is not valid JSON"
        FAILED=$((FAILED + 1))
        return
    fi
    if [ -z "$count" ]; then
        log_fail "$label: could not parse finding count"
        FAILED=$((FAILED + 1))
        return
    fi
    if [ "$count" -ge "$min_count" ]; then
        log_ok "$label: $count findings (>= $min_count expected)"
        PASSED=$((PASSED + 1))
    else
        log_fail "$label: only $count findings (expected >= $min_count)"
        FAILED=$((FAILED + 1))
    fi
}

# Test 1 (plan + brute-force) should find vulnerable-rest-complex BOLA vulns
assert_findings "test1 has findings" "$RESULT_FILE" 1

# Test 2 (planner-only) — file should exist and be valid JSON
assert_findings "test2 result file valid" "$RESULT_FILE_ONLY" 0

# Test 3 (context-steered) — orders endpoint is a known vulnerable-rest-complex BOLA target with >=1 finding
assert_findings "test3 context-steered findings" "$RESULT_FILE_CTX" 1

# Summary
echo ""
echo -e "${BOLD}=== LLM Planner Test Results (${PROVIDER}) ===${NC}"
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
