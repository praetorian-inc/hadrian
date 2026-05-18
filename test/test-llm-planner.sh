#!/usr/bin/env bash
# =============================================================================
# test-llm-planner.sh
#
# Tests LLM-assisted attack planner against crAPI.
# Verifies the planner generates a valid attack plan and executes it.
#
# Prerequisites:
#   - crAPI running on the port resolved by setup-live-targets.sh
#     (default 8888 — see CRAPI_OPENAPI_SPEC_DEFAULT_PORT in
#     test/crapi/crapi-helpers.sh; override via CRAPI_PORT env var or
#     .live-test-config)
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

# Load setup config (CRAPI_PORT, CRAPI_SPEC_FILE, canonical creds) if it
# exists. Without this, we'd reach for a different default port and
# different user credentials than setup-live-targets.sh used.
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

# Shared crAPI helpers (canonical users, signup/login, spec patcher).
# Sourced BEFORE the CRAPI_PORT default so the default tracks
# CRAPI_OPENAPI_SPEC_DEFAULT_PORT (single source of truth) instead of
# duplicating the literal 8888.
# shellcheck source=test/crapi/crapi-helpers.sh
. "${SCRIPT_DIR}/crapi/crapi-helpers.sh"

CRAPI_PORT="${CRAPI_PORT:-$CRAPI_OPENAPI_SPEC_DEFAULT_PORT}"
CRAPI_URL="http://localhost:${CRAPI_PORT}"

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

if ! curl -s -o /dev/null -w '%{http_code}' "${CRAPI_URL}/identity/api/auth/signup" 2>/dev/null | grep -qE '^[2-4][0-9]{2}$'; then
    log_fail "crAPI not running on $CRAPI_URL"
    exit 1
fi

# Setup crAPI users + tokens.
# Sign up the canonical roster — this is idempotent against an existing DB
# but required against a freshly torn-down one. Previous versions of this
# script assumed users already existed (with credentials that didn't match
# what setup-live-targets.sh registered) and failed silently against a
# clean volume.
log_info "Setting up crAPI users and tokens..."
# Wrap with `if !` so a provisioning failure produces a coherent diagnostic
# instead of a raw set-e abort with no context (matches the pattern in
# run-live-tests.sh and setup-live-targets.sh).
if ! crapi_setup_users "$CRAPI_URL"; then
    log_fail "crAPI user provisioning failed (see error above)"
    exit 1
fi

CRAPI_ADMIN_TOKEN=$(crapi_login    "$CRAPI_URL" "$CRAPI_ADMIN_EMAIL"    "$CRAPI_PASSWORD")
CRAPI_USER_TOKEN=$(crapi_login     "$CRAPI_URL" "$CRAPI_USER_EMAIL"     "$CRAPI_PASSWORD")
CRAPI_USER2_TOKEN=$(crapi_login    "$CRAPI_URL" "$CRAPI_USER2_EMAIL"    "$CRAPI_PASSWORD")
CRAPI_MECHANIC_TOKEN=$(crapi_login "$CRAPI_URL" "$CRAPI_MECHANIC_EMAIL" "$CRAPI_PASSWORD")

# All four tokens must be acquired so role-specific templates (BFLA
# admin-video-delete, mechanic workflows) run with the correct identity.
# Previously this script mapped admin -> USER_TOKEN, which silently
# degraded admin-scoped templates in the planner test to regular-user
# credentials.
if [ -z "$CRAPI_ADMIN_TOKEN" ] || [ -z "$CRAPI_USER_TOKEN" ] \
        || [ -z "$CRAPI_USER2_TOKEN" ] || [ -z "$CRAPI_MECHANIC_TOKEN" ]; then
    log_fail "Failed to get crAPI tokens (admin/user1/user2/mechanic must all be non-empty)"
    exit 1
fi
log_ok "Tokens acquired"

mkdir -p "$OUTPUT_DIR"

# Resolve the OpenAPI spec path. Prefer the patched copy that
# setup-live-targets.sh wrote into .live-test-config, but only if its
# baked-in port matches our current CRAPI_PORT — otherwise a runtime
# CRAPI_PORT override against a stale config would silently mis-route.
# When re-patching, write into the same SPEC_CACHE_DIR setup uses
# (test/.live-test-cache/) so a planner-only run doesn't leave a cache
# artifact in the .results directory.
SPEC_CACHE_DIR="${SCRIPT_DIR}/.live-test-cache"
# Anchor the port match on a non-digit / end-of-line boundary to avoid
# substring false-matches (e.g. CRAPI_PORT=889 vs localhost:8895).
if [ -n "${CRAPI_SPEC_FILE:-}" ] && [ -f "$CRAPI_SPEC_FILE" ] \
        && grep -qE "localhost:${CRAPI_PORT}([^0-9]|\$)" "$CRAPI_SPEC_FILE"; then
    CRAPI_SPEC="$CRAPI_SPEC_FILE"
else
    if [ -n "${CRAPI_SPEC_FILE:-}" ] && [ -f "$CRAPI_SPEC_FILE" ]; then
        log_info "Cached spec at ${CRAPI_SPEC_FILE} does not match CRAPI_PORT=${CRAPI_PORT}; re-patching."
    fi
    mkdir -p "$SPEC_CACHE_DIR"
    CRAPI_SPEC=$(crapi_patch_openapi_spec \
        "${SCRIPT_DIR}/crapi/crapi-openapi-spec.json" \
        "$CRAPI_PORT" \
        "$SPEC_CACHE_DIR")
fi
# Guard against silent failure of crapi_patch_openapi_spec (validation
# branch returns 1 + empty stdout). An unchecked empty $CRAPI_SPEC would
# pass `--api ""` to hadrian and produce an opaque downstream error.
if [ -z "$CRAPI_SPEC" ] || [ ! -f "$CRAPI_SPEC" ]; then
    log_fail "Could not resolve crAPI OpenAPI spec (empty path or missing file)"
    exit 1
fi

AUTH_FILE="${OUTPUT_DIR}/planner-auth.yaml"
# Export tokens as env vars so the YAML can reference them by name. The
# YAML is emitted with a QUOTED heredoc terminator (`<<'EOF'`) so bash
# does NOT substitute the ${...} text — hadrian's pkg/auth/auth.go
# expands them via expandEnvSafe before detectHardcodedSecret fires,
# which suppresses the SECURITY warning that fires on inline tokens.
export CRAPI_ADMIN_TOKEN CRAPI_MECHANIC_TOKEN CRAPI_USER_TOKEN CRAPI_USER2_TOKEN
(umask 077; cat > "$AUTH_FILE" <<'EOF'
method: bearer
location: header
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
        --api "$CRAPI_SPEC" \
        --roles "${SCRIPT_DIR}/crapi/roles.yaml" \
        --auth "$AUTH_FILE" \
        --template-dir "${SCRIPT_DIR}/crapi/templates/owasp" \
        --planner --planner-provider "$PROVIDER" \
        --output json --output-file "$RESULT_FILE"

# Test 2: Planner-only mode produces findings
RESULT_FILE_ONLY="${OUTPUT_DIR}/planner-only-${PROVIDER}-results.json"
run_test "planner-only mode runs" \
    "$HADRIAN_BIN" test rest \
        --api "$CRAPI_SPEC" \
        --roles "${SCRIPT_DIR}/crapi/roles.yaml" \
        --auth "$AUTH_FILE" \
        --template-dir "${SCRIPT_DIR}/crapi/templates/owasp" \
        --planner --planner-only --planner-provider "$PROVIDER" \
        --output json --output-file "$RESULT_FILE_ONLY"

# Test 3: Custom context steers the planner
RESULT_FILE_CTX="${OUTPUT_DIR}/planner-context-${PROVIDER}-results.json"
run_test "planner-context steers plan" \
    "$HADRIAN_BIN" test rest \
        --api "$CRAPI_SPEC" \
        --roles "${SCRIPT_DIR}/crapi/roles.yaml" \
        --auth "$AUTH_FILE" \
        --template-dir "${SCRIPT_DIR}/crapi/templates/owasp" \
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

# Test 1 (plan + brute-force) should find crAPI BOLA vulns
assert_findings "test1 has findings" "$RESULT_FILE" 1

# Test 2 (planner-only) — file should exist and be valid JSON
assert_findings "test2 result file valid" "$RESULT_FILE_ONLY" 0

# Test 3 (context-steered) — orders endpoint is a known crAPI BOLA target with >=1 finding
assert_findings "test3 context-steered findings" "$RESULT_FILE_CTX" 1

# Summary
echo ""
echo -e "${BOLD}=== LLM Planner Test Results (${PROVIDER}) ===${NC}"
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
