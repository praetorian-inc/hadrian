#!/usr/bin/env bash
# =============================================================================
# test-llm-triage.sh
#
# Tests LLM triage with OpenAI or Anthropic against the in-house
# vulnerable-rest-complex target. Verifies that findings include LLM analysis
# when a cloud provider is used.
#
# Prerequisites:
#   - vulnerable-rest-complex running (./test/setup-live-targets.sh first, or
#     the binary started on $VULN_REST_COMPLEX_PORT — no Docker required)
#   - OPENAI_API_KEY or ANTHROPIC_API_KEY set
#   - hadrian binary built
#
# Usage:
#   ./test/test-llm-triage.sh [openai|anthropic]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HADRIAN_BIN="${HADRIAN_BIN:-${REPO_ROOT}/hadrian}"
OUTPUT_DIR="${SCRIPT_DIR}/.results"
CONFIG_FILE="${SCRIPT_DIR}/.live-test-config"

# Pick up the port assigned by setup-live-targets.sh if present. Fail fast on
# unsafe content rather than silently skipping it — same quoted-value-only
# guard as run-live-tests.sh / test-llm-planner.sh.
if [ -f "$CONFIG_FILE" ]; then
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

log_info() { echo -e "${CYAN}[INFO]${NC} $1" >&2; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $1" >&2; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" >&2; }

# Parse provider argument
PROVIDER="${1:-openai}"
case "$PROVIDER" in
    openai)
        if [ -z "${OPENAI_API_KEY:-}" ]; then
            log_fail "OPENAI_API_KEY not set"
            exit 1
        fi
        ;;
    anthropic)
        if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
            log_fail "ANTHROPIC_API_KEY not set"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 [openai|anthropic]"
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
    echo "Start it with: ./test/setup-live-targets.sh --targets vulnerable-rest-complex"
    echo "          then: (cd test/vulnerable-rest-complex && PORT=${REST_COMPLEX_PORT} ./vulnerable-rest-complex)"
    exit 1
fi

# Setup users and tokens
log_info "Setting up vulnerable-rest-complex tokens..."

# shellcheck source=test/lib/rest-complex-helpers.sh
. "${SCRIPT_DIR}/lib/rest-complex-helpers.sh"

ADMIN_TOKEN=$(rest_complex_login "admin" "admin123")
USER_TOKEN=$(rest_complex_login "user1" "user1pass")
USER2_TOKEN=$(rest_complex_login "user2" "user2pass")
MECH_TOKEN=$(rest_complex_login "mechanic1" "mech1pass")

if [ -z "$ADMIN_TOKEN" ] || [ -z "$USER_TOKEN" ] || [ -z "$USER2_TOKEN" ] || [ -z "$MECH_TOKEN" ]; then
    log_fail "Failed to get vulnerable-rest-complex tokens (see test/vulnerable-rest-complex/README.md)"
    exit 1
fi
log_ok "Tokens acquired"

# Write temp auth config
mkdir -p "$OUTPUT_DIR"
AUTH_FILE="${OUTPUT_DIR}/llm-triage-auth.yaml"
trap 'rm -f "$AUTH_FILE"' EXIT
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

# Resolve the OpenAPI spec path. The target ships a static spec pinned to the
# default port; if running on a non-default port, patch the server URL into a
# copy so hadrian (which reads servers[0].url) targets the right port. Mirrors
# test-llm-planner.sh.
REST_COMPLEX_SPEC="${SCRIPT_DIR}/vulnerable-rest-complex/openapi.yaml"
if [ "$REST_COMPLEX_PORT" != "8888" ]; then
    REST_COMPLEX_SPEC="${OUTPUT_DIR}/triage-rest-complex-openapi.yaml"
    sed "s|http://localhost:8888|http://localhost:${REST_COMPLEX_PORT}|g" \
        "${SCRIPT_DIR}/vulnerable-rest-complex/openapi.yaml" > "$REST_COMPLEX_SPEC"
    log_info "Patched OpenAPI spec to use port $REST_COMPLEX_PORT"
fi

# Run hadrian with LLM triage
RESULT_FILE="${OUTPUT_DIR}/llm-triage-${PROVIDER}-results.json"
log_info "Running hadrian with --llm-provider ${PROVIDER}..."

"$HADRIAN_BIN" test rest \
    --api "$REST_COMPLEX_SPEC" \
    --roles "${SCRIPT_DIR}/vulnerable-rest-complex/roles.yaml" \
    --auth "$AUTH_FILE" \
    --template-dir "${SCRIPT_DIR}/vulnerable-rest-complex/templates/owasp" \
    --llm-provider "$PROVIDER" \
    --output json \
    --output-file "$RESULT_FILE"

# Validate results
if [ ! -f "$RESULT_FILE" ]; then
    log_fail "No results file generated"
    exit 1
fi

FINDING_COUNT=$(python3 -c "import json; d=json.load(open('$RESULT_FILE')); print(len(d.get('findings',[])))" 2>/dev/null || echo "0")
LLM_COUNT=$(python3 -c "import json; d=json.load(open('$RESULT_FILE')); print(sum(1 for f in d.get('findings',[]) if f.get('llm_analysis')))" 2>/dev/null || echo "0")

echo ""
echo -e "${BOLD}=== LLM Triage Test Results (${PROVIDER}) ===${NC}"
echo "  Total findings: $FINDING_COUNT"
echo "  With LLM analysis: $LLM_COUNT"
echo "  Results: $RESULT_FILE"

if [ "$FINDING_COUNT" -gt 0 ] && [ "$LLM_COUNT" -gt 0 ]; then
    log_ok "LLM triage working — ${LLM_COUNT}/${FINDING_COUNT} findings have analysis"
    exit 0
elif [ "$FINDING_COUNT" -gt 0 ] && [ "$LLM_COUNT" -eq 0 ]; then
    log_fail "Findings detected but none have LLM analysis — triage may not have fired"
    exit 1
else
    log_fail "No findings detected — vulnerable-rest-complex may not be running or tokens are expired"
    exit 1
fi
