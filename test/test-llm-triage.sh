#!/usr/bin/env bash
# =============================================================================
# test-llm-triage.sh
#
# Tests LLM triage with OpenAI or Anthropic against crAPI.
# Verifies that findings include LLM analysis when a cloud provider is used.
#
# Prerequisites:
#   - crAPI running on localhost:8888
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

if ! curl -sf -o /dev/null "$CRAPI_URL" 2>/dev/null; then
    log_fail "crAPI not running on $CRAPI_URL"
    echo "Start it with: cd crAPI/deploy/docker && docker-compose up -d"
    exit 1
fi

# Setup crAPI users and tokens
log_info "Setting up crAPI tokens..."

crapi_login() {
    local email="$1" password="$2"
    printf '{"email":"%s","password":"%s"}' "$email" "$password" | \
        curl -sf -X POST "${CRAPI_URL}/identity/api/auth/login" \
            -H "Content-Type: application/json" \
            --data-binary @- 2>/dev/null | \
        python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo ""
}

USER_TOKEN=$(crapi_login "user1@test.com" "Testpass123!")
USER2_TOKEN=$(crapi_login "user2@test.com" "Testpass123!")
MECH_TOKEN=$(crapi_login "mechanic1@test.com" "Testpass123!")

if [ -z "$USER_TOKEN" ] || [ -z "$USER2_TOKEN" ] || [ -z "$MECH_TOKEN" ]; then
    log_fail "Failed to get crAPI tokens. Create users first (see test/crapi/README.md)"
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

# Run hadrian with LLM triage
RESULT_FILE="${OUTPUT_DIR}/llm-triage-${PROVIDER}-results.json"
log_info "Running hadrian with --llm-provider ${PROVIDER}..."

"$HADRIAN_BIN" test rest \
    --api "${SCRIPT_DIR}/crapi/crapi-openapi-spec.json" \
    --roles "${SCRIPT_DIR}/crapi/roles.yaml" \
    --auth "$AUTH_FILE" \
    --template-dir "${SCRIPT_DIR}/crapi/templates/owasp" \
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
    log_fail "No findings detected — crAPI may not be running or tokens are expired"
    exit 1
fi
