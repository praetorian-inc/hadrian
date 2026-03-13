#!/bin/bash
# =============================================================================
# run-all-auth-tests.sh
#
# Runs Hadrian security tests against the vulnerable API using all four
# authentication methods: Bearer JWT, API Key, Basic Auth, and Cookie.
#
# Usage:
#   ./run-all-auth-tests.sh [options]
#
# Options:
#   --bearer-only           Run only Bearer JWT tests
#   --apikey-only           Run only API Key tests
#   --basic-only            Run only Basic Auth tests
#   --no-build              Skip building the API
#   --verbose               Enable verbose Hadrian output
#   --cli-only              Print CLI output only (no JSON files)
#   --proxy <url>           Route traffic through a proxy (e.g., http://127.0.0.1:8080 for Burp)
#   --reset-between-tests   Reset API data before each auth method test (ensures consistent results)
#   --help                  Show this help message
# =============================================================================

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_PORT="${API_PORT:-8889}"
API_URL="http://localhost:${API_PORT}"
HADRIAN_BIN="${HADRIAN_BIN:-hadrian}"
TEMPLATES_DIR="${SCRIPT_DIR}/templates/owasp"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
RUN_BEARER=true
RUN_APIKEY=true
RUN_BASIC=true
RUN_COOKIE=true
DO_BUILD=true
VERBOSE=""
CLI_ONLY=false
PROXY=""
RESET_BETWEEN_TESTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --bearer-only)
            RUN_BEARER=true
            RUN_APIKEY=false
            RUN_BASIC=false
            RUN_COOKIE=false
            shift
            ;;
        --apikey-only)
            RUN_BEARER=false
            RUN_APIKEY=true
            RUN_BASIC=false
            RUN_COOKIE=false
            shift
            ;;
        --basic-only)
            RUN_BEARER=false
            RUN_APIKEY=false
            RUN_BASIC=true
            RUN_COOKIE=false
            shift
            ;;
        --cookie-only)
            RUN_BEARER=false
            RUN_APIKEY=false
            RUN_BASIC=false
            RUN_COOKIE=true
            shift
            ;;
        --no-build)
            DO_BUILD=false
            shift
            ;;
        --verbose)
            VERBOSE="--verbose"
            shift
            ;;
        --cli-only)
            CLI_ONLY=true
            shift
            ;;
        --proxy)
            PROXY="$2"
            shift 2
            ;;
        --reset-between-tests)
            RESET_BETWEEN_TESTS=true
            shift
            ;;
        --help)
            head -25 "$0" | tail -20
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

cleanup() {
    log_info "Cleaning up..."
    if [[ -n "$API_PID" ]]; then
        kill "$API_PID" 2>/dev/null || true
        wait "$API_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

wait_for_api() {
    local max_attempts=30
    local attempt=0

    while [[ $attempt -lt $max_attempts ]]; do
        if curl -s "${API_URL}/health" > /dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.5
    done

    log_error "API failed to start after ${max_attempts} attempts"
    return 1
}

start_api() {
    local auth_method="$1"

    # Kill any existing API process (from this script)
    if [[ -n "$API_PID" ]]; then
        kill "$API_PID" 2>/dev/null || true
        wait "$API_PID" 2>/dev/null || true
    fi

    # Kill any leftover vulnerable-api processes from previous runs
    # Use -x for exact match to avoid killing this script (whose path contains "vulnerable-api")
    pkill -x "vulnerable-api" 2>/dev/null || true
    sleep 0.5

    log_info "Starting API with AUTH_METHOD=${auth_method}..."
    if [[ "$CLI_ONLY" == "true" ]]; then
        # Suppress API server logs in CLI-only mode
        # Use nohup and full redirect to ensure no output leaks
        AUTH_METHOD="${auth_method}" PORT="${API_PORT}" nohup "${SCRIPT_DIR}/vulnerable-api" </dev/null &>/dev/null &
    else
        AUTH_METHOD="${auth_method}" PORT="${API_PORT}" "${SCRIPT_DIR}/vulnerable-api" &
    fi
    API_PID=$!

    if ! wait_for_api; then
        log_error "Failed to start API"
        exit 1
    fi

    log_success "API started on ${API_URL} (PID: ${API_PID})"
}

reset_api_data() {
    log_info "Resetting API data..."
    if curl -s -X POST "${API_URL}/api/reset" > /dev/null; then
        log_success "Data reset successful"
    else
        log_warn "Data reset failed (API may have restarted)"
    fi
}

get_jwt_tokens() {
    log_info "Obtaining JWT tokens..."

    # Get admin token
    ADMIN_RESPONSE=$(curl -s -X POST "${API_URL}/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"admin123"}')
    export ADMIN_TOKEN=$(echo "$ADMIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

    if [[ -z "$ADMIN_TOKEN" ]]; then
        log_error "Failed to get admin token"
        echo "Response: $ADMIN_RESPONSE"
        return 1
    fi

    # Get user1 token
    USER1_RESPONSE=$(curl -s -X POST "${API_URL}/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"user1","password":"user1pass"}')
    export USER1_TOKEN=$(echo "$USER1_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

    if [[ -z "$USER1_TOKEN" ]]; then
        log_error "Failed to get user1 token"
        return 1
    fi

    # Get user2 token
    USER2_RESPONSE=$(curl -s -X POST "${API_URL}/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"user2","password":"user2pass"}')
    export USER2_TOKEN=$(echo "$USER2_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

    if [[ -z "$USER2_TOKEN" ]]; then
        log_error "Failed to get user2 token"
        return 1
    fi

    log_success "JWT tokens obtained for admin, user1, user2"
    return 0
}

run_hadrian() {
    local auth_config="$1"
    local auth_method="$2"
    local output_file="${SCRIPT_DIR}/results-${auth_method}.json"

    log_info "Running Hadrian with ${auth_method} authentication..."

    # Use --concurrency 1 to ensure tests run in alphabetical order.
    # This prevents DELETE tests from running before GET tests, which would
    # delete resources before BOLA read tests can detect vulnerabilities.
    # Build proxy flags if set (--insecure needed for Burp Suite TLS interception)
    local proxy_flags=""
    if [[ -n "$PROXY" ]]; then
        proxy_flags="--proxy ${PROXY} --insecure"
    fi

    if [[ "$CLI_ONLY" == "true" ]]; then
        # CLI-only mode: print directly to terminal, no JSON files
        HADRIAN_TEMPLATES="${TEMPLATES_DIR}" "${HADRIAN_BIN}" test rest \
            --api "${SCRIPT_DIR}/openapi.yaml" \
            --roles "${SCRIPT_DIR}/roles.yaml" \
            --auth "${SCRIPT_DIR}/${auth_config}" \
            --concurrency 1 \
            ${proxy_flags} \
            ${VERBOSE}
    else
        # Default mode: output to JSON files with log
        HADRIAN_TEMPLATES="${TEMPLATES_DIR}" "${HADRIAN_BIN}" test rest \
            --api "${SCRIPT_DIR}/openapi.yaml" \
            --roles "${SCRIPT_DIR}/roles.yaml" \
            --auth "${SCRIPT_DIR}/${auth_config}" \
            --concurrency 1 \
            --output json \
            --output-file "${output_file}" \
            ${proxy_flags} \
            ${VERBOSE} \
            2>&1 | tee "${SCRIPT_DIR}/hadrian-${auth_method}.log"
    fi

    local exit_code=${PIPESTATUS[0]}

    if [[ $exit_code -eq 0 ]]; then
        log_success "Hadrian completed for ${auth_method}"

        # Only show JSON summary when not in CLI-only mode
        if [[ "$CLI_ONLY" != "true" ]]; then
            log_info "Results saved to: ${output_file}"

            # Display findings summary from JSON
            if [[ -f "${output_file}" ]] && command -v jq &> /dev/null; then
                echo ""
                echo -e "${BLUE}--- Findings Summary ---${NC}"

                local total=$(jq '.findings | length' "${output_file}" 2>/dev/null || echo "0")
                local critical=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' "${output_file}" 2>/dev/null || echo "0")
                local high=$(jq '[.findings[] | select(.severity == "HIGH")] | length' "${output_file}" 2>/dev/null || echo "0")
                local medium=$(jq '[.findings[] | select(.severity == "MEDIUM")] | length' "${output_file}" 2>/dev/null || echo "0")
                local low=$(jq '[.findings[] | select(.severity == "LOW")] | length' "${output_file}" 2>/dev/null || echo "0")

                echo -e "  Total:    ${total}"
                [[ "$critical" -gt 0 ]] && echo -e "  ${RED}CRITICAL: ${critical}${NC}"
                [[ "$high" -gt 0 ]] && echo -e "  ${YELLOW}HIGH:     ${high}${NC}"
                [[ "$medium" -gt 0 ]] && echo -e "  MEDIUM:   ${medium}"
                [[ "$low" -gt 0 ]] && echo -e "  LOW:      ${low}"

                echo ""
                echo -e "${BLUE}--- Vulnerabilities Found ---${NC}"
                jq -r '.findings[] | "  [\(.severity)] \(.category) - \(.name) \(.method) \(.endpoint)"' "${output_file}" 2>/dev/null | head -20

                if [[ "$total" -gt 20 ]]; then
                    echo "  ... and $((total - 20)) more (see ${output_file})"
                fi
                echo ""
            fi
        fi
    else
        log_warn "Hadrian exited with code ${exit_code} for ${auth_method}"
    fi

    return $exit_code
}


# -----------------------------------------------------------------------------
# Main Script
# -----------------------------------------------------------------------------

cd "${SCRIPT_DIR}"

log_header "Hadrian Multi-Auth Test Suite"

echo "Configuration:"
echo "  API URL:      ${API_URL}"
echo "  Templates:    ${TEMPLATES_DIR}"
echo "  Hadrian:      ${HADRIAN_BIN}"
echo "  Run Bearer:   ${RUN_BEARER}"
echo "  Run API Key:  ${RUN_APIKEY}"
echo "  Run Basic:    ${RUN_BASIC}"
echo "  Run Cookie:   ${RUN_COOKIE}"
echo "  CLI Only:     ${CLI_ONLY}"
if [[ -n "$PROXY" ]]; then
echo "  Proxy:        ${PROXY}"
fi
echo "  Reset Between Tests: ${RESET_BETWEEN_TESTS}"
echo ""

# Build the API if needed
if [[ "$DO_BUILD" == "true" ]]; then
    log_info "Building vulnerable API..."
    GOWORK=off go build -o vulnerable-api .
    log_success "Build complete"
fi

# Check Hadrian is available
if ! command -v "${HADRIAN_BIN}" &> /dev/null; then
    log_error "Hadrian binary not found: ${HADRIAN_BIN}"
    log_info "Build Hadrian with: go build -o hadrian ./cmd/hadrian (from the hadrian repo root)"
    exit 1
fi

# Track results (using simple variables for macOS bash 3.x compatibility)
RESULT_bearer=""
RESULT_apikey=""
RESULT_basic=""
RESULT_cookie=""

# -----------------------------------------------------------------------------
# Test 1: Bearer JWT Authentication
# -----------------------------------------------------------------------------

if [[ "$RUN_BEARER" == "true" ]]; then
    log_header "Test 1: Bearer JWT Authentication"

    start_api "bearer"

    if get_jwt_tokens; then
        # Create temporary auth file with actual tokens
        cat > "${SCRIPT_DIR}/auth-bearer-active.yaml" << EOF
# Auto-generated auth config with JWT tokens
method: bearer

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

        # Reset data before test if enabled
        if [[ "$RESET_BETWEEN_TESTS" == "true" ]]; then
            reset_api_data
        fi

        if run_hadrian "auth-bearer-active.yaml" "bearer"; then
            RESULT_bearer="PASS"
        else
            RESULT_bearer="FAIL"
        fi

        # Cleanup temp file
        rm -f "${SCRIPT_DIR}/auth-bearer-active.yaml"
    else
        RESULT_bearer="ERROR (token generation failed)"
    fi
fi

# -----------------------------------------------------------------------------
# Test 2: API Key Authentication
# -----------------------------------------------------------------------------

if [[ "$RUN_APIKEY" == "true" ]]; then
    log_header "Test 2: API Key Authentication"

    start_api "api_key"

    # Reset data before test if enabled
    if [[ "$RESET_BETWEEN_TESTS" == "true" ]]; then
        reset_api_data
    fi

    if run_hadrian "auth-apikey.yaml" "apikey"; then
        RESULT_apikey="PASS"
    else
        RESULT_apikey="FAIL"
    fi
fi

# -----------------------------------------------------------------------------
# Test 3: Basic HTTP Authentication
# -----------------------------------------------------------------------------

if [[ "$RUN_BASIC" == "true" ]]; then
    log_header "Test 3: Basic HTTP Authentication"

    start_api "basic"

    # Reset data before test if enabled
    if [[ "$RESET_BETWEEN_TESTS" == "true" ]]; then
        reset_api_data
    fi

    if run_hadrian "auth-basic.yaml" "basic"; then
        RESULT_basic="PASS"
    else
        RESULT_basic="FAIL"
    fi
fi

# -----------------------------------------------------------------------------
# Test 4: Cookie Authentication
# -----------------------------------------------------------------------------

if [[ "$RUN_COOKIE" == "true" ]]; then
    log_header "Test 4: Cookie Authentication"

    start_api "cookie"

    # Reset data before test if enabled
    if [[ "$RESET_BETWEEN_TESTS" == "true" ]]; then
        reset_api_data
    fi

    if run_hadrian "auth-cookie.yaml" "cookie"; then
        RESULT_cookie="PASS"
    else
        RESULT_cookie="FAIL"
    fi
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

log_header "Test Summary"

echo "Authentication Method Results:"
echo ""

for method in bearer apikey basic cookie; do
    eval "result=\$RESULT_${method}"
    if [[ -n "$result" ]]; then
        if [[ "$result" == "PASS" ]]; then
            echo -e "  ${method}:  ${GREEN}${result}${NC}"
        else
            echo -e "  ${method}:  ${RED}${result}${NC}"
        fi
    fi
done

if [[ "$CLI_ONLY" != "true" ]]; then
    echo ""
    echo "Output files:"
    for method in bearer apikey basic cookie; do
        if [[ -f "${SCRIPT_DIR}/results-${method}.json" ]]; then
            echo "  - results-${method}.json"
        fi
        if [[ -f "${SCRIPT_DIR}/hadrian-${method}.log" ]]; then
            echo "  - hadrian-${method}.log"
        fi
    done
fi

echo ""
log_success "All tests completed!"
