#!/usr/bin/env bash
# =============================================================================
# setup-live-targets.sh
#
# One-time setup for all Hadrian live test targets.
# Builds the in-house Go target binaries and hadrian itself, then writes a
# config file (port assignments) for run-live-tests.sh.
#
# All four targets are in-house Go binaries — no container runtime, image
# pull, or repository clone is required. This means the full live-test suite
# runs in a fresh devcontainer with no container daemon (LAB-2750).
#
# Usage:
#   ./test/setup-live-targets.sh [options]
#
# Options:
#   --targets <list>   Comma-separated targets (default: all)
#                      Valid: vulnerable-api,vulnerable-graphql,grpc,vulnerable-rest-complex
#   --no-build         Skip rebuilding hadrian and Go targets if binaries exist
#   --teardown         Stop any running target processes and remove config
#   --help             Show this help message
#
# Environment overrides:
#   VULN_API_PORT_OVERRIDE           Force a specific port for vulnerable-api
#   VULN_GRAPHQL_PORT_OVERRIDE       Force a specific port for vulnerable-graphql
#   GRPC_PORT_OVERRIDE               Force a specific port for grpc-server
#   VULN_REST_COMPLEX_PORT_OVERRIDE  Force a specific port for vulnerable-rest-complex
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/.live-test-config"
SPEC_CACHE_DIR="${SCRIPT_DIR}/.live-test-cache"

# Default ports. The script will pick these unless they're already in use,
# in which case find_available_port walks forward until it finds a free one
# (skipping any ports already claimed earlier in the same run).
DEFAULT_VULN_API_PORT=9889
DEFAULT_VULN_GRAPHQL_PORT=5013
DEFAULT_GRPC_PORT=50051
DEFAULT_VULN_REST_COMPLEX_PORT=8888

VULN_API_PORT=$DEFAULT_VULN_API_PORT
VULN_GRAPHQL_PORT=$DEFAULT_VULN_GRAPHQL_PORT
GRPC_PORT=$DEFAULT_GRPC_PORT
VULN_REST_COMPLEX_PORT=$DEFAULT_VULN_REST_COMPLEX_PORT

# Defaults
TARGETS="vulnerable-api,vulnerable-graphql,grpc,vulnerable-rest-complex"
SKIP_START=false
TEARDOWN=false
DO_BUILD=true

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# All log_* helpers write to stderr. Several functions in this script
# (find_available_port, resolve_target_port) echo their result on stdout for
# capture via `$(...)`. If log_* wrote to stdout, an error message during a
# port walk would silently end up inside the captured port value — a real
# bug seen during code review.
log_header() {
    echo "" >&2
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}" >&2
    echo -e "${BOLD}${BLUE}  $1${NC}" >&2
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}" >&2
}
log_info()  { echo -e "${CYAN}[INFO]${NC} $1" >&2; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1" >&2; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $1" >&2; }

# ==== Argument parsing ====
while [ $# -gt 0 ]; do
    case $1 in
        --targets)    TARGETS="$2"; shift 2 ;;
        --skip-start) SKIP_START=true; shift ;;
        --no-build)   DO_BUILD=false; shift ;;
        --teardown)   TEARDOWN=true; shift ;;
        --help)
            sed -n '2,/^# =====/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# ==== Teardown ====
# Every target is a local Go process now, so teardown just kills them by name
# and removes the generated config. No containers or volumes to clean.
if [ "$TEARDOWN" = true ]; then
    log_header "Tearing Down Live Targets"

    pkill -f "vulnerable-api$" 2>/dev/null && log_ok "Stopped vulnerable-api" || true
    pkill -f "vulnerable-graphql$" 2>/dev/null && log_ok "Stopped vulnerable-graphql" || true
    pkill -f "grpc-server$" 2>/dev/null && log_ok "Stopped grpc-server" || true
    pkill -f "vulnerable-rest-complex$" 2>/dev/null && log_ok "Stopped vulnerable-rest-complex" || true

    rm -f "$CONFIG_FILE"
    rm -rf "$SPEC_CACHE_DIR"
    log_ok "Removed config file and spec cache"
    echo ""
    exit 0
fi

# ==== Port helpers ====
# port_in_use, find_available_port, _port_excluded, and resolve_target_port
# live in test/lib/port-helpers.sh so the regression harness can source the
# same definitions and any prod-source change automatically affects what the
# harness asserts.
# shellcheck source=test/lib/port-helpers.sh
. "${SCRIPT_DIR}/lib/port-helpers.sh"

# ==== Prerequisite checks ====
log_header "Checking Prerequisites"

# All targets are Go binaries, so Go is required iff we're going to build at
# least one binary in this run (DO_BUILD=true) or a needed binary is missing.
need_go=false
if [ "$DO_BUILD" = true ]; then
    need_go=true
elif [ ! -x "${REPO_ROOT}/hadrian" ]; then
    need_go=true
fi
# Split per Go target so `--targets vulnerable-api --no-build` doesn't require
# Go just because another target's binary happens to be missing.
if echo "$TARGETS" | grep -q "vulnerable-api" && \
       { [ "$DO_BUILD" = true ] \
         || [ ! -x "${SCRIPT_DIR}/vulnerable-api/vulnerable-api" ]; }; then
    need_go=true
fi
if echo "$TARGETS" | grep -q "vulnerable-graphql" && \
       { [ "$DO_BUILD" = true ] \
         || [ ! -x "${SCRIPT_DIR}/vulnerable-graphql/vulnerable-graphql" ]; }; then
    need_go=true
fi
if echo "$TARGETS" | grep -q "grpc" && \
       { [ "$DO_BUILD" = true ] \
         || [ ! -x "${SCRIPT_DIR}/grpc-server/grpc-server" ]; }; then
    need_go=true
fi
if echo "$TARGETS" | grep -q "vulnerable-rest-complex" && \
       { [ "$DO_BUILD" = true ] \
         || [ ! -x "${SCRIPT_DIR}/vulnerable-rest-complex/vulnerable-rest-complex" ]; }; then
    need_go=true
fi

if [ "$need_go" = true ]; then
    if ! command -v go >/dev/null 2>&1; then
        log_fail "Go is not installed. Install Go 1.21+ from https://go.dev/dl/"
        log_info "Or re-run with --no-build if all target binaries already exist."
        exit 1
    fi
    log_ok "Go $(go version | awk '{print $3}')"
else
    log_ok "Go check skipped (no Go build required)"
fi

if echo "$TARGETS" | grep -q "grpc"; then
    if ! command -v protoc >/dev/null 2>&1; then
        log_warn "protoc not found. Installing protobuf compiler..."
        if command -v brew >/dev/null 2>&1; then
            brew install protobuf
        else
            log_fail "protoc not found and brew not available."
            log_info "Install protobuf: https://grpc.io/docs/protoc-installation/"
            exit 1
        fi
    fi
    log_ok "protoc $(protoc --version 2>&1 | awk '{print $NF}')"

    # Ensure Go protoc plugins are in PATH
    GOBIN="$(go env GOPATH)/bin"
    if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
        export PATH="$PATH:$GOBIN"
        log_info "Added $GOBIN to PATH for this session"
    fi

    # Install protoc plugins if not available
    if ! command -v protoc-gen-go >/dev/null 2>&1; then
        log_info "Installing protoc-gen-go..."
        go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    fi
    if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
        log_info "Installing protoc-gen-go-grpc..."
        go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    fi

    # Verify plugins are now available (re-check after install)
    if ! command -v protoc-gen-go >/dev/null 2>&1 || ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
        log_fail "protoc plugins not found after installation."
        log_info "Add the following to your shell profile (~/.zshrc or ~/.bashrc):"
        log_info "  export PATH=\"\$PATH:\$(go env GOPATH)/bin\""
        log_info "Then restart your shell or run: source ~/.zshrc"
        exit 1
    fi
    log_ok "protoc Go plugins installed"
fi

# ==== Find available ports ====
log_header "Resolving Ports"

# CLAIMED_PORTS tracks every port assigned in this run so subsequent
# find_available_port calls won't hand out the same number to a different
# target. Without this, two targets can both end up on (e.g.) 8889 when
# 8888 is taken on the host: the OS still says 8889 is free between the
# two assignments because nothing has actually bound it yet.
CLAIMED_PORTS=()

if echo "$TARGETS" | grep -q "vulnerable-api"; then
    VULN_API_PORT=$(resolve_target_port "${VULN_API_PORT_OVERRIDE:-}" \
        "$DEFAULT_VULN_API_PORT" "vulnerable-api" \
        "${CLAIMED_PORTS[@]+"${CLAIMED_PORTS[@]}"}") || exit 1
    CLAIMED_PORTS+=("$VULN_API_PORT")
    log_ok "vulnerable-api -> port $VULN_API_PORT"
fi

if echo "$TARGETS" | grep -q "vulnerable-graphql"; then
    VULN_GRAPHQL_PORT=$(resolve_target_port "${VULN_GRAPHQL_PORT_OVERRIDE:-}" \
        "$DEFAULT_VULN_GRAPHQL_PORT" "vulnerable-graphql" \
        "${CLAIMED_PORTS[@]+"${CLAIMED_PORTS[@]}"}") || exit 1
    CLAIMED_PORTS+=("$VULN_GRAPHQL_PORT")
    log_ok "vulnerable-graphql -> port $VULN_GRAPHQL_PORT"
fi

if echo "$TARGETS" | grep -q "grpc"; then
    GRPC_PORT=$(resolve_target_port "${GRPC_PORT_OVERRIDE:-}" \
        "$DEFAULT_GRPC_PORT" "grpc-server" \
        "${CLAIMED_PORTS[@]+"${CLAIMED_PORTS[@]}"}") || exit 1
    CLAIMED_PORTS+=("$GRPC_PORT")
    log_ok "grpc-server -> port $GRPC_PORT"
fi

if echo "$TARGETS" | grep -q "vulnerable-rest-complex"; then
    VULN_REST_COMPLEX_PORT=$(resolve_target_port "${VULN_REST_COMPLEX_PORT_OVERRIDE:-}" \
        "$DEFAULT_VULN_REST_COMPLEX_PORT" "vulnerable-rest-complex" \
        "${CLAIMED_PORTS[@]+"${CLAIMED_PORTS[@]}"}") || exit 1
    CLAIMED_PORTS+=("$VULN_REST_COMPLEX_PORT")
    log_ok "vulnerable-rest-complex -> port $VULN_REST_COMPLEX_PORT"
fi

# ==== Build Go targets ====
log_header "Building Hadrian and Go Targets"

if [ "$DO_BUILD" = true ] || [ ! -x "${REPO_ROOT}/hadrian" ]; then
    log_info "Building hadrian..."
    (cd "$REPO_ROOT" && go build -o hadrian ./cmd/hadrian)
    log_ok "hadrian built"
else
    log_ok "hadrian binary exists (--no-build, skipping)"
fi

if echo "$TARGETS" | grep -q "vulnerable-api"; then
    if [ "$DO_BUILD" = true ] || [ ! -x "${SCRIPT_DIR}/vulnerable-api/vulnerable-api" ]; then
        log_info "Building vulnerable-api..."
        (cd "${SCRIPT_DIR}/vulnerable-api" && go build -o vulnerable-api .)
        log_ok "vulnerable-api built"
    else
        log_ok "vulnerable-api binary exists (--no-build, skipping)"
    fi
fi

if echo "$TARGETS" | grep -q "vulnerable-graphql"; then
    if [ "$DO_BUILD" = true ] || [ ! -x "${SCRIPT_DIR}/vulnerable-graphql/vulnerable-graphql" ]; then
        log_info "Building vulnerable-graphql..."
        (cd "${SCRIPT_DIR}/vulnerable-graphql" && go build -o vulnerable-graphql .)
        log_ok "vulnerable-graphql built"
    else
        log_ok "vulnerable-graphql binary exists (--no-build, skipping)"
    fi
fi

if echo "$TARGETS" | grep -q "grpc"; then
    if [ "$DO_BUILD" = true ] || [ ! -x "${SCRIPT_DIR}/grpc-server/grpc-server" ]; then
        log_info "Building grpc-server..."
        (cd "${SCRIPT_DIR}/grpc-server" && {
            # Check for actual generated files, not just directory existence
            # This handles the case where pb/ exists but is empty from a failed run
            if [ ! -f pb/service.pb.go ] || [ ! -f pb/service_grpc.pb.go ]; then
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
            fi
            go build -o grpc-server .
        })
        log_ok "grpc-server built"
    else
        log_ok "grpc-server binary exists (--no-build, skipping)"
    fi
fi

if echo "$TARGETS" | grep -q "vulnerable-rest-complex"; then
    if [ "$DO_BUILD" = true ] || [ ! -x "${SCRIPT_DIR}/vulnerable-rest-complex/vulnerable-rest-complex" ]; then
        log_info "Building vulnerable-rest-complex..."
        (cd "${SCRIPT_DIR}/vulnerable-rest-complex" && go build -o vulnerable-rest-complex .)
        log_ok "vulnerable-rest-complex built"
    else
        log_ok "vulnerable-rest-complex binary exists (--no-build, skipping)"
    fi
fi

# All targets are launched on demand by run-live-tests.sh (it starts each Go
# binary, health-checks it, runs hadrian, then stops it). --skip-start is
# accepted for backwards compatibility but there are no long-lived services
# to start here anymore.
if [ "$SKIP_START" = true ]; then
    log_info "--skip-start: targets are started on demand by run-live-tests.sh anyway."
fi

# ==== Write config file ====
log_header "Writing Configuration"

# Path values are written quoted (KEY="VALUE") below, and the readers in
# run-live-tests.sh and test-llm-planner.sh reject any line that doesn't
# match `^[A-Za-z_][A-Za-z0-9_]*="[A-Za-z0-9_./:@,+ -]*"$` — quoted-only.
# Inside double quotes, `source` does NOT word-split, so paths with spaces
# round-trip safely.

cat > "$CONFIG_FILE" <<EOF
# Auto-generated by setup-live-targets.sh on $(date -Iseconds 2>/dev/null || date)
# Source this or let run-live-tests.sh read it automatically.
# Values must match run-live-tests.sh's safety regex
# (^[[:space:]]*(#.*)?\$|^[A-Za-z_][A-Za-z0-9_]*=\"[A-Za-z0-9_./:@,+ -]*\"\$).
# All values are quoted so \`source\` won't word-split paths/values.
VULN_API_PORT="${VULN_API_PORT}"
VULN_GRAPHQL_PORT="${VULN_GRAPHQL_PORT}"
GRPC_PORT="${GRPC_PORT}"
VULN_REST_COMPLEX_PORT="${VULN_REST_COMPLEX_PORT}"
EOF

log_ok "Config written to ${CONFIG_FILE}"

# ==== Summary ====
log_header "Setup Complete"

echo ""
echo -e "${BOLD}Targets ready (all in-house Go binaries — no container runtime required):${NC}"
if echo "$TARGETS" | grep -q "vulnerable-api"; then
    echo -e "  vulnerable-api          ${GREEN}built${NC}  (starts on port $VULN_API_PORT)"
fi
if echo "$TARGETS" | grep -q "vulnerable-graphql"; then
    echo -e "  vulnerable-graphql      ${GREEN}built${NC}  (starts on port $VULN_GRAPHQL_PORT)"
fi
if echo "$TARGETS" | grep -q "grpc"; then
    echo -e "  grpc-server             ${GREEN}built${NC}  (starts on port $GRPC_PORT)"
fi
if echo "$TARGETS" | grep -q "vulnerable-rest-complex"; then
    echo -e "  vulnerable-rest-complex ${GREEN}built${NC}  (starts on port $VULN_REST_COMPLEX_PORT)"
fi
echo ""
echo -e "${BOLD}Next step:${NC}"
echo -e "  ./test/run-live-tests.sh"
echo ""
echo -e "${BOLD}To tear down (stops any running target processes):${NC}"
echo -e "  ./test/setup-live-targets.sh --teardown"
echo ""
