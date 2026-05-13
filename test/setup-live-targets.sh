#!/usr/bin/env bash
# =============================================================================
# setup-live-targets.sh
#
# One-time setup for all Hadrian live test targets.
# Pulls Docker images, clones repos, builds binaries, starts services,
# and writes a config file for run-live-tests.sh.
#
# Usage:
#   ./test/setup-live-targets.sh [options]
#
# Options:
#   --targets <list>   Comma-separated targets (default: all)
#                      Valid: vulnerable-api,dvga,grpc,crapi
#   --crapi-dir <dir>  Path to existing crAPI repo (skips clone)
#   --skip-start       Only build/pull, don't start services
#   --no-build         Skip rebuilding hadrian and Go targets if binaries exist
#   --teardown         Stop and remove all running targets (and their volumes)
#   --purge            With --teardown, also remove the cached crAPI clone
#   --help             Show this help message
#
# Environment overrides:
#   VULN_API_PORT_OVERRIDE  Force a specific port for vulnerable-api
#   DVGA_PORT_OVERRIDE      Force a specific port for dvga
#   GRPC_PORT_OVERRIDE      Force a specific port for grpc-server
#   CRAPI_PORT_OVERRIDE     Force a specific port for crAPI's web service
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/.live-test-config"
SPEC_CACHE_DIR="${SCRIPT_DIR}/.live-test-cache"

# Default ports. The script will pick these unless they're already in use,
# in which case find_available_port walks forward until it finds a free one
# (skipping any ports already claimed earlier in the same run).
# CRAPI default tracks crapi-helpers.sh's CRAPI_OPENAPI_SPEC_DEFAULT_PORT
# (sourced below) so a future spec-port move flows through one place.
DEFAULT_VULN_API_PORT=9889
DEFAULT_DVGA_PORT=5013
DEFAULT_GRPC_PORT=50051

VULN_API_PORT=$DEFAULT_VULN_API_PORT
DVGA_PORT=$DEFAULT_DVGA_PORT
GRPC_PORT=$DEFAULT_GRPC_PORT
CRAPI_READY=true

# Defaults
TARGETS="vulnerable-api,dvga,grpc,crapi"
CRAPI_DIR=""
SKIP_START=false
TEARDOWN=false
PURGE=false
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
# (find_available_port, resolve_target_port, crapi_patch_openapi_spec)
# echo their result on stdout for capture via `$(...)`. If log_* wrote to
# stdout, an error message during a port walk would silently end up
# inside the captured port value — a real bug seen during code review.
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

# Load shared crAPI helpers (canonical users, signup/login, spec patcher).
# shellcheck source=test/crapi/crapi-helpers.sh
. "${SCRIPT_DIR}/crapi/crapi-helpers.sh"

# crAPI default port comes from the helper's CRAPI_OPENAPI_SPEC_DEFAULT_PORT
# so the spec-patch default and the setup default move together.
DEFAULT_CRAPI_PORT="$CRAPI_OPENAPI_SPEC_DEFAULT_PORT"
CRAPI_PORT=$DEFAULT_CRAPI_PORT

# ==== Argument parsing ====
while [ $# -gt 0 ]; do
    case $1 in
        --targets)    TARGETS="$2"; shift 2 ;;
        --crapi-dir)  CRAPI_DIR="$2"; shift 2 ;;
        --skip-start) SKIP_START=true; shift ;;
        --no-build)   DO_BUILD=false; shift ;;
        --teardown)   TEARDOWN=true; shift ;;
        --purge)      PURGE=true; shift ;;
        --help)
            sed -n '2,/^# =====/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# --purge only removes the cached crAPI clone inside the --teardown branch.
# Warn loudly if the user passes --purge alone so it's not a silent no-op.
if [ "$PURGE" = true ] && [ "$TEARDOWN" != true ]; then
    log_warn "--purge requires --teardown to take effect; ignoring."
fi

# ==== Teardown ====
if [ "$TEARDOWN" = true ]; then
    log_header "Tearing Down Live Targets"

    pkill -f "vulnerable-api$" 2>/dev/null && log_ok "Stopped vulnerable-api" || true
    pkill -f "grpc-server$" 2>/dev/null && log_ok "Stopped grpc-server" || true

    # If the operator ran setup with `--crapi-dir /custom/path`, the saved
    # path lives in .live-test-config. Without re-reading it here the
    # teardown's docker compose down would target the wrong directory and
    # leave the actual containers + volumes running (the very state this
    # PR was trying to clean up reliably). Honor the saved value before
    # falling back to the default clone path.
    if [ -z "$CRAPI_DIR" ] && [ -f "$CONFIG_FILE" ]; then
        if ! grep -qvE '^[[:space:]]*(#.*)?$|^[A-Za-z_][A-Za-z0-9_]*="[A-Za-z0-9_./:@,+ -]*"$' "$CONFIG_FILE"; then
            # shellcheck disable=SC1090
            . "$CONFIG_FILE"
            if [ -n "${CRAPI_DIR:-}" ] && [ ! -d "$CRAPI_DIR" ]; then
                log_warn "Saved CRAPI_DIR=${CRAPI_DIR} from .live-test-config does not exist; ignoring."
                CRAPI_DIR=""
            elif [ -n "${CRAPI_DIR:-}" ]; then
                log_info "Using saved CRAPI_DIR=${CRAPI_DIR} from .live-test-config"
            fi
        fi
    fi

    if command -v docker >/dev/null 2>&1; then
        docker rm -f hadrian-dvga 2>/dev/null && log_ok "Removed dvga container" || true

        CRAPI_COMPOSE="${CRAPI_DIR:-${SCRIPT_DIR}/.crapi-repo}/deploy/docker"
        if [ -d "$CRAPI_COMPOSE" ]; then
            # `down -v --remove-orphans` is required: without `-v`, Postgres
            # and Mongo named volumes survive teardown, so the next setup
            # boots crAPI against a dirty DB (phone numbers already
            # registered, mechanic codes collide, leftover users with
            # unknown passwords). Stderr is intentionally NOT swallowed —
            # if teardown fails we want to see why.
            if (cd "$CRAPI_COMPOSE" && docker compose down -v --remove-orphans); then
                log_ok "Stopped crapi containers (volumes removed)"
            else
                log_warn "crapi teardown returned non-zero; some containers/volumes may remain"
            fi
        fi

        if [ "$PURGE" = true ]; then
            CRAPI_REPO_DEFAULT="${SCRIPT_DIR}/.crapi-repo"
            # Purge removes the default cached clone iff CRAPI_DIR is
            # either unset OR explicitly equals the default path. The
            # earlier `[ -z "$CRAPI_DIR" ]`-only guard pre-dates teardown
            # reading CRAPI_DIR from .live-test-config — once that load
            # populates CRAPI_DIR with the default, the empty-string
            # check would silently skip the rm and `--teardown --purge`
            # would no-op in the common case (CodeRabbit review
            # 4258701255 CR-7-2). Operator-supplied --crapi-dir paths
            # still survive.
            if [ -d "$CRAPI_REPO_DEFAULT" ] && \
               { [ -z "$CRAPI_DIR" ] || [ "$CRAPI_DIR" = "$CRAPI_REPO_DEFAULT" ]; }; then
                rm -rf "$CRAPI_REPO_DEFAULT"
                log_ok "Removed cached crAPI clone at $CRAPI_REPO_DEFAULT"
            fi
        fi
    fi

    rm -f "$CONFIG_FILE"
    rm -rf "$SPEC_CACHE_DIR"
    log_ok "Removed config file and spec cache"
    echo ""
    exit 0
fi

# ==== Port helpers ====
# port_in_use, find_available_port, _port_excluded, resolve_target_port,
# and patch_crapi_compose_port live in test/crapi/port-helpers.sh so the
# regression harness can source the same definitions and any prod-source
# change automatically affects what the harness asserts.
# shellcheck source=test/crapi/port-helpers.sh
. "${SCRIPT_DIR}/crapi/port-helpers.sh"

# ==== Prerequisite checks ====
log_header "Checking Prerequisites"

# Go is required iff (a) we're going to build at least one Go binary in
# this run (DO_BUILD=true and a Go target is selected), or (b) the user
# already-built binary is missing for a Go target. Skip the check when
# the user runs e.g. `--targets crapi --no-build` on a Docker-only box.
need_go=false
if [ "$DO_BUILD" = true ]; then
    # Hadrian binary itself is always built unless --no-build (handled below).
    need_go=true
elif [ ! -x "${REPO_ROOT}/hadrian" ]; then
    need_go=true
fi
# Split per Go-needing target so `--targets vulnerable-api --no-build`
# doesn't require Go just because the grpc-server binary happens to be
# missing (and vice versa). Only check the binary that's actually needed
# for the selected target subset.
if echo "$TARGETS" | grep -q "vulnerable-api" && \
       { [ "$DO_BUILD" = true ] \
         || [ ! -x "${SCRIPT_DIR}/vulnerable-api/vulnerable-api" ]; }; then
    need_go=true
fi
if echo "$TARGETS" | grep -q "grpc" && \
       { [ "$DO_BUILD" = true ] \
         || [ ! -x "${SCRIPT_DIR}/grpc-server/grpc-server" ]; }; then
    need_go=true
fi

if [ "$need_go" = true ]; then
    if ! command -v go >/dev/null 2>&1; then
        log_fail "Go is not installed. Install Go 1.21+ from https://go.dev/dl/"
        log_info "Or re-run with --no-build if all target binaries already exist and you only need Docker-based targets."
        exit 1
    fi
    log_ok "Go $(go version | awk '{print $3}')"
else
    log_ok "Go check skipped (no Go build required)"
fi

if echo "$TARGETS" | grep -qE "dvga|crapi"; then
    if ! command -v docker >/dev/null 2>&1; then
        log_fail "Docker is not installed. Install from https://docker.com"
        exit 1
    fi
    log_ok "Docker available"
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

if echo "$TARGETS" | grep -q "dvga"; then
    DVGA_PORT=$(resolve_target_port "${DVGA_PORT_OVERRIDE:-}" \
        "$DEFAULT_DVGA_PORT" "dvga" \
        "${CLAIMED_PORTS[@]+"${CLAIMED_PORTS[@]}"}") || exit 1
    CLAIMED_PORTS+=("$DVGA_PORT")
    log_ok "dvga -> port $DVGA_PORT"
fi

if echo "$TARGETS" | grep -q "grpc"; then
    GRPC_PORT=$(resolve_target_port "${GRPC_PORT_OVERRIDE:-}" \
        "$DEFAULT_GRPC_PORT" "grpc-server" \
        "${CLAIMED_PORTS[@]+"${CLAIMED_PORTS[@]}"}") || exit 1
    CLAIMED_PORTS+=("$GRPC_PORT")
    log_ok "grpc-server -> port $GRPC_PORT"
fi

if echo "$TARGETS" | grep -q "crapi"; then
    CRAPI_PORT=$(resolve_target_port "${CRAPI_PORT_OVERRIDE:-}" \
        "$DEFAULT_CRAPI_PORT" "crapi" \
        "${CLAIMED_PORTS[@]+"${CLAIMED_PORTS[@]}"}") || exit 1
    CLAIMED_PORTS+=("$CRAPI_PORT")
    log_ok "crapi -> port $CRAPI_PORT"
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

# ==== Pull Docker images ====
if echo "$TARGETS" | grep -q "dvga"; then
    log_header "Setting Up dvga"
    log_info "Pulling dvga image..."
    docker pull dolevf/dvga:latest
    log_ok "dvga image ready"
fi

# ==== Set up crAPI ====
if echo "$TARGETS" | grep -q "crapi"; then
    log_header "Setting Up crapi"

    if [ -z "$CRAPI_DIR" ]; then
        CRAPI_DIR="${SCRIPT_DIR}/.crapi-repo"
    fi

    if [ ! -d "$CRAPI_DIR" ]; then
        log_info "Cloning crAPI repository..."
        git clone --depth 1 https://github.com/OWASP/crAPI.git "$CRAPI_DIR"
        log_ok "crAPI cloned to $CRAPI_DIR"
    else
        log_ok "crAPI repo exists at $CRAPI_DIR"
    fi

    COMPOSE_DIR="${CRAPI_DIR}/deploy/docker"
    COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.yml"

    # Reset docker-compose.yml to original state (undo any previous sed patches)
    if [ -d "${CRAPI_DIR}/.git" ]; then
        (cd "$CRAPI_DIR" && git checkout -- deploy/docker/docker-compose.yml 2>/dev/null) || true
        log_info "Reset docker-compose.yml to original"
    elif [ -f "${COMPOSE_FILE}.bak" ]; then
        cp "${COMPOSE_FILE}.bak" "$COMPOSE_FILE"
        log_info "Restored docker-compose.yml from backup"
    fi

    # patch_crapi_compose_port is sourced from test/crapi/port-helpers.sh.
    if ! patch_crapi_compose_port "$COMPOSE_FILE" "$CRAPI_PORT"; then
        exit 1
    fi
fi

# ==== Start services ====
if [ "$SKIP_START" = false ]; then
    log_header "Starting Services"

    if echo "$TARGETS" | grep -q "dvga"; then
        docker rm -f hadrian-dvga 2>/dev/null || true
        log_info "Starting dvga on port $DVGA_PORT..."
        docker run -d -p "${DVGA_PORT}:5013" -e WEB_HOST=0.0.0.0 --name hadrian-dvga dolevf/dvga:latest >/dev/null
        log_ok "dvga container started"
    fi

    if echo "$TARGETS" | grep -q "crapi"; then
        log_info "Starting crapi services on port $CRAPI_PORT (this may take 1-2 minutes)..."
        if (cd "${CRAPI_DIR}/deploy/docker" && docker compose up -d 2>&1); then
            log_ok "crapi containers started"
        else
            log_warn "Some crapi containers may have failed to start (check output above)"
            log_info "Continuing anyway - health check will verify readiness..."
        fi
    fi

    # Wait for Docker services
    if echo "$TARGETS" | grep -q "dvga"; then
        log_info "Waiting for dvga to be ready..."
        elapsed=0
        while ! curl -sf -o /dev/null "http://localhost:${DVGA_PORT}/" 2>/dev/null; do
            sleep 2
            elapsed=$((elapsed + 2))
            if [ $elapsed -ge 60 ]; then
                log_fail "dvga did not respond within 60s"
                docker logs hadrian-dvga 2>&1 | tail -10
                exit 1
            fi
        done
        log_ok "dvga is ready on port $DVGA_PORT"
    fi

    if echo "$TARGETS" | grep -q "crapi"; then
        log_info "Waiting for crapi to be ready (may take up to 2 minutes)..."
        elapsed=0
        while ! curl -s -o /dev/null -w "%{http_code}" "http://localhost:${CRAPI_PORT}/identity/api/auth/login" 2>/dev/null | grep -qE "^[2-4]"; do
            sleep 5
            elapsed=$((elapsed + 5))
            if [ $elapsed -ge 180 ]; then
                log_fail "crapi did not respond within 180s"
                log_warn "Container status:"
                (cd "${CRAPI_DIR}/deploy/docker" && docker compose ps 2>&1) || true
                log_warn "crapi-web logs:"
                (cd "${CRAPI_DIR}/deploy/docker" && docker compose logs crapi-web 2>&1 | tail -20) || true
                log_info "Debug with:"
                log_info "  cd ${CRAPI_DIR}/deploy/docker && docker compose ps"
                log_info "  docker compose logs <container-name>"
                CRAPI_READY=false
                break
            fi
            printf "."
        done
        echo ""
        if [ "$CRAPI_READY" = true ]; then
            log_ok "crapi is ready on port $CRAPI_PORT"
        fi
    fi
fi

# ==== Fail fast on crapi readiness ====
# A failed readiness probe used to print warnings and continue, writing
# .live-test-config and exiting 0. Downstream test scripts then assumed
# crAPI was up, and CI treated the setup as successful. Now we exit
# non-zero with crAPI in the target set so the failure is visible.
if [ "$CRAPI_READY" != true ]; then
    log_fail "crAPI did not become ready. Re-run setup or pass a different --targets list."
    log_info "To run other targets without crapi: --targets vulnerable-api,dvga,grpc"
    exit 1
fi

# ==== Sign up canonical crAPI users ====
# crapi_setup_users verifies each signup by attempting a login and
# retries on failure. If it still can't provision a user, that's a hard
# fail — without users, every downstream test against crAPI is broken.
if [ "$SKIP_START" = false ] && echo "$TARGETS" | grep -q "crapi"; then
    log_header "Setting Up crAPI Users"
    log_info "Signing up canonical users..."
    if ! crapi_setup_users "http://localhost:${CRAPI_PORT}"; then
        log_fail "crapi user provisioning failed (see error above)"
        exit 1
    fi
    log_ok "crapi users created and verified"
fi

# ==== Build patched OpenAPI spec for crAPI ====
# The spec hardcodes localhost:8888 in its servers[] entry and at least
# one report_link example. When CRAPI_PORT differs, downstream scripts
# that read the spec verbatim end up pointing hadrian at port 8888 even
# though crAPI is listening elsewhere. Centralize the patch here so every
# downstream script reads CRAPI_SPEC_FILE from .live-test-config.
CRAPI_SPEC_FILE=""
if echo "$TARGETS" | grep -q "crapi"; then
    log_info "Preparing crAPI OpenAPI spec for port ${CRAPI_PORT}..."
    CRAPI_SPEC_FILE=$(crapi_patch_openapi_spec \
        "${SCRIPT_DIR}/crapi/crapi-openapi-spec.json" \
        "$CRAPI_PORT" \
        "$SPEC_CACHE_DIR")
    # Under set -e, $(failing) usually exits — but $(false_at_exit_1) inside
    # an assignment is one of bash's quietly-permissive corners across some
    # versions, so check explicitly. An empty CRAPI_SPEC_FILE here would be
    # a misleading "ready" log + an empty CRAPI_SPEC_FILE= line in the
    # config that downstream consumers fail loudly on later.
    if [ -z "$CRAPI_SPEC_FILE" ]; then
        log_fail "crapi_patch_openapi_spec returned empty path; aborting."
        exit 1
    fi
    log_ok "OpenAPI spec ready at $CRAPI_SPEC_FILE"
fi

# ==== Write config file ====
log_header "Writing Configuration"

# Path values are written quoted (KEY="VALUE") below, and the readers in
# run-live-tests.sh and test-llm-planner.sh reject any line that doesn't
# match `^[A-Za-z_][A-Za-z0-9_]*="[A-Za-z0-9_./:@,+ -]*"$` — quoted-only.
# Inside double quotes, `source` does NOT word-split, so paths with
# spaces (e.g. a repo cloned to `/Users/name/My Code/hadrian/`) round-
# trip safely. The earlier whitespace-rejection loop here was redundant
# defense and broke valid paths (CodeRabbit review 4258701255 CR-7-3).

cat > "$CONFIG_FILE" <<EOF
# Auto-generated by setup-live-targets.sh on $(date -Iseconds 2>/dev/null || date)
# Source this or let run-live-tests.sh read it automatically.
# Values must match run-live-tests.sh's safety regex
# (^[[:space:]]*(#.*)?\$|^[A-Za-z_][A-Za-z0-9_]*=\"[A-Za-z0-9_./:@,+ -]*\"\$).
# All values are quoted so `source` won't word-split paths/values.
# Canonical user identities and passwords are NOT written here — they
# come from test/crapi/crapi-helpers.sh (sourced by every downstream
# script) so we don't have to escape special chars like '!' through this
# allowlisted format.
VULN_API_PORT="${VULN_API_PORT}"
DVGA_PORT="${DVGA_PORT}"
GRPC_PORT="${GRPC_PORT}"
CRAPI_PORT="${CRAPI_PORT}"
CRAPI_DIR="${CRAPI_DIR}"
CRAPI_SPEC_FILE="${CRAPI_SPEC_FILE}"
EOF

log_ok "Config written to ${CONFIG_FILE}"

# ==== Summary ====
log_header "Setup Complete"

echo ""
echo -e "${BOLD}Targets ready:${NC}"
if echo "$TARGETS" | grep -q "vulnerable-api"; then
    echo -e "  vulnerable-api  ${GREEN}built${NC}     (will start on port $VULN_API_PORT)"
fi
if echo "$TARGETS" | grep -q "dvga"; then
    echo -e "  dvga            ${GREEN}running${NC}   http://localhost:$DVGA_PORT"
fi
if echo "$TARGETS" | grep -q "grpc"; then
    echo -e "  grpc-server     ${GREEN}built${NC}     (will start on port $GRPC_PORT)"
fi
if echo "$TARGETS" | grep -q "crapi"; then
    echo -e "  crapi           ${GREEN}running${NC}   http://localhost:$CRAPI_PORT"
fi
echo ""
echo -e "${BOLD}Next step:${NC}"
echo -e "  ./test/run-live-tests.sh"
echo ""
echo -e "${BOLD}To tear down (stops containers AND removes volumes):${NC}"
echo -e "  ./test/setup-live-targets.sh --teardown"
echo ""
