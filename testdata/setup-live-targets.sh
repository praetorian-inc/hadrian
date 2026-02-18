#!/usr/bin/env bash
# =============================================================================
# setup-live-targets.sh
#
# One-time setup for all Hadrian live test targets.
# Pulls Docker images, clones repos, builds binaries, starts services,
# and writes a config file for run-live-tests.sh.
#
# Usage:
#   ./testdata/setup-live-targets.sh [options]
#
# Options:
#   --targets <list>   Comma-separated targets (default: all)
#                      Valid: vulnerable-api,dvga,grpc,crapi
#   --crapi-dir <dir>  Path to existing crAPI repo (skips clone)
#   --skip-start       Only build/pull, don't start services
#   --teardown         Stop and remove all running targets
#   --help             Show this help message
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/.live-test-config"

# Default ports
VULN_API_PORT=8080
DVGA_PORT=5013
GRPC_PORT=50051
CRAPI_PORT=8888

# Defaults
TARGETS="vulnerable-api,dvga,grpc,crapi"
CRAPI_DIR=""
SKIP_START=false
TEARDOWN=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_header() {
    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
}
log_info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $1"; }

# ==== Argument parsing ====
while [ $# -gt 0 ]; do
    case $1 in
        --targets)    TARGETS="$2"; shift 2 ;;
        --crapi-dir)  CRAPI_DIR="$2"; shift 2 ;;
        --skip-start) SKIP_START=true; shift ;;
        --teardown)   TEARDOWN=true; shift ;;
        --help)
            sed -n '2,/^# =====/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# ==== Teardown ====
if [ "$TEARDOWN" = true ]; then
    log_header "Tearing Down Live Targets"

    pkill -f "vulnerable-api$" 2>/dev/null && log_ok "Stopped vulnerable-api" || true
    pkill -f "grpc-server$" 2>/dev/null && log_ok "Stopped grpc-server" || true

    if command -v docker >/dev/null 2>&1; then
        docker rm -f hadrian-dvga 2>/dev/null && log_ok "Removed dvga container" || true
        (cd "${CRAPI_DIR:-${SCRIPT_DIR}/.crapi-repo/deploy/docker}" 2>/dev/null && \
            docker compose down 2>/dev/null && log_ok "Stopped crapi containers") || true
    fi

    rm -f "$CONFIG_FILE"
    log_ok "Removed config file"
    echo ""
    exit 0
fi

# ==== Port helpers ====
port_in_use() {
    if command -v lsof >/dev/null 2>&1; then
        lsof -i :"$1" >/dev/null 2>&1
    elif command -v ss >/dev/null 2>&1; then
        ss -ltn | grep -q ":$1 "
    else
        # Fallback: try to connect
        (echo >/dev/tcp/localhost/"$1") 2>/dev/null
    fi
}

find_available_port() {
    local base_port=$1
    local port=$base_port
    while port_in_use "$port"; do
        port=$((port + 1))
        if [ $((port - base_port)) -gt 20 ]; then
            echo ""
            return 1
        fi
    done
    echo "$port"
}

# ==== Prerequisite checks ====
log_header "Checking Prerequisites"

if ! command -v go >/dev/null 2>&1; then
    log_fail "Go is not installed. Install Go 1.21+ from https://go.dev/dl/"
    exit 1
fi
log_ok "Go $(go version | awk '{print $3}')"

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

    # Ensure Go protoc plugins
    if ! command -v protoc-gen-go >/dev/null 2>&1; then
        log_info "Installing protoc-gen-go..."
        go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    fi
    if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
        log_info "Installing protoc-gen-go-grpc..."
        go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    fi
    log_ok "protoc Go plugins installed"
fi

# ==== Find available ports ====
log_header "Resolving Ports"

if echo "$TARGETS" | grep -q "vulnerable-api"; then
    VULN_API_PORT=$(find_available_port 8080)
    if [ -z "$VULN_API_PORT" ]; then
        log_fail "No available port near 8080 for vulnerable-api"
        exit 1
    fi
    log_ok "vulnerable-api -> port $VULN_API_PORT"
fi

if echo "$TARGETS" | grep -q "dvga"; then
    DVGA_PORT=$(find_available_port 5013)
    if [ -z "$DVGA_PORT" ]; then
        log_fail "No available port near 5013 for dvga"
        exit 1
    fi
    log_ok "dvga -> port $DVGA_PORT"
fi

if echo "$TARGETS" | grep -q "grpc"; then
    GRPC_PORT=$(find_available_port 50051)
    if [ -z "$GRPC_PORT" ]; then
        log_fail "No available port near 50051 for grpc-server"
        exit 1
    fi
    log_ok "grpc-server -> port $GRPC_PORT"
fi

if echo "$TARGETS" | grep -q "crapi"; then
    CRAPI_PORT=$(find_available_port 8888)
    if [ -z "$CRAPI_PORT" ]; then
        log_fail "No available port near 8888 for crapi"
        exit 1
    fi
    log_ok "crapi -> port $CRAPI_PORT"
fi

# ==== Build Go targets ====
log_header "Building Hadrian and Go Targets"

log_info "Building hadrian..."
(cd "$REPO_ROOT" && go build -o hadrian ./cmd/hadrian)
log_ok "hadrian built"

if echo "$TARGETS" | grep -q "vulnerable-api"; then
    log_info "Building vulnerable-api..."
    (cd "${SCRIPT_DIR}/vulnerable-api" && go build -o vulnerable-api .)
    log_ok "vulnerable-api built"
fi

if echo "$TARGETS" | grep -q "grpc"; then
    log_info "Building grpc-server..."
    (cd "${SCRIPT_DIR}/grpc-server" && {
        if [ ! -d pb ]; then
            log_info "Generating protobuf code..."
            mkdir -p pb
            protoc --go_out=pb --go_opt=paths=source_relative \
                --go-grpc_out=pb --go-grpc_opt=paths=source_relative \
                service.proto
        fi
        go build -o grpc-server .
    })
    log_ok "grpc-server built"
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

    # Patch docker-compose port if not default
    COMPOSE_DIR="${CRAPI_DIR}/deploy/docker"
    if [ "$CRAPI_PORT" != "8888" ]; then
        log_info "Patching crAPI docker-compose to use port $CRAPI_PORT..."
        sed -i.bak "s/8888:80/${CRAPI_PORT}:80/g" "${COMPOSE_DIR}/docker-compose.yml"
        log_ok "Patched crAPI to port $CRAPI_PORT"
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
        log_info "Starting crapi services (this may take 1-2 minutes)..."
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
        CRAPI_READY=true
        elapsed=0
        while ! curl -s -o /dev/null -w "%{http_code}" "http://localhost:${CRAPI_PORT}/identity/api/auth/login" 2>/dev/null | grep -qE "^[2-4]"; do
            sleep 5
            elapsed=$((elapsed + 5))
            if [ $elapsed -ge 180 ]; then
                log_warn "crapi did not respond within 180s"
                log_warn "Container status:"
                (cd "${CRAPI_DIR}/deploy/docker" && docker compose ps 2>&1) || true
                log_warn "crapi-web logs:"
                (cd "${CRAPI_DIR}/deploy/docker" && docker compose logs crapi-web 2>&1 | tail -10) || true
                log_warn "crapi will be skipped during test run. Debug with:"
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

# ==== Write config file ====
log_header "Writing Configuration"

cat > "$CONFIG_FILE" <<EOF
# Auto-generated by setup-live-targets.sh on $(date -Iseconds 2>/dev/null || date)
# Source this or let run-live-tests.sh read it automatically.
VULN_API_PORT=${VULN_API_PORT}
DVGA_PORT=${DVGA_PORT}
GRPC_PORT=${GRPC_PORT}
CRAPI_PORT=${CRAPI_PORT}
CRAPI_DIR=${CRAPI_DIR}
TARGETS_SETUP=${TARGETS}
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
    if [ "$CRAPI_READY" = false ]; then
        echo -e "  crapi           ${YELLOW}warning${NC}   may not be ready (check containers)"
    else
        echo -e "  crapi           ${GREEN}running${NC}   http://localhost:$CRAPI_PORT"
    fi
fi
echo ""
echo -e "${BOLD}Next step:${NC}"
echo -e "  ./testdata/run-live-tests.sh"
echo ""
echo -e "${BOLD}To tear down:${NC}"
echo -e "  ./testdata/setup-live-targets.sh --teardown"
echo ""
