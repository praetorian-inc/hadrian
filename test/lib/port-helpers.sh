#!/usr/bin/env bash
# =============================================================================
# port-helpers.sh
#
# Pure (no global state) port helpers. SOURCE THIS FILE — do not execute.
# Functions defined here:
#
#   - port_in_use <port>             OS-level check (lsof/ss/dev-tcp fallback)
#   - find_available_port <base> [excluded...]   walks forward, skips OS-busy
#                                                AND in-run-claimed ports
#   - _port_excluded <needle> [hay...]   private; helper for find_available_port
#   - resolve_target_port <override> <default> <label> [claimed...]
#                                    honors *_PORT_OVERRIDE env vars then
#                                    falls back to find_available_port,
#                                    collision-checks against host + claimed
#
# Each function relies on log_info / log_ok / log_warn / log_fail being
# defined in the sourcing scope (setup-live-targets.sh provides them; the
# regression harness stubs them with no-ops). This is intentional: the
# helpers are I/O-light and let the consumer decide formatting.
#
# History: these helpers used to live in test/crapi/port-helpers.sh alongside
# a crAPI-specific docker-compose port patcher. LAB-2750 replaced the Docker
# crAPI/DVGA targets with in-house Go binaries and removed the compose
# patcher; the generic port helpers moved here so every Go target can share
# them without depending on a crAPI directory.
#
# Sourced by:
#   - test/setup-live-targets.sh
#   - test/run-live-tests.sh
#   - test/test-llm-planner.sh
# =============================================================================

# port_in_use <port>
# Returns 0 (true) iff the OS reports something using the given port.
# `lsof -i :PORT` reports ALL socket states (LISTEN + ESTABLISHED +
# TIME_WAIT + ...). To match that with ss we need `-a` (all states).
# Earlier iterations used `-ltn` (listen-only) which missed
# ESTABLISHED/TIME_WAIT, then `-tn` (non-listening) which missed LISTEN
# entirely — both produced false-frees that find_available_port would
# then hand out. `-atn` covers everything ss can show.
port_in_use() {
    if command -v lsof >/dev/null 2>&1; then
        lsof -i :"$1" >/dev/null 2>&1
    elif command -v ss >/dev/null 2>&1; then
        ss -atn | grep -q ":$1 "
    else
        # Fallback: try to connect
        (echo >/dev/tcp/localhost/"$1") 2>/dev/null
    fi
}

# _port_excluded <needle> [hay...]
# Returns 0 iff <needle> is in the [hay...] list. Private helper — find_available_port
# uses this to skip ports claimed earlier in the same setup run.
_port_excluded() {
    local needle=$1
    shift
    local p
    for p in "$@"; do
        [ "$p" = "$needle" ] && return 0
    done
    return 1
}

# find_available_port <base_port> [excluded_port]...
# Walks forward from base_port until it finds a port that is both not in
# use by the OS AND not in the excluded list. The excluded list is how
# callers tell us about ports they've already claimed earlier in the same
# setup run — those ports are still "free" from the OS's perspective
# (nothing is bound there yet), but binding to them later would collide.
# Echoes the resolved port on stdout, or empty + non-zero on no-port-found.
find_available_port() {
    local base_port=$1
    shift
    local excluded=("$@")
    local port=$base_port
    while port_in_use "$port" || _port_excluded "$port" "${excluded[@]+"${excluded[@]}"}"; do
        port=$((port + 1))
        if [ $((port - base_port)) -gt 20 ]; then
            echo ""
            return 1
        fi
    done
    echo "$port"
}

# resolve_target_port <override_value> <default_port> <label> [claimed_port]...
# Resolves a port for one target:
# - if <override_value> is non-empty, validate it isn't OS-busy and isn't
#   already claimed by another target in the same run; on conflict log
#   fail-mode diagnostics to stderr (via log_fail) and return 1.
# - otherwise call find_available_port from <default_port> skipping the
#   already-claimed list.
# Echoes the resolved port on stdout. log_fail must be defined in the
# sourcing scope.
resolve_target_port() {
    local override_value=$1 default_port=$2 label=$3
    shift 3
    local claimed=("$@")
    if [ -n "$override_value" ]; then
        if port_in_use "$override_value"; then
            log_fail "${label}: override port ${override_value} is already in use"
            return 1
        fi
        if _port_excluded "$override_value" "${claimed[@]+"${claimed[@]}"}"; then
            log_fail "${label}: override port ${override_value} collides with another target"
            return 1
        fi
        echo "$override_value"
        return 0
    fi
    local resolved
    resolved=$(find_available_port "$default_port" "${claimed[@]+"${claimed[@]}"}")
    if [ -z "$resolved" ]; then
        log_fail "No available port near ${default_port} for ${label}"
        return 1
    fi
    echo "$resolved"
}
