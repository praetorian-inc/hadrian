#!/usr/bin/env bash
# Unit test for detect_planner_provider. Sources llm-helpers.sh directly.
# Run with: ./test/test_detect_planner_provider.sh
#
# Covers six scenarios for the four branches of detect_planner_provider:
#   P1: only OPENAI_API_KEY set             → echoes "openai"
#   P2: only ANTHROPIC_API_KEY set          → echoes "anthropic"
#   P3: both OPENAI + ANTHROPIC set         → echoes "openai" (priority)
#   P4: no keys, OLLAMA_HOST unreachable    → echoes "" (curl timeout path)
#   P5: OLLAMA_HOST=http://127.0.0.1:1     → --max-time 2 fires → echoes ""
#   P6: one-shot HTTP server on free port   → echoes "ollama" (reachable)
set -u  # NOT -e: we want to catch failed assertions and keep going.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Source the helper directly — no sed extraction needed.
# shellcheck source=test/llm-helpers.sh
. "${SCRIPT_DIR}/llm-helpers.sh"

pass=0; fail=0

assert_eq() {  # assert_eq <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "  PASS: $1"
        pass=$((pass + 1))
    else
        echo "  FAIL: $1 — expected [${2}], got [${3}]"
        fail=$((fail + 1))
    fi
}

# Save caller's env so we can restore it between scenarios.
_SAVED_OPENAI="${OPENAI_API_KEY:-}"
_SAVED_ANTHROPIC="${ANTHROPIC_API_KEY:-}"
_SAVED_OLLAMA="${OLLAMA_HOST:-}"

restore_env() {
    if [ -n "$_SAVED_OPENAI" ];    then export OPENAI_API_KEY="$_SAVED_OPENAI";    else unset OPENAI_API_KEY;    fi
    if [ -n "$_SAVED_ANTHROPIC" ]; then export ANTHROPIC_API_KEY="$_SAVED_ANTHROPIC"; else unset ANTHROPIC_API_KEY; fi
    if [ -n "$_SAVED_OLLAMA" ];    then export OLLAMA_HOST="$_SAVED_OLLAMA";        else unset OLLAMA_HOST;        fi
}

# ---------------------------------------------------------------------------
# P1: only OPENAI_API_KEY set → should echo "openai"
# ---------------------------------------------------------------------------
echo "P1: only OPENAI_API_KEY set → openai"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST
export OPENAI_API_KEY="sk-test-key-openai"
out=$(detect_planner_provider)
assert_eq "P1 echoes openai" "openai" "$out"
restore_env

# ---------------------------------------------------------------------------
# P2: only ANTHROPIC_API_KEY set → should echo "anthropic"
# ---------------------------------------------------------------------------
echo "P2: only ANTHROPIC_API_KEY set → anthropic"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST
export ANTHROPIC_API_KEY="sk-ant-test-key"
out=$(detect_planner_provider)
assert_eq "P2 echoes anthropic" "anthropic" "$out"
restore_env

# ---------------------------------------------------------------------------
# P3: both OPENAI and ANTHROPIC set → OpenAI wins (priority)
# ---------------------------------------------------------------------------
echo "P3: both OPENAI_API_KEY and ANTHROPIC_API_KEY set → openai wins"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST
export OPENAI_API_KEY="sk-test-openai-priority"
export ANTHROPIC_API_KEY="sk-ant-test-priority"
out=$(detect_planner_provider)
assert_eq "P3 openai wins priority" "openai" "$out"
restore_env

# ---------------------------------------------------------------------------
# P4: no keys, OLLAMA_HOST points at black-hole IP/port → curl fails → ""
# Using 127.0.0.1:1 (port 1 is always closed; connection refused fires
# immediately, so --max-time 2 still returns promptly).
# ---------------------------------------------------------------------------
echo "P4: no keys, OLLAMA_HOST=http://127.0.0.1:1 → curl fails → empty"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST
export OLLAMA_HOST="http://127.0.0.1:1"
out=$(detect_planner_provider)
assert_eq "P4 echoes empty on curl failure" "" "$out"
restore_env

# ---------------------------------------------------------------------------
# P5: OLLAMA_HOST=http://127.0.0.1:1, explicit --max-time 2 guard
# Same as P4 but documents the --max-time timeout scenario explicitly.
# Port 1 is guaranteed closed so connection is refused immediately (not
# after 2 seconds), exercising the "curl returns non-zero" code path that
# the --max-time guard is designed to handle.
# ---------------------------------------------------------------------------
echo "P5: OLLAMA_HOST unreachable (port 1) → --max-time 2 guard fires → empty"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST
export OLLAMA_HOST="http://127.0.0.1:1"
out=$(detect_planner_provider)
assert_eq "P5 echoes empty on timeout/refusal" "" "$out"
restore_env

# ---------------------------------------------------------------------------
# P6: one-shot HTTP server on a free local port → detect_planner_provider
#     should succeed on the ollama curl probe and echo "ollama".
#
# Strategy: use python3 to bind to port 0 (OS assigns a free port), record
# the assigned port, then start a minimal HTTP server that returns 200 OK on
# GET /api/tags. A trap kills the server PID on exit.
# ---------------------------------------------------------------------------
echo "P6: local HTTP server returns 200 on /api/tags → echoes ollama"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST

# Find a free port by binding to :0 and reading back getsockname.
FREE_PORT=$(python3 -c "
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
")

# Start a one-request HTTP server in the background that serves 200 on any path.
python3 -c "
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{}')
    def log_message(self, *a): pass
srv = http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H)
srv.handle_request()
" "$FREE_PORT" &
_P6_SERVER_PID=$!
trap 'kill "$_P6_SERVER_PID" 2>/dev/null; wait "$_P6_SERVER_PID" 2>/dev/null' EXIT

# Give the server a moment to start.
sleep 0.1

export OLLAMA_HOST="http://127.0.0.1:${FREE_PORT}"
out=$(detect_planner_provider)
assert_eq "P6 echoes ollama when server reachable" "ollama" "$out"
restore_env

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit $(( fail > 0 ? 1 : 0 ))
