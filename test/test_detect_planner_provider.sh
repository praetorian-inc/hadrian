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
# P5: OLLAMA_HOST unset → helper uses default http://localhost:11434
# Exercises the ${OLLAMA_HOST:-http://localhost:11434} default fallback.
# Assumes no local ollama is running on the test host (valid for CI/dev
# sandboxes; may be flaky on a developer's box with ollama running).
# ---------------------------------------------------------------------------
echo "P5: OLLAMA_HOST unset → falls back to default localhost:11434 → empty (no local ollama)"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST
out=$(detect_planner_provider 2>/dev/null || true)
assert_eq "P5 OLLAMA_HOST default fallback (assumes no local ollama)" "" "$out"
restore_env

# ---------------------------------------------------------------------------
# PE: empty-but-set OPENAI_API_KEY treated as not set (regression guard)
# The helper uses [ -n "${OPENAI_API_KEY:-}" ] which treats both unset and
# empty as "not set". This test guards against regressions where someone
# changes to [ -n "${OPENAI_API_KEY-}" ] (no colon), which would silently
# match empty-but-set.
# ---------------------------------------------------------------------------
echo "PE: empty-but-set OPENAI_API_KEY treated as not set → empty"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST
OPENAI_API_KEY="" ANTHROPIC_API_KEY="" OLLAMA_HOST="http://127.0.0.1:1" \
    out=$(detect_planner_provider 2>/dev/null || true)
assert_eq "PE empty-but-set OPENAI_API_KEY falls through" "" "$out"
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

# Start a persistent HTTP server in the background that serves 200 on any path.
# Uses serve_forever() (not handle_request()) so the /dev/tcp readiness probe
# and the curl from detect_planner_provider can both be served without racing.
# The process is explicitly killed after the assertion.
python3 -c "
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{}')
    def log_message(self, *a): pass
srv = http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H)
srv.serve_forever()
" "$FREE_PORT" &
_P6_SERVER_PID=$!

# Wait for the server to bind (max ~500ms); avoids the timing-fragile sleep 0.1.
OLLAMA_PORT="$FREE_PORT"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if exec 3<>"/dev/tcp/127.0.0.1/${OLLAMA_PORT}" 2>/dev/null; then
        exec 3<&-
        break
    fi
    sleep 0.05
done

export OLLAMA_HOST="http://127.0.0.1:${FREE_PORT}"
out=$(detect_planner_provider)
assert_eq "P6 echoes ollama when server reachable" "ollama" "$out"

# Explicit cleanup — do NOT use trap here to avoid clobbering any outer trap chain.
kill "$_P6_SERVER_PID" 2>/dev/null
wait "$_P6_SERVER_PID" 2>/dev/null || true
restore_env

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit $(( fail > 0 ? 1 : 0 ))
