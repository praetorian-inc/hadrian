#!/usr/bin/env bash
# Unit test for detect_planner_provider. Sources llm-helpers.sh directly.
# Run with: ./test/test_detect_planner_provider.sh
#
# Covers eight checks for detect_planner_provider behavior:
#   P1: only OPENAI_API_KEY set                                  → echoes "openai"
#   P2: only ANTHROPIC_API_KEY set                               → echoes "anthropic"
#   P3: both OPENAI + ANTHROPIC set                              → echoes "openai" (priority)
#   P4: no keys, OLLAMA_HOST=http://127.0.0.1:1                  → echoes ""
#   P5: OLLAMA_HOST unset (default localhost:11434)              → echoes "" (or SKIP if local ollama has the model)
#   PE: empty-but-set OPENAI/ANTHROPIC keys + unreachable ollama → echoes ""
#   P6: HTTP server whose /api/tags lists the model              → echoes "ollama" (reachable AND model present)
#   P7: HTTP server whose /api/tags omits the model              → echoes "" (reachable but model NOT pulled)
set -u  # NOT -e: we want to catch failed assertions and keep going.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Source the helper directly — no sed extraction needed.
# shellcheck source=test/llm-helpers.sh
. "${SCRIPT_DIR}/llm-helpers.sh"

pass=0; fail=0; skip=0

assert_eq() {  # assert_eq <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "  PASS: $1"
        pass=$((pass + 1))
    else
        echo "  FAIL: $1 — expected [${2}], got [${3}]"
        fail=$((fail + 1))
    fi
}

assert_skip() {  # assert_skip <label> <reason>
    echo "  SKIP: $1 — $2"
    skip=$((skip + 1))
}

# Save caller's env so we can restore it between scenarios. OLLAMA_MODEL is
# saved too: detect_planner_provider's model check (_ollama_has_model) reads it,
# so a developer with OLLAMA_MODEL exported would otherwise make P6 (which
# serves llama3.2:latest) non-deterministic.
_SAVED_OPENAI="${OPENAI_API_KEY:-}"
_SAVED_ANTHROPIC="${ANTHROPIC_API_KEY:-}"
_SAVED_OLLAMA="${OLLAMA_HOST:-}"
_SAVED_OLLAMA_MODEL="${OLLAMA_MODEL:-}"

restore_env() {
    if [ -n "$_SAVED_OPENAI" ];    then export OPENAI_API_KEY="$_SAVED_OPENAI";    else unset OPENAI_API_KEY;    fi
    if [ -n "$_SAVED_ANTHROPIC" ]; then export ANTHROPIC_API_KEY="$_SAVED_ANTHROPIC"; else unset ANTHROPIC_API_KEY; fi
    if [ -n "$_SAVED_OLLAMA" ];    then export OLLAMA_HOST="$_SAVED_OLLAMA";        else unset OLLAMA_HOST;        fi
    if [ -n "$_SAVED_OLLAMA_MODEL" ]; then export OLLAMA_MODEL="$_SAVED_OLLAMA_MODEL"; else unset OLLAMA_MODEL; fi
}

# _start_tags_server <body_json> — starts a background HTTP server on an
# OS-assigned free port that returns <body_json> for every GET (so /api/tags
# is served), waits until it accepts connections, and sets two globals:
#   _TAGS_PORT       — the bound port
#   _TAGS_SERVER_PID — the server PID (for _stop_tags_server)
# Binding and port publication happen in the SAME process (port written to a
# tmpfile), so there is no TOCTOU window. The server's own stdout/stderr are
# sent to /dev/null so callers can run this without a command-substitution
# pipe staying open. Call this from the MAIN shell (not in $(...)) so the
# globals propagate.
_TAGS_SERVER_PID=""
_TAGS_PORT=""
_start_tags_server() {
    local body="$1"
    local port_file; port_file="$(mktemp)"
    _TAGS_BODY="$body" python3 -c "
import http.server, pathlib, sys, os
payload = os.environ['_TAGS_BODY'].encode()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *a): pass
srv = http.server.HTTPServer(('127.0.0.1', 0), H)
pathlib.Path(sys.argv[1]).write_text(str(srv.server_port))
srv.serve_forever()
" "$port_file" >/dev/null 2>&1 &
    _TAGS_SERVER_PID=$!

    # Wait for the server to publish its port (max ~500ms).
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ -s "$port_file" ] && break
        sleep 0.05
    done
    _TAGS_PORT="$(cat "$port_file")"
    rm -f "$port_file"

    # Wait for the server to accept connections (max ~500ms). Subshell + outer
    # 2>/dev/null reliably suppresses bash's "connect: Connection refused"
    # diagnostic on failed /dev/tcp attempts.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if (exec 3<>"/dev/tcp/127.0.0.1/${_TAGS_PORT}") 2>/dev/null; then
            break
        fi
        sleep 0.05
    done
}

# _stop_tags_server — kill the server started by _start_tags_server. No trap,
# to avoid clobbering any outer trap chain.
_stop_tags_server() {
    [ -n "$_TAGS_SERVER_PID" ] || return 0
    kill "$_TAGS_SERVER_PID" 2>/dev/null
    wait "$_TAGS_SERVER_PID" 2>/dev/null || true
    _TAGS_SERVER_PID=""
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
# If a local ollama is actually running on the default port (common on
# developer machines), SKIP — the assertion can't distinguish "default
# expansion happened correctly" from "ollama is up and responded".
# ---------------------------------------------------------------------------
echo "P5: OLLAMA_HOST unset → falls back to default localhost:11434 → empty (no local ollama with the model)"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST OLLAMA_MODEL
if _ollama_has_model 2>/dev/null; then
    assert_skip "P5 OLLAMA_HOST default fallback" \
        "local ollama on localhost:11434 has the model; default-fallback path produces 'ollama' instead of empty"
else
    out=$(detect_planner_provider 2>/dev/null || true)
    assert_eq "P5 OLLAMA_HOST default fallback" "" "$out"
fi
restore_env

# ---------------------------------------------------------------------------
# PE: empty-but-set OPENAI_API_KEY / ANTHROPIC_API_KEY treated as no-credential.
# The helper uses [ -n "${VAR:-}" ] (emptiness check) so empty strings are
# rejected. This test guards against a future regression where the helper is
# switched to a set-presence check ([ -v VAR ] or [ -n "${VAR+set}" ]) which
# would incorrectly accept an exported-but-empty key as a valid credential.
# Note: this scenario does NOT distinguish `${VAR:-}` from `${VAR-}`, since
# both expand to "" when VAR is empty-but-set — the regression guard is
# specifically against set-presence semantics, not against dropping the colon.
# ---------------------------------------------------------------------------
echo "PE: empty-but-set OPENAI_API_KEY treated as not set → empty"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST
export OPENAI_API_KEY=""
export ANTHROPIC_API_KEY=""
export OLLAMA_HOST="http://127.0.0.1:1"
out=$(detect_planner_provider 2>/dev/null || true)
assert_eq "PE empty-but-set OPENAI_API_KEY falls through" "" "$out"
restore_env

# ---------------------------------------------------------------------------
# P6: HTTP server whose /api/tags lists the wanted model → echoes "ollama".
#     Exercises the reachable-AND-model-present path of _ollama_has_model.
# ---------------------------------------------------------------------------
echo "P6: /api/tags lists llama3.2:latest → echoes ollama"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST OLLAMA_MODEL
_start_tags_server '{"models":[{"name":"llama3.2:latest"}]}'
export OLLAMA_HOST="http://127.0.0.1:${_TAGS_PORT}"
out=$(detect_planner_provider)
assert_eq "P6 echoes ollama when model present" "ollama" "$out"
_stop_tags_server
restore_env

# ---------------------------------------------------------------------------
# P7: HTTP server whose /api/tags omits the wanted model → echoes "".
#     This is the regression guard for the reachability-vs-usability fix: a
#     running ollama without the model pulled must NOT be reported usable.
# ---------------------------------------------------------------------------
echo "P7: /api/tags omits the model → echoes empty (reachable but model absent)"
unset OPENAI_API_KEY ANTHROPIC_API_KEY OLLAMA_HOST OLLAMA_MODEL
_start_tags_server '{"models":[{"name":"some-other-model:latest"}]}'
export OLLAMA_HOST="http://127.0.0.1:${_TAGS_PORT}"
out=$(detect_planner_provider)
assert_eq "P7 echoes empty when model absent" "" "$out"
_stop_tags_server
restore_env

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
if [ "$skip" -gt 0 ]; then
    echo "=== Results: $pass passed, $fail failed, $skip skipped ==="
else
    echo "=== Results: $pass passed, $fail failed ==="
fi
exit $(( fail > 0 ? 1 : 0 ))
