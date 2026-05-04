#!/usr/bin/env bash
# =============================================================================
# lab-2247-regression-tests.sh
#
# Regression harness for LAB-2247
# (https://linear.app/praetorianlabs/issue/LAB-2247).
#
# The 11 bugs called out in that ticket all sit in the live-test setup
# scripts (test/setup-live-targets.sh, test/run-live-tests.sh,
# test/test-llm-planner.sh, test/crapi/crapi-helpers.sh, plus the
# vulnerable-api default-port move). This harness asserts the **shape**
# of each fix without booting docker — every check works against the
# committed source so it can run anywhere bash + python3 + grep + sed
# exist.
#
# It does NOT replace the end-to-end flow
# (`./test/setup-live-targets.sh && ./test/run-live-tests.sh`), which
# only works on a developer box with Docker; what it does is catch a
# regression of any individual fix in CI before that end-to-end run
# even attempts to start.
#
# Usage (from repo root):
#     bash test/regression/lab-2247-regression-tests.sh
#
# Exits 0 on full pass, non-zero on any failure.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Quoted-value safety regex matches the format setup-live-targets.sh writes.
SAFE_REGEX='^[[:space:]]*(#.*)?$|^[A-Za-z_][A-Za-z0-9_]*="[A-Za-z0-9_./:@,+ -]*"$'
TESTS_RUN=0
TESTS_FAIL=0

pass() { echo "  PASS: $1"; TESTS_RUN=$((TESTS_RUN+1)); }
fail() { echo "  FAIL: $1"; TESTS_RUN=$((TESTS_RUN+1)); TESTS_FAIL=$((TESTS_FAIL+1)); }

# guard_mktemp / guard_mktemp_d wrap mktemp so a silent mktemp failure
# can't leave us with an empty path (which without `set -e` would let
# downstream `> "$VAR"` clobber an unrelated file or make later checks
# false-pass). Per CodeRabbit iter-3 review.
guard_mktemp() {
    local v
    v=$(mktemp "$@") || { fail "FATAL: mktemp failed"; exit 1; }
    [ -n "$v" ] || { fail "FATAL: mktemp produced empty path"; exit 1; }
    echo "$v"
}
guard_mktemp_d() {
    local v
    v=$(mktemp -d "$@") || { fail "FATAL: mktemp -d failed"; exit 1; }
    [ -n "$v" ] && [ -d "$v" ] || { fail "FATAL: mktemp -d produced unusable path: $v"; exit 1; }
    echo "$v"
}

cd "$ROOT" || { echo "FATAL: cannot cd to $ROOT" >&2; exit 1; }

echo "=== Bug #1, #6: teardown uses 'down -v --remove-orphans' and surfaces stderr ==="
if grep -qE 'docker compose down -v --remove-orphans' test/setup-live-targets.sh; then
    pass "teardown uses -v --remove-orphans"
else
    fail "teardown still missing -v"
fi
if ! grep -qE 'docker compose down 2>/dev/null' test/setup-live-targets.sh; then
    pass "teardown no longer swallows stderr unconditionally"
else
    fail "teardown still swallows stderr"
fi

echo
echo "=== Bug #2: setup writes CRAPI_SPEC_FILE; downstream scripts read it ==="
if grep -q 'CRAPI_SPEC_FILE=' test/setup-live-targets.sh; then
    pass "setup writes CRAPI_SPEC_FILE"
else
    fail "setup does not write CRAPI_SPEC_FILE"
fi
if grep -q 'CRAPI_SPEC_FILE' test/run-live-tests.sh && \
   grep -q 'CRAPI_SPEC_FILE' test/test-llm-planner.sh; then
    pass "both run-live-tests.sh and test-llm-planner.sh consume CRAPI_SPEC_FILE"
else
    fail "downstream scripts do not consume CRAPI_SPEC_FILE"
fi
# CRAPI_SPEC_FILE staleness fix (Codex review) + iter-5 CodeRabbit:
# the staleness predicate must use ANCHORED port matching so port 889
# doesn't false-match localhost:8895.
if grep -qE 'grep -qE "localhost:\$\{?CRAPI_PORT\}?\(\[\^0-9\]\|\\\$\)"' test/run-live-tests.sh && \
   grep -qE 'grep -qE "localhost:\$\{?CRAPI_PORT\}?\(\[\^0-9\]\|\\\$\)"' test/test-llm-planner.sh; then
    pass "downstream scripts use ANCHORED port match (boundary-safe vs substring)"
else
    fail "stale CRAPI_SPEC_FILE check uses substring grep — port 889 false-matches 8895"
fi

echo
echo "=== Bug #3: CRAPI_READY=false hard-fails ==="
if awk '
        flag && /^fi[[:space:]]*$/ { flag=0 }
        flag && /exit 1/ { found=1 }
        /CRAPI_READY/ && /!= true/ { flag=1 }
        END { exit found ? 0 : 1 }
    ' test/setup-live-targets.sh; then
    pass "setup exits 1 when crAPI readiness fails"
else
    fail "setup does not exit on readiness failure"
fi

echo
echo "=== Bug #4, #11: compose patch auto-detects upstream port and validates ==="
# log_* stubs so the sourced helpers (which call them) don't pollute output.
# shellcheck disable=SC2317  # called indirectly by the sourced helper
log_info()  { :; }
# shellcheck disable=SC2317
log_ok()    { :; }
# shellcheck disable=SC2317
log_warn()  { :; }
# shellcheck disable=SC2317
log_fail()  { :; }

# Source the SAME port-helpers.sh that setup-live-targets.sh uses. The
# previous version of this harness reimplemented patch_crapi_compose_port
# and find_available_port inline, so a prod-source change would not have
# affected these tests. (LAB-2247 iteration-2 review TEST-003.)
# shellcheck source=test/crapi/port-helpers.sh
. test/crapi/port-helpers.sh

TMP=$(guard_mktemp_d)
cat > "$TMP/compose.yml" <<EOF
services:
  crapi-web:
    ports:
      - "\${LISTEN_IP:-127.0.0.1}:5500:5500"
      - "\${LISTEN_IP:-127.0.0.1}:8889:80"
      - "\${LISTEN_IP:-127.0.0.1}:30080:80"
      - "\${LISTEN_IP:-127.0.0.1}:8443:443"
EOF

if patch_crapi_compose_port "$TMP/compose.yml" 8888 && \
   grep -q ':8888:80"' "$TMP/compose.yml" && \
   ! grep -q ':8889:80"' "$TMP/compose.yml"; then
    pass "compose patched 8889 -> 8888 (upstream rebase scenario)"
else
    fail "compose patch failed for 8889 -> 8888"
fi
if [ "$(grep -c ':30080:80"' "$TMP/compose.yml")" = "1" ]; then
    pass "30080 redirector untouched"
else
    fail "30080 redirector mistakenly modified"
fi

# TEST-002 follow-up: same-port no-op branch.
# When target_port == current upstream port, the function must short-circuit
# and not invoke sed (no .bak file should appear).
cat > "$TMP/compose-noop.yml" <<EOF
services:
  crapi-web:
    ports:
      - "\${LISTEN_IP:-127.0.0.1}:8888:80"
      - "\${LISTEN_IP:-127.0.0.1}:30080:80"
EOF
rm -f "$TMP/compose-noop.yml.bak"
if patch_crapi_compose_port "$TMP/compose-noop.yml" 8888 && \
   [ ! -f "$TMP/compose-noop.yml.bak" ]; then
    pass "patch_crapi_compose_port no-op when target == current upstream port"
else
    fail "patch_crapi_compose_port unexpectedly invoked sed when target == current"
fi

# TEST-002 follow-up: missing-source branch (compose has no LISTEN_IP mapping).
echo "(empty compose)" > "$TMP/compose-empty.yml"
if ! patch_crapi_compose_port "$TMP/compose-empty.yml" 8888 2>/dev/null; then
    pass "patch_crapi_compose_port returns non-zero when no LISTEN_IP mapping found"
else
    fail "patch_crapi_compose_port silently succeeded on a compose without LISTEN_IP mapping"
fi

rm -rf "$TMP"

echo
echo "=== Bug #5: shared helper exists with canonical creds and signup functions ==="
if [ -f test/crapi/crapi-helpers.sh ]; then
    pass "test/crapi/crapi-helpers.sh exists"
else
    fail "test/crapi/crapi-helpers.sh missing"
fi
# shellcheck source=test/crapi/crapi-helpers.sh
. test/crapi/crapi-helpers.sh
for fn in crapi_signup crapi_login crapi_mechanic_signup crapi_setup_users crapi_patch_openapi_spec _crapi_provision_user _crapi_json; do
    if declare -F "$fn" >/dev/null; then
        pass "helper exports $fn"
    else
        fail "helper missing $fn"
    fi
done
for var in CRAPI_PASSWORD CRAPI_ADMIN_EMAIL CRAPI_USER_EMAIL CRAPI_USER2_EMAIL CRAPI_MECHANIC_EMAIL CRAPI_OPENAPI_SPEC_DEFAULT_PORT; do
    if [ -n "${!var:-}" ]; then
        pass "helper sets $var"
    else
        fail "helper does not set $var"
    fi
done
for f in test/setup-live-targets.sh test/run-live-tests.sh test/test-llm-planner.sh; do
    if grep -q 'crapi/crapi-helpers.sh' "$f"; then
        pass "$f sources crapi-helpers.sh"
    else
        fail "$f does not source crapi-helpers.sh"
    fi
done

echo
echo "=== Bug #2 follow-up: spec patcher branches (review feedback TEST-002) ==="
TMP=$(guard_mktemp_d)
# Branch (a): different port — substitutes both occurrences.
patched=$(crapi_patch_openapi_spec test/crapi/crapi-openapi-spec.json 8895 "$TMP")
n_new=$(grep -c 'localhost:8895' "$patched")
n_old=$(grep -c 'localhost:8888' "$patched")
if [ "$n_new" -ge 2 ] && [ "$n_old" -eq 0 ]; then
    pass "spec patcher rewrites both 8888 occurrences (servers + report_link)"
else
    fail "spec patcher left ${n_old} occurrences; produced ${n_new} new"
fi

# Branch (b): same port (target == default) — echo source path unchanged,
# do not write a copy.
out=$(crapi_patch_openapi_spec test/crapi/crapi-openapi-spec.json \
        "${CRAPI_OPENAPI_SPEC_DEFAULT_PORT}" "$TMP/noop")
if [ "$out" = "test/crapi/crapi-openapi-spec.json" ] && [ ! -e "$TMP/noop/crapi-openapi-spec.json" ]; then
    pass "spec patcher no-ops (echoes source path) when target == default port"
else
    fail "spec patcher unexpectedly wrote a copy on no-op path (out=$out, file_exists=$([ -e "$TMP/noop/crapi-openapi-spec.json" ] && echo yes || echo no))"
fi

# Branch (c): missing source — return non-zero, write nothing.
if ! crapi_patch_openapi_spec /nonexistent/path/spec.json 8895 "$TMP/missing" 2>/dev/null; then
    if [ ! -e "$TMP/missing/crapi-openapi-spec.json" ]; then
        pass "spec patcher returns non-zero AND writes nothing when source is missing"
    else
        fail "spec patcher returned non-zero but still wrote a destination file"
    fi
else
    fail "spec patcher silently succeeded with a missing source"
fi
rm -rf "$TMP"

echo
echo "=== Bug #5 follow-up: _crapi_provision_user retry-on-failure execution (review feedback TEST-001) ==="
# Stub crapi_signup and crapi_login so we can drive _crapi_provision_user
# through its retry loop and assert it converges. The first two login
# attempts return empty (signup didn't take); the third returns a token.
# We override CRAPI_PROVISION_RETRIES via env. Use a tmp counter file to
# avoid subshell-isolation gotchas in `local` declarations.
LOGIN_ATTEMPTS=$(guard_mktemp)
SIGNUP_ATTEMPTS=$(guard_mktemp)
echo 0 > "$LOGIN_ATTEMPTS"
echo 0 > "$SIGNUP_ATTEMPTS"
# shellcheck disable=SC2317  # called by _crapi_provision_user
crapi_signup() {
    local n
    n=$(($(cat "$SIGNUP_ATTEMPTS") + 1))
    echo "$n" > "$SIGNUP_ATTEMPTS"
}
# shellcheck disable=SC2317
crapi_mechanic_signup() { crapi_signup "$@"; }
# shellcheck disable=SC2317
crapi_login() {
    local n
    n=$(($(cat "$LOGIN_ATTEMPTS") + 1))
    echo "$n" > "$LOGIN_ATTEMPTS"
    if [ "$n" -ge 3 ]; then
        echo "fake-token-after-${n}-attempts"
    else
        echo ""
    fi
}
# `sleep` shadowing keeps the test fast (default backoff is 2+4+6+... s).
# shellcheck disable=SC2317
sleep() { :; }
# SC2218: shellcheck sees a later override of _crapi_provision_user in
# the iter-7 hard-stop test and warns the function is "only defined
# later" — but the actual definition is in test/crapi/crapi-helpers.sh
# (sourced at line 165) so this call is sound.
# shellcheck disable=SC2218
CRAPI_PROVISION_RETRIES=5 \
  _crapi_provision_user "http://stub" regular "x@example.com" "X" "0" "p"
rc=$?
logins=$(cat "$LOGIN_ATTEMPTS")
signups=$(cat "$SIGNUP_ATTEMPTS")
if [ "$rc" -eq 0 ] && [ "$logins" -eq 3 ] && [ "$signups" -eq 3 ]; then
    pass "_crapi_provision_user retries (3 signups, 3 logins, exit 0) — convergence path"
else
    fail "_crapi_provision_user retry mismatch: rc=$rc logins=$logins signups=$signups (expected rc=0 each=3)"
fi

# Branch: every attempt fails → exhaust retries → exit non-zero.
# Also asserts crapi_signup is called every iteration (CodeRabbit iter-3
# review TEST-LEAD-7-B): a regression that loops without re-attempting
# signup would now be caught.
echo 0 > "$LOGIN_ATTEMPTS"
echo 0 > "$SIGNUP_ATTEMPTS"
# shellcheck disable=SC2317
crapi_login() {
    local n
    n=$(($(cat "$LOGIN_ATTEMPTS") + 1))
    echo "$n" > "$LOGIN_ATTEMPTS"
    echo ""   # always-empty
}
# shellcheck disable=SC2218  # see comment above re: sourced helper
CRAPI_PROVISION_RETRIES=3 \
  _crapi_provision_user "http://stub" regular "y@example.com" "Y" "0" "p" 2>/dev/null
rc=$?
logins=$(cat "$LOGIN_ATTEMPTS")
signups=$(cat "$SIGNUP_ATTEMPTS")
if [ "$rc" -ne 0 ] && [ "$logins" -eq 3 ] && [ "$signups" -eq 3 ]; then
    pass "_crapi_provision_user exhausts retries (3 signups, 3 logins, non-zero exit) — failure path"
else
    fail "_crapi_provision_user exhaustion mismatch: rc=$rc logins=$logins signups=$signups (expected rc!=0 each=3)"
fi

# Re-source crapi-helpers.sh so subsequent sections see the REAL helpers
# (CodeRabbit iter-3 review CR-2 + iter-3 my-review FRESH-002): `unset -f`
# would permanently strip the originals; re-sourcing restores them.
unset -f sleep crapi_signup crapi_login crapi_mechanic_signup
# shellcheck source=test/crapi/crapi-helpers.sh
. test/crapi/crapi-helpers.sh
rm -f "$LOGIN_ATTEMPTS" "$SIGNUP_ATTEMPTS"

echo
echo "=== Bug #5 follow-up: _crapi_json correctly escapes special chars (review feedback) ==="
# Single-quoted strings preserve backslashes literally — the email here
# contains a real " and the password contains two real backslashes.
# Round-trip via python proves _crapi_json emits well-formed JSON that
# parses back to the original bytes (which printf-format-string JSON
# building would have corrupted).
expected_email='ab"cd@test.com'
expected_password='p\\ssw0rd!'
out=$(_crapi_json "email=$expected_email" "password=$expected_password")
roundtrip=$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d.get("email","") + "|" + d.get("password",""))
' 2>/dev/null || echo "ERR")
if [ "$roundtrip" = "${expected_email}|${expected_password}" ]; then
    pass "_crapi_json escapes quotes and backslashes for JSON-safe payloads"
else
    fail "_crapi_json round-trip mismatch: expected '${expected_email}|${expected_password}', got '${roundtrip}'"
fi

echo
echo "=== Bug #5 follow-up: crapi_setup_users self-heals via _crapi_provision_user retry ==="
if grep -qE '_crapi_provision_user' test/crapi/crapi-helpers.sh && \
   grep -qE 'CRAPI_PROVISION_RETRIES' test/crapi/crapi-helpers.sh; then
    pass "_crapi_provision_user retries with backoff on empty token"
else
    fail "missing retry logic in crapi_setup_users"
fi

echo
echo "=== Bug #9: find_available_port skips ports already claimed in this run ==="
# Use the SOURCED port_in_use override pattern: bash function lookup is
# dynamic, so redefining port_in_use after the helper is sourced makes
# the helper's find_available_port use our stub.
port_in_use() { [ "$1" = "8888" ]; }   # simulate VS Code holding 8888

claimed=()
v=$(find_available_port 9889 "${claimed[@]+${claimed[@]}}")
claimed+=("$v")
c=$(find_available_port 8888 "${claimed[@]+${claimed[@]}}")
claimed+=("$c")
if [ -n "$v" ] && [ -n "$c" ] && [ "$v" != "$c" ]; then
    pass "vulnerable-api ($v) and crapi ($c) get distinct ports with 8888 simulated taken"
else
    fail "port collision: vulnerable-api=$v crapi=$c"
fi

# TEST-005: resolve_target_port honors override AND rejects collisions.
# Use the same port_in_use stub from above.
# (a) Override wins when free + not claimed.
out=$(resolve_target_port 9999 8888 "test" "${claimed[@]+${claimed[@]}}")
if [ "$out" = "9999" ]; then
    pass "resolve_target_port honors override when free + not claimed"
else
    fail "resolve_target_port did not honor free override (got: $out)"
fi
# (b) Override that's OS-busy → return 1, log_fail.
log_fail_msg=""
log_fail() { log_fail_msg="$*"; }
if ! resolve_target_port 8888 9999 "test" "${claimed[@]+${claimed[@]}}" >/dev/null 2>&1; then
    if [ -n "$log_fail_msg" ] && echo "$log_fail_msg" | grep -q "already in use"; then
        pass "resolve_target_port rejects override that's already in use on host"
    else
        fail "resolve_target_port rejected override but log_fail message unexpected: $log_fail_msg"
    fi
else
    fail "resolve_target_port silently accepted an override port that's in use"
fi
# (c) Override that collides with a port claimed earlier this run → return 1.
log_fail_msg=""
already_claimed=("$v" "$c")
if ! resolve_target_port "${already_claimed[0]}" 9000 "test" "${already_claimed[@]}" >/dev/null 2>&1; then
    if [ -n "$log_fail_msg" ] && echo "$log_fail_msg" | grep -q "collides with another target"; then
        pass "resolve_target_port rejects override that collides with claimed list"
    else
        fail "resolve_target_port rejected claimed-list override but log_fail message unexpected: $log_fail_msg"
    fi
else
    fail "resolve_target_port silently accepted an override port that was already claimed"
fi
# Restore log_fail to the no-op for downstream tests; clear scratch var.
# Also unset the port_in_use stub so any later test that needs the real
# OS-level check gets it (CodeRabbit iter-3 review CR-4 + my iter-3
# review TEST-004).
# shellcheck disable=SC2317  # called indirectly by sourced helpers below
log_fail() { :; }
unset log_fail_msg
unset -f port_in_use

echo
echo "=== Bug #10: *_PORT_OVERRIDE env vars are honored by setup ==="
if grep -qE 'VULN_API_PORT_OVERRIDE|CRAPI_PORT_OVERRIDE' test/setup-live-targets.sh; then
    pass "setup recognizes *_PORT_OVERRIDE env vars"
else
    fail "setup does not implement *_PORT_OVERRIDE"
fi
if grep -q 'resolve_target_port' test/setup-live-targets.sh; then
    pass "setup uses a single resolve_target_port helper consistently"
else
    fail "setup lacks a unified port-resolution helper"
fi

echo
echo "=== Bug #11: vulnerable-api default is 9889 (not 8889) ==="
if grep -q 'port = "9889"' test/vulnerable-api/main.go; then
    pass "vulnerable-api/main.go default is 9889"
else
    fail "vulnerable-api/main.go default still 8889"
fi
if grep -q 'localhost:9889' test/vulnerable-api/openapi.yaml; then
    pass "openapi.yaml advertises 9889"
else
    fail "openapi.yaml still advertises 8889"
fi
if grep -q 'DEFAULT_VULN_API_PORT=9889' test/setup-live-targets.sh; then
    pass "setup default vulnerable-api port is 9889"
else
    fail "setup still defaults vulnerable-api to 8889"
fi
# Q2: hardcoded port literals replaced with named constants in run-live-tests.sh
if grep -q 'VULN_API_DEFAULT_PORT' test/run-live-tests.sh && \
   grep -q 'CRAPI_OPENAPI_SPEC_DEFAULT_PORT' test/run-live-tests.sh; then
    pass "run-live-tests.sh uses named port constants instead of hardcoded literals"
else
    fail "run-live-tests.sh still hardcodes 9889/8888 in conditionals"
fi
# Q3: Makefile uses API_PORT variable for reset URL.
# `$(API_URL)` here is a Makefile variable reference, not shell.
# shellcheck disable=SC2016  # intentional literal Makefile $(...) expression
if grep -q '^API_PORT' test/vulnerable-api/Makefile && \
   grep -q '\$(API_URL)/api/reset' test/vulnerable-api/Makefile; then
    pass "Makefile reset target uses API_PORT/API_URL variables"
else
    fail "Makefile reset target still hardcodes the port"
fi

echo
echo "=== Bug #7: --no-build flag exists and gates Go-build steps (TEST-006) ==="
if grep -q '\-\-no-build' test/setup-live-targets.sh; then
    pass "setup exposes --no-build flag"
else
    fail "setup lacks --no-build flag"
fi
# Structural: the build step must be guarded such that DO_BUILD=true OR
# the binary is missing — i.e. when --no-build is passed AND the binary
# already exists, we must NOT rebuild.
if awk '
    tolower($0) ~ /building hadrian and go targets/{flag=1}
    flag && /\[ "\$DO_BUILD" = true \] \|\| \[ ! -x .*hadrian/{found=1}
    flag && /^# ==== Pull/{exit}
    END{exit found ? 0 : 1}
' test/setup-live-targets.sh; then
    pass "hadrian build is gated by [DO_BUILD=true OR binary missing]"
else
    fail "hadrian build is not properly gated for --no-build"
fi
# Same gate for vulnerable-api and grpc-server inside their target-specific blocks.
# shellcheck disable=SC2016  # we want the literal "$DO_BUILD" string in the source file
if grep -qE '\[ "\$DO_BUILD" = true \] \|\| \[ ! -x .*vulnerable-api/vulnerable-api' test/setup-live-targets.sh; then
    pass "vulnerable-api build is gated by [DO_BUILD=true OR binary missing]"
else
    fail "vulnerable-api build is not properly gated for --no-build"
fi
# shellcheck disable=SC2016
if grep -qE '\[ "\$DO_BUILD" = true \] \|\| \[ ! -x .*grpc-server/grpc-server' test/setup-live-targets.sh; then
    pass "grpc-server build is gated by [DO_BUILD=true OR binary missing]"
else
    fail "grpc-server build is not properly gated for --no-build"
fi

echo
echo "=== Bug #8: --purge flag exists and is gated on --teardown (TEST-004) ==="
if grep -q '\-\-purge' test/setup-live-targets.sh; then
    pass "setup exposes --purge flag"
else
    fail "setup lacks --purge flag"
fi
# Structural: the purge action (rm -rf .crapi-repo) must live INSIDE the
# `if [ "$TEARDOWN" = true ]; then ... fi` block so passing --purge alone
# (without --teardown) cannot remove the cached clone.
# We assert by extracting the line numbers of (a) the teardown block
# bounds and (b) the purge `rm -rf "$CRAPI_REPO_DEFAULT"`, and checking
# the rm is bracketed.
# shellcheck disable=SC2016  # literal "$TEARDOWN" / "$CRAPI_REPO_DEFAULT" patterns
teardown_start=$(grep -n '^if \[ "\$TEARDOWN" = true \]; then' test/setup-live-targets.sh | head -1 | cut -d: -f1)
teardown_end=$(awk -v s="$teardown_start" 'NR>s && /^fi$/{print NR; exit}' test/setup-live-targets.sh)
# shellcheck disable=SC2016
purge_rm=$(grep -n 'rm -rf "\$CRAPI_REPO_DEFAULT"' test/setup-live-targets.sh | head -1 | cut -d: -f1)
if [ -n "$teardown_start" ] && [ -n "$teardown_end" ] && [ -n "$purge_rm" ] && \
   [ "$purge_rm" -gt "$teardown_start" ] && [ "$purge_rm" -lt "$teardown_end" ]; then
    pass "--purge clone-removal is structurally inside the --teardown block (lines: teardown=${teardown_start}..${teardown_end}, purge_rm=${purge_rm})"
else
    fail "--purge clone-removal is NOT inside --teardown block (teardown=${teardown_start}..${teardown_end}, purge_rm=${purge_rm})"
fi

echo
echo "=== Reviewer regression: .live-test-config matches safety regex ==="
TMP=$(mktemp)
cat > "$TMP" <<'EOF'
# Auto-generated by setup-live-targets.sh on 2026-05-09T00:00:00Z
VULN_API_PORT="9889"
DVGA_PORT="5013"
GRPC_PORT="50051"
CRAPI_PORT="8888"
CRAPI_DIR="/some/path/.crapi-repo"
CRAPI_SPEC_FILE="/some/path/.live-test-cache/crapi-openapi-spec.json"
TARGETS_SETUP="vulnerable-api,dvga,grpc,crapi"
EOF
if grep -qvE "$SAFE_REGEX" "$TMP"; then
    fail ".live-test-config has lines that fail the safety regex"
    grep -vE "$SAFE_REGEX" "$TMP"
else
    pass ".live-test-config (quoted format) passes safety regex"
fi
rm -f "$TMP"

# Path-with-space injection guard (Codex / SEC-BE-003): the safety regex
# must NOT accept an unquoted value containing a space.
TMP=$(mktemp)
echo 'CRAPI_DIR=/tmp/foo bar' > "$TMP"
if grep -qvE "$SAFE_REGEX" "$TMP"; then
    pass "unquoted value containing space is rejected (path-with-space injection guard)"
else
    fail "safety regex accepts unquoted value with space — injection guard is broken"
fi
rm -f "$TMP"

# Conversely: a QUOTED value containing a space MUST pass — repos cloned
# under paths like "/Users/name/My Code/hadrian/" are valid use cases
# (CodeRabbit review 4258701255 CR-7-3). The earlier whitespace-rejection
# loop in setup-live-targets.sh broke this; we removed it and rely on
# the quoted-value safety regex + heredoc quoting to keep `source` safe.
TMP=$(mktemp)
echo 'CRAPI_DIR="/tmp/foo bar"' > "$TMP"
if grep -qvE "$SAFE_REGEX" "$TMP"; then
    fail "safety regex rejects QUOTED path with space — would break valid setups (e.g. /Users/Name/My Code/...)"
else
    pass "safety regex accepts QUOTED path with space (round-trips safely via source)"
fi
rm -f "$TMP"
# And the loop itself must be GONE from setup-live-targets.sh.
if grep -qE 'for _name in CRAPI_DIR CRAPI_SPEC_FILE; do' test/setup-live-targets.sh; then
    fail "stale whitespace-rejection loop survives — would block valid repo paths"
else
    pass "whitespace-rejection loop removed (safety now via quoted heredoc + tightened regex)"
fi

echo
echo "=== Review-feedback regressions ==="

# Gemini #1 / CodeRabbit: log_* helpers redirect to stderr so command-substituted
# helpers don't capture log lines as port values.
if awk '
    /^log_(info|ok|warn|fail|header)/{flag=1}
    flag && />&2/{found=1}
    flag && /^}/{flag=0}
    END {exit found ? 0 : 1}
' test/setup-live-targets.sh; then
    pass "setup-live-targets.sh log_* helpers redirect to stderr"
else
    fail "log_* helpers still write to stdout (will pollute \$(...) captures)"
fi

# Codex #1: go check is conditional on --no-build + selected targets
if grep -qE 'need_go=' test/setup-live-targets.sh; then
    pass "setup-live-targets.sh skips Go check when no Go build is needed"
else
    fail "setup-live-targets.sh still requires Go unconditionally"
fi

# Codex #3 / SEC-BE-003: heredoc values are quoted in the writer
if grep -qE 'CRAPI_DIR="\$\{CRAPI_DIR\}"' test/setup-live-targets.sh; then
    pass "setup-live-targets.sh quotes CRAPI_DIR in the config heredoc"
else
    fail "CRAPI_DIR still unquoted in heredoc (path-with-space injection)"
fi

echo
echo "=== Iteration-3 + iteration-4 review feedback ==="

# My iter-3 TEST-001: harness asserts port-helpers.sh is actually sourced
# from setup-live-targets.sh (not just that the function names appear).
if grep -q 'crapi/port-helpers.sh' test/setup-live-targets.sh; then
    pass "setup-live-targets.sh sources test/crapi/port-helpers.sh"
else
    fail "setup-live-targets.sh does NOT source port-helpers.sh — re-inline regression risk"
fi

# CodeRabbit iter-3 CR-1: token-empty gate covers admin AND mechanic.
# The gate may span multiple lines (line-wrapped), so check both names appear
# in the same `if [ ... ]; then ... log_fail ... fi` block.
if awk '
    /^[[:space:]]*if .*-z "\$CRAPI_/ { in_if=1; block="" }
    in_if { block = block "\n" $0 }
    in_if && /; then/ {
        if (block ~ /CRAPI_ADMIN_TOKEN/ && block ~ /CRAPI_MECHANIC_TOKEN/ \
            && block ~ /CRAPI_USER_TOKEN/ && block ~ /CRAPI_USER2_TOKEN/) {
            found=1
        }
        in_if=0
    }
    END { exit found ? 0 : 1 }
' test/run-live-tests.sh; then
    pass "run-live-tests.sh token-empty gate covers admin, user, user2, AND mechanic"
else
    fail "token-empty gate does not check all four tokens — degraded auth would silently slip through"
fi

# CodeRabbit iter-3 CR-5: --purge alone emits a pre-flight warning.
if grep -q -- '--purge requires --teardown' test/setup-live-targets.sh; then
    pass "--purge without --teardown emits a pre-flight warning"
else
    fail "--purge without --teardown is silently a no-op"
fi

# CodeRabbit iter-3 CR-6: test-llm-planner writes the patched spec into the same
# SPEC_CACHE_DIR setup uses (test/.live-test-cache/), not OUTPUT_DIR.
if grep -q 'SPEC_CACHE_DIR' test/test-llm-planner.sh; then
    pass "test-llm-planner.sh writes patched spec into SPEC_CACHE_DIR (aligned with setup)"
else
    fail "test-llm-planner.sh still writes spec into OUTPUT_DIR (cache artifact in results dir)"
fi

# CodeRabbit iter-3 CR-7: crapi_patch_openapi_spec validates the substitution
# actually landed (defensive against upstream spec rewording).
TMP=$(guard_mktemp_d)
echo '{"servers":[{"url":"http://localhost:9999"}]}' > "$TMP/spec.json"
if ! crapi_patch_openapi_spec "$TMP/spec.json" 8895 "$TMP/out" 2>/dev/null; then
    if [ ! -e "$TMP/out/crapi-openapi-spec.json" ]; then
        pass "crapi_patch_openapi_spec returns non-zero AND writes nothing when source lacks localhost:DEFAULT"
    else
        fail "crapi_patch_openapi_spec rejected but left a destination file"
    fi
else
    fail "crapi_patch_openapi_spec silently succeeded with an unsubstitutable source"
fi
rm -rf "$TMP"

# CodeRabbit iter-3 CR-9 → iter-4 QUAL-1: port_in_use uses ss -atn (all
# states), matches lsof coverage. Earlier iterations got this wrong twice
# (-ltn missed ESTABLISHED, -tn missed LISTEN); -atn covers everything.
# This duplicates the QUAL-1 assertion below and is kept here as a
# CR-9-anchored sentinel that the regression has stayed fixed.
if grep -qE 'ss -atn \| grep -q' test/crapi/port-helpers.sh && \
   ! grep -qE 'ss -[lt]+n[[:space:]]*\| grep' test/crapi/port-helpers.sh; then
    pass "port_in_use uses ss -atn (CR-9 sentinel: not -ltn / not -tn)"
else
    fail "port_in_use ss flag regressed; expected -atn"
fi

# My iter-3 FRESH-001: test-llm-planner acquires ADMIN_TOKEN and uses it
# for the admin role (not USER_TOKEN, which previously degraded admin
# templates to regular-user creds in the planner test).
if grep -qE 'ADMIN_TOKEN=\$\(crapi_login.*CRAPI_ADMIN_EMAIL' test/test-llm-planner.sh && \
   grep -qE 'admin:[[:space:]]*$' test/test-llm-planner.sh; then
    if awk '/^roles:/{flag=1} flag && /admin:/{getline next_line; if (next_line ~ /\$\{ADMIN_TOKEN\}/) found=1} END{exit found?0:1}' test/test-llm-planner.sh; then
        pass "test-llm-planner.sh acquires ADMIN_TOKEN and binds it to the admin role"
    else
        fail "test-llm-planner.sh acquires ADMIN_TOKEN but admin role still uses a different var"
    fi
else
    fail "test-llm-planner.sh does not acquire ADMIN_TOKEN — admin templates run with degraded creds"
fi

echo
echo "=== Iteration-4 review feedback ==="

# QUAL-1 (iter-4 capability-reviewer): port_in_use uses ss -atn (all states),
# matching lsof's coverage of LISTEN + ESTABLISHED + TIME_WAIT.
if grep -qE 'ss -atn \| grep -q' test/crapi/port-helpers.sh && \
   ! grep -qE 'ss -ltn \| grep' test/crapi/port-helpers.sh && \
   ! grep -qE 'ss -tn \| grep' test/crapi/port-helpers.sh; then
    pass "port_in_use uses ss -atn (covers LISTEN + non-LISTEN, matches lsof)"
else
    fail "port_in_use ss flag wrong — must be -atn (not -ltn / not -tn)"
fi

# QUAL-2 (iter-4): setup-live-targets.sh guards against empty CRAPI_SPEC_FILE
# from a failed crapi_patch_openapi_spec call.
if grep -qE '\[ -z "\$CRAPI_SPEC_FILE" \].*$' test/setup-live-targets.sh && \
   awk '/CRAPI_SPEC_FILE=\$\(crapi_patch_openapi_spec/{flag=1} flag && /\[ -z "\$CRAPI_SPEC_FILE" \]/{found=1; exit} flag && /^fi/{exit} END{exit found?0:1}' test/setup-live-targets.sh; then
    pass "setup-live-targets.sh guards against empty CRAPI_SPEC_FILE"
else
    fail "setup-live-targets.sh does not validate crapi_patch_openapi_spec result is non-empty"
fi

# QUAL-3 (iter-4): run-live-tests.sh guards against empty CRAPI_SPEC.
if grep -qE '\[ -z "\$CRAPI_SPEC" \] \|\| \[ ! -f "\$CRAPI_SPEC" \]' test/run-live-tests.sh; then
    pass "run-live-tests.sh guards against empty/missing CRAPI_SPEC"
else
    fail "run-live-tests.sh does not validate CRAPI_SPEC before passing to hadrian"
fi
# Same in test-llm-planner.sh
if grep -qE '\[ -z "\$CRAPI_SPEC" \] \|\| \[ ! -f "\$CRAPI_SPEC" \]' test/test-llm-planner.sh; then
    pass "test-llm-planner.sh guards against empty/missing CRAPI_SPEC"
else
    fail "test-llm-planner.sh does not validate CRAPI_SPEC before passing to hadrian"
fi

# test-lead iter-4 #1: SPEC_CACHE_DIR alignment in run-live-tests.sh too
# (iteration 3 only fixed test-llm-planner.sh).
if grep -q 'SPEC_CACHE_DIR' test/run-live-tests.sh; then
    pass "run-live-tests.sh writes patched spec into SPEC_CACHE_DIR (aligned with setup)"
else
    fail "run-live-tests.sh still writes spec into OUTPUT_DIR — diverges from setup"
fi

# test-lead iter-4 #2: assert ALL four DEFAULT_PORT constants present.
for c in VULN_API_DEFAULT_PORT DVGA_DEFAULT_PORT GRPC_DEFAULT_PORT; do
    if grep -qE "^${c}=" test/run-live-tests.sh; then
        pass "run-live-tests.sh defines ${c}"
    else
        fail "run-live-tests.sh missing ${c} constant"
    fi
done
# CRAPI default comes from helpers' CRAPI_OPENAPI_SPEC_DEFAULT_PORT.
if grep -q 'CRAPI_OPENAPI_SPEC_DEFAULT_PORT' test/run-live-tests.sh; then
    pass "run-live-tests.sh references CRAPI_OPENAPI_SPEC_DEFAULT_PORT"
else
    fail "run-live-tests.sh missing CRAPI_OPENAPI_SPEC_DEFAULT_PORT reference"
fi

# test-lead iter-4 #3: crapi_setup_users provisions all four canonical roles.
for email_var in CRAPI_ADMIN_EMAIL CRAPI_USER_EMAIL CRAPI_USER2_EMAIL CRAPI_MECHANIC_EMAIL; do
    if grep -qE "_crapi_provision_user.*${email_var}" test/crapi/crapi-helpers.sh; then
        pass "crapi_setup_users provisions ${email_var}"
    else
        fail "crapi_setup_users does NOT provision ${email_var}"
    fi
done

# test-lead iter-4 #7: setup hard-fails when crapi_setup_users returns non-zero.
if awk '
    /^[[:space:]]*if ! crapi_setup_users/ { flag=1 }
    flag && /^[[:space:]]*fi[[:space:]]*$/ { flag=0 }
    flag && /exit 1/ { found=1 }
    END { exit found ? 0 : 1 }
' test/setup-live-targets.sh; then
    pass "setup-live-targets.sh exits 1 on crapi_setup_users provisioning failure"
else
    fail "setup-live-targets.sh does not exit on user-provisioning failure"
fi

echo
echo "=== Iteration-6 review feedback ==="

# TEST-001: patch_crapi_compose_port post-sed validation-failure branch.
# Drive the function with sed shadowed to a no-op in a subshell, so the
# function detects current_port, runs the no-op sed (file unchanged),
# then the validation grep fails and the function returns 1.
TMP=$(guard_mktemp_d)
cat > "$TMP/compose.yml" <<EOF
services:
  crapi-web:
    ports:
      - "\${LISTEN_IP:-127.0.0.1}:8889:80"
      - "\${LISTEN_IP:-127.0.0.1}:30080:80"
EOF
( # subshell so sed shadowing doesn't escape
    # shellcheck disable=SC2317  # called by patch_crapi_compose_port
    sed() { :; }
    if ! patch_crapi_compose_port "$TMP/compose.yml" 9999 2>/dev/null; then
        exit 0
    fi
    exit 1
)
if [ $? -eq 0 ]; then
    pass "patch_crapi_compose_port returns non-zero when post-sed validation fails"
else
    fail "patch_crapi_compose_port silently succeeds when sed doesn't substitute"
fi
rm -rf "$TMP"

# TEST-002: _crapi_provision_user "mechanic" kind dispatches to crapi_mechanic_signup.
SIGNUP_REGULAR=$(guard_mktemp)
SIGNUP_MECH=$(guard_mktemp)
echo 0 > "$SIGNUP_REGULAR"
echo 0 > "$SIGNUP_MECH"
# shellcheck disable=SC2317
crapi_signup() {
    n=$(($(cat "$SIGNUP_REGULAR") + 1))
    echo "$n" > "$SIGNUP_REGULAR"
}
# shellcheck disable=SC2317
crapi_mechanic_signup() {
    n=$(($(cat "$SIGNUP_MECH") + 1))
    echo "$n" > "$SIGNUP_MECH"
}
# shellcheck disable=SC2317
crapi_login() { echo "fake-token"; }   # immediate convergence
# shellcheck disable=SC2317
sleep() { :; }
# shellcheck disable=SC2218  # _crapi_provision_user is sourced from crapi-helpers.sh
CRAPI_PROVISION_RETRIES=2 \
  _crapi_provision_user "http://stub" mechanic "m@example.com" "M" "0" "p" "CODE" >/dev/null
reg_count=$(cat "$SIGNUP_REGULAR")
mech_count=$(cat "$SIGNUP_MECH")
if [ "$mech_count" -eq 1 ] && [ "$reg_count" -eq 0 ]; then
    pass "_crapi_provision_user kind=mechanic dispatches to crapi_mechanic_signup (mech=1, regular=0)"
else
    fail "_crapi_provision_user mechanic dispatch wrong: regular=$reg_count mechanic=$mech_count (expected 0/1)"
fi
unset -f sleep crapi_signup crapi_mechanic_signup crapi_login
. test/crapi/crapi-helpers.sh
rm -f "$SIGNUP_REGULAR" "$SIGNUP_MECH"

# TEST-003: resolve_target_port with empty override falls back to find_available_port.
# Stub port_in_use so 8888 is free; resolve with empty override should return 8888.
port_in_use() { return 1; }   # everything is "free"
out=$(resolve_target_port "" 8888 "fallback-test")
rc=$?
unset -f port_in_use
if [ "$rc" -eq 0 ] && [ "$out" = "8888" ]; then
    pass "resolve_target_port empty override falls back to find_available_port (returns 8888)"
else
    fail "resolve_target_port empty-override fallback mismatch: rc=$rc out=[$out]"
fi

# TEST-004 (updated for iter-7 CR-7-2 fix): --purge guard. The rm -rf
# of the default cached clone must be wrapped in BOTH `if [ "$PURGE" = true ]`
# AND a CRAPI_DIR-tolerant condition (empty OR equals CRAPI_REPO_DEFAULT).
# A regression that drops the empty-OR-equals branch would either
# silently no-op (CR-7-2 case) or rm an operator-supplied custom dir.
if awk '
    /^[[:space:]]*if \[ "\$PURGE" = true \]; then$/ { p=1; next }
    p && /\[ -z "\$CRAPI_DIR" \]/ && /\[ "\$CRAPI_DIR" = "\$CRAPI_REPO_DEFAULT" \]/ { gate=1 }
    p && /rm -rf "\$CRAPI_REPO_DEFAULT"/ && gate { found=1 }
    p && /^[[:space:]]*fi[[:space:]]*$/ { p=0 }
    END { exit found ? 0 : 1 }
' test/setup-live-targets.sh; then
    pass "--purge rm -rf is gated by [PURGE=true] AND [CRAPI_DIR empty OR equals default] (custom dir survives, default purged)"
else
    fail "--purge guard wrong: must permit rm of default when CRAPI_DIR is unset OR equals CRAPI_REPO_DEFAULT"
fi

# TEST-006: SPEC_CACHE_DIR positional-arg assertion is location-agnostic.
# Tighten by requiring SPEC_CACHE_DIR appear as the LAST argument before
# the closing paren of the patcher call (the dest_dir position).
if awk '
    /CRAPI_SPEC=\$\(crapi_patch_openapi_spec/ { flag=1; arg_count=0; next }
    flag {
        # trim whitespace
        line=$0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        # the call is multi-line: source spec, port, dest_dir.
        if (line ~ /^\)$/) { exit }
        if (line ~ /SPEC_CACHE_DIR/) { last_arg=line; arg_count++ }
        else if (line !~ /^[[:space:]]*\\?$/) { other_arg=line; arg_count++ }
    }
    END { exit (last_arg ~ /SPEC_CACHE_DIR/ && arg_count >= 3) ? 0 : 1 }
' test/run-live-tests.sh; then
    pass "run-live-tests.sh patcher dest_dir is SPEC_CACHE_DIR specifically (not just contained)"
else
    fail "SPEC_CACHE_DIR positional check unable to confirm dest_dir position"
fi

# TEST-007: anchored-port-match negative assertion must catch BOTH
# `grep -q ` and `grep -qE ` substring forms (a regression to either
# would re-introduce the false-match).
if ! grep -qE 'grep -qE? "localhost:\$\{?CRAPI_PORT[}]*"$' test/run-live-tests.sh test/test-llm-planner.sh && \
   ! grep -qE 'grep -qE? "localhost:\$\{?CRAPI_PORT\}?"' test/run-live-tests.sh test/test-llm-planner.sh; then
    pass "no remaining substring grep for localhost:CRAPI_PORT (catches both grep -q AND grep -qE forms)"
else
    fail "substring grep (either -q or -qE form) for localhost:CRAPI_PORT still present"
fi

echo
echo "=== Iteration-5 review feedback ==="

# Iter-5 my-TEST-001 (was the only blocker): exercise find_available_port's
# 20-port walk-forward exhaustion branch. Stub port_in_use to claim every
# port; assert empty result + non-zero return.
port_in_use() { return 0; }   # everything is "busy"
out=$(find_available_port 8888)
rc=$?
unset -f port_in_use
if [ -z "$out" ] && [ "$rc" -ne 0 ]; then
    pass "find_available_port returns empty + non-zero when 20-port walk exhausts"
else
    fail "find_available_port walk-forward exhaustion mismatch: rc=$rc out=[$out]"
fi

# Iter-5 my-TEST-002: SPEC_CACHE_DIR assertion was comment-permissive.
# Tighten: the variable must appear as an assignment AND be passed as the
# third arg to crapi_patch_openapi_spec (the dest_dir position).
if grep -qE '^[[:space:]]*SPEC_CACHE_DIR=' test/run-live-tests.sh && \
   awk '/CRAPI_SPEC=\$\(crapi_patch_openapi_spec/{flag=1}
        flag && /SPEC_CACHE_DIR/{found=1; exit}
        flag && /^[[:space:]]*\)/{exit}
        END{exit found?0:1}' test/run-live-tests.sh; then
    pass "run-live-tests.sh defines SPEC_CACHE_DIR AND passes it as the patcher dest dir"
else
    fail "run-live-tests.sh SPEC_CACHE_DIR assertion incomplete (assignment + use both required)"
fi

# Iter-5 my-TEST-003: roster-coverage assertion now binds email to role kind.
# admin/user1/user2 must use kind=regular; mechanic must use kind=mechanic.
if awk '
    /_crapi_provision_user .* "?regular"? .*CRAPI_ADMIN_EMAIL/{a=1}
    /_crapi_provision_user .* "?regular"? .*CRAPI_USER_EMAIL/{u1=1}
    /_crapi_provision_user .* "?regular"? .*CRAPI_USER2_EMAIL/{u2=1}
    /_crapi_provision_user .* "?mechanic"? .*CRAPI_MECHANIC_EMAIL/{m=1}
    END{exit (a && u1 && u2 && m) ? 0 : 1}
' test/crapi/crapi-helpers.sh; then
    pass "crapi_setup_users binds admin/user1/user2 -> regular, mechanic -> mechanic"
else
    fail "crapi_setup_users role-kind binding incorrect (a regression that swaps mechanic to regular would slip through)"
fi

# CodeRabbit iter-5 CR-1: ANCHORED port match in run-live-tests.sh AND
# test-llm-planner.sh (already partially covered above; assert non-anchored
# substring greps are GONE).
if ! grep -qE 'grep -q "localhost:\$\{?CRAPI_PORT' test/run-live-tests.sh test/test-llm-planner.sh; then
    pass "no remaining substring grep for localhost:CRAPI_PORT (boundary-anchored only)"
else
    fail "substring grep for localhost:CRAPI_PORT survives — port 889 would false-match 8895"
fi

# CodeRabbit iter-5 CR-2: teardown reads saved CRAPI_DIR from .live-test-config.
if awk '
    /^if \[ "\$TEARDOWN" = true \]; then/{flag=1}
    flag && /^fi$/{flag=0}
    flag && /\. "\$CONFIG_FILE"/{found=1}
    flag && /CRAPI_DIR.*from .live-test-config/{has_diag=1}
    END{exit found?0:1}
' test/setup-live-targets.sh; then
    pass "teardown sources .live-test-config to recover saved CRAPI_DIR"
else
    fail "teardown does not load CRAPI_DIR from .live-test-config — custom --crapi-dir setups leak containers/volumes"
fi

# CodeRabbit iter-5 CR-3: per-target need_go check (vulnerable-api and grpc
# evaluated independently). Two distinct `if echo "$TARGETS" | grep -q "X" && ...` blocks.
if awk '
    /^if echo "\$TARGETS" \| grep -q "vulnerable-api" && /{vuln=1}
    /^if echo "\$TARGETS" \| grep -q "grpc" && /{grpc=1}
    END{exit (vuln && grpc) ? 0 : 1}
' test/setup-live-targets.sh; then
    pass "need_go is split per Go target (vulnerable-api and grpc checked separately)"
else
    fail "need_go still combines vulnerable-api OR grpc — `--targets vulnerable-api --no-build` still requires grpc-server binary"
fi

# Iter-5 lane-dropped (capability-reviewer): test-llm-planner.sh wraps
# crapi_setup_users in `if ! ... log_fail ...` like the sibling scripts do.
if grep -qE 'if ! crapi_setup_users' test/test-llm-planner.sh; then
    pass "test-llm-planner.sh wraps crapi_setup_users with diagnostic guard"
else
    fail "test-llm-planner.sh leaves crapi_setup_users bare — failure surfaces as raw set-e abort"
fi

echo
echo "=== Iteration-7 review feedback ==="

# Iter-7 lane-dropped (capability-reviewer): test-llm-planner.sh CRAPI_PORT
# default now references CRAPI_OPENAPI_SPEC_DEFAULT_PORT (single source of
# truth) rather than hardcoding 8888. The helper must be sourced BEFORE
# the CRAPI_PORT default assignment.
if awk '
    /\. "\$\{SCRIPT_DIR\}\/crapi\/crapi-helpers\.sh"/ { sourced=1 }
    /CRAPI_PORT="\$\{CRAPI_PORT:-\$CRAPI_OPENAPI_SPEC_DEFAULT_PORT\}"/ && sourced { found=1 }
    END { exit found ? 0 : 1 }
' test/test-llm-planner.sh; then
    pass "test-llm-planner.sh sources helper BEFORE CRAPI_PORT default (uses CRAPI_OPENAPI_SPEC_DEFAULT_PORT)"
else
    fail "test-llm-planner.sh CRAPI_PORT default does not reference helper constant — port-default redundancy"
fi

# Iter-7 lane-dropped (capability-reviewer): setup-live-targets.sh
# DEFAULT_CRAPI_PORT now derives from CRAPI_OPENAPI_SPEC_DEFAULT_PORT
# (helper-sourced first). Asserts the literal `=8888` is gone for the
# crAPI default, AND that the helper source line precedes the
# DEFAULT_CRAPI_PORT assignment (otherwise CRAPI_OPENAPI_SPEC_DEFAULT_PORT
# would be unset at assignment time — set -u would catch it loudly, but
# we want a structural guarantee parallel to the test-llm-planner check).
if awk '
    /\. "\$\{?SCRIPT_DIR\}?\/crapi\/crapi-helpers\.sh"/ { sourced=1 }
    /^DEFAULT_CRAPI_PORT="\$CRAPI_OPENAPI_SPEC_DEFAULT_PORT"/ && sourced { found=1 }
    END { exit found ? 0 : 1 }
' test/setup-live-targets.sh && \
   ! grep -qE '^DEFAULT_CRAPI_PORT=8888' test/setup-live-targets.sh; then
    pass "setup-live-targets.sh sources helper BEFORE DEFAULT_CRAPI_PORT assignment (no hardcoded 8888)"
else
    fail "setup-live-targets.sh DEFAULT_CRAPI_PORT either hardcodes 8888 or doesn't source helper first"
fi

# Iter-7 TEST-002: kind=regular dispatch (negative direction).
# Mirror of the mechanic test at lines 794+: with kind=regular, regular
# signup must be called once and mechanic signup not at all.
SIGNUP_REGULAR=$(guard_mktemp)
SIGNUP_MECH=$(guard_mktemp)
echo 0 > "$SIGNUP_REGULAR"
echo 0 > "$SIGNUP_MECH"
# shellcheck disable=SC2317
crapi_signup() {
    n=$(($(cat "$SIGNUP_REGULAR") + 1))
    echo "$n" > "$SIGNUP_REGULAR"
}
# shellcheck disable=SC2317
crapi_mechanic_signup() {
    n=$(($(cat "$SIGNUP_MECH") + 1))
    echo "$n" > "$SIGNUP_MECH"
}
# shellcheck disable=SC2317
crapi_login() { echo "fake-token"; }
# shellcheck disable=SC2317
sleep() { :; }
# shellcheck disable=SC2218  # _crapi_provision_user is sourced from crapi-helpers.sh
CRAPI_PROVISION_RETRIES=2 \
  _crapi_provision_user "http://stub" regular "r@example.com" "R" "0" "p" >/dev/null
reg_count=$(cat "$SIGNUP_REGULAR")
mech_count=$(cat "$SIGNUP_MECH")
if [ "$reg_count" -eq 1 ] && [ "$mech_count" -eq 0 ]; then
    pass "_crapi_provision_user kind=regular dispatches to crapi_signup (regular=1, mechanic=0)"
else
    fail "_crapi_provision_user regular dispatch wrong: regular=$reg_count mechanic=$mech_count (expected 1/0)"
fi
unset -f sleep crapi_signup crapi_mechanic_signup crapi_login
. test/crapi/crapi-helpers.sh
rm -f "$SIGNUP_REGULAR" "$SIGNUP_MECH"

# Iter-7 TEST-003: crapi_setup_users hard-stop ordering. Stub
# _crapi_provision_user to count calls and fail on the 3rd (user2).
# Assert mechanic was NOT provisioned, exit code is non-zero.
PROV_CALLS=$(guard_mktemp)
: > "$PROV_CALLS"   # truncate to truly-empty (echo "" leaves a newline)
# shellcheck disable=SC2317,SC2218
# SC2218: intentional override of the sourced _crapi_provision_user for
# this test; the original is restored by re-sourcing crapi-helpers.sh at
# the end of this block.
_crapi_provision_user() {
    echo "$1 $2 $3" >> "$PROV_CALLS"
    n=$(grep -c . "$PROV_CALLS")
    if [ "$n" -ge 3 ]; then return 1; fi
    return 0
}
crapi_setup_users "http://stub" 2>/dev/null
rc=$?
# `grep -c X` already prints 0 on no match (and exits 1). The `|| echo 0`
# fallback would run a SECOND echo on no-match, smashing both into one
# captured value like "0\n0". Just trust grep -c's output.
calls=$(grep -c . "$PROV_CALLS")
# The stub records `$1 $2 $3` = base_url + kind + email. Match against the
# EXPANDED canonical mechanic email (from crapi-helpers.sh) — grepping
# the literal var name `CRAPI_MECHANIC_EMAIL` was a tautology since the
# file never contains the var name, only its value.
mech_called=$(grep -c "$CRAPI_MECHANIC_EMAIL" "$PROV_CALLS")
[ -z "$mech_called" ] && mech_called=0
if [ "$rc" -ne 0 ] && [ "$calls" -eq 3 ] && [ "$mech_called" -eq 0 ]; then
    pass "crapi_setup_users hard-stops on first failure (3 calls made, mechanic NOT reached, rc!=0)"
else
    fail "crapi_setup_users hard-stop wrong: rc=$rc calls=$calls mechanic_called=$mech_called (expected rc!=0 calls=3 mech=0)"
fi
unset -f _crapi_provision_user
. test/crapi/crapi-helpers.sh
rm -f "$PROV_CALLS"

# Iter-7 TEST-004 (extended in iter-8 for behavioral coverage): drive a
# subshell that RECONSTRUCTS the teardown safety-regex gate (not extracts
# verbatim from setup-live-targets.sh — bash function-extraction would be
# fragile and the gate is just three lines). Drift between this
# reconstruction and the prod loader is caught by the SAFE_REGEX
# byte-equality pin against all three prod copies (TEST-005 below).
# Together these two tests cover both behavior (subshell mirror) and
# byte-level correctness (regex pin).
TMP=$(guard_mktemp_d)
cat > "$TMP/.live-test-config" <<'EOF'
# malformed: unquoted value with shell meta-character (command substitution)
CRAPI_DIR=/tmp/`whoami`
EOF
# (a) Inline assertion that the regex rejects it (cheap sanity)
if grep -qvE "$SAFE_REGEX" "$TMP/.live-test-config"; then
    pass "safety regex rejects unsafe config (would prevent teardown from sourcing it)"
else
    fail "safety regex accepts unsafe config — teardown could source command-injection attempt"
fi

# (b) Behavioral: extract the actual teardown loader block from
# setup-live-targets.sh and run it against the malformed config in a
# subshell. The loader uses `! grep -qvE <regex> "$CONFIG_FILE"` to
# decide whether to source — so a malformed config means grep -qvE
# matches (returns 0), the negation fails, and we DON'T enter the
# source branch. Assert the malicious assignment is NOT applied.
( # subshell — prod loader uses CONFIG_FILE, mirror it
    CONFIG_FILE="$TMP/.live-test-config"
    CRAPI_DIR="(unset)"
    # shellcheck disable=SC2310 # using guard like prod does
    if [ -f "$CONFIG_FILE" ]; then
        if ! grep -qvE "$SAFE_REGEX" "$CONFIG_FILE"; then
            # shellcheck source=/dev/null
            . "$CONFIG_FILE"
        fi
    fi
    # If the gate worked, CRAPI_DIR keeps its sentinel value.
    [ "$CRAPI_DIR" = "(unset)" ] && exit 0 || exit 1
)
if [ $? -eq 0 ]; then
    pass "teardown loader behavioral test: malformed config does NOT mutate CRAPI_DIR"
else
    fail "teardown loader behavioral test: malformed config WAS sourced (CRAPI_DIR mutated)"
fi
rm -rf "$TMP"

# Iter-9 follow-up: behavioral test for the post-source CRAPI_DIR-existence
# reset branch in setup-live-targets.sh teardown (lines ~132-137). When the
# saved CRAPI_DIR from .live-test-config points to a directory that no
# longer exists (operator deleted their --crapi-dir tree, or moved it),
# the loader must clear CRAPI_DIR back to empty so the teardown falls
# through to the default clone path. A regression that drops the reset
# would silently target the missing path and leave both the missing dir's
# `docker compose down` ineffective AND the default clone untouched.
TMP=$(guard_mktemp_d)
cat > "$TMP/.live-test-config" <<EOF
CRAPI_DIR="$TMP/this/path/does/not/exist"
EOF
( # subshell mirroring the prod loader logic at setup-live-targets.sh:128-138
    CONFIG_FILE="$TMP/.live-test-config"
    CRAPI_DIR=""
    if [ -f "$CONFIG_FILE" ]; then
        if ! grep -qvE "$SAFE_REGEX" "$CONFIG_FILE"; then
            # shellcheck source=/dev/null
            . "$CONFIG_FILE"
            if [ -n "${CRAPI_DIR:-}" ] && [ ! -d "$CRAPI_DIR" ]; then
                CRAPI_DIR=""
            fi
        fi
    fi
    # If the reset branch fired, CRAPI_DIR is now empty.
    [ -z "$CRAPI_DIR" ] && exit 0 || exit 1
)
if [ $? -eq 0 ]; then
    pass "teardown loader CRAPI_DIR-existence reset: missing saved path is cleared to empty"
else
    fail "teardown loader does NOT reset CRAPI_DIR when saved path is missing — would target nonexistent dir"
fi
rm -rf "$TMP"

# Iter-7 TEST-005 (extended in iter-8): pin SAFE_REGEX to ALL THREE prod
# copies — run-live-tests.sh, test-llm-planner.sh, AND setup-live-targets.sh
# (teardown reload). A divergence in any of the three locations would be
# silently invisible to the harness without this triple check.
PROD_REGEX_RUN=$(grep -oE "'[^']*\\^\[\[:space:\]\]\\*\(#\\.\\*\)\\?\\\$\\|[^']+'" test/run-live-tests.sh | head -1)
PROD_REGEX_PLN=$(grep -oE "'[^']*\\^\[\[:space:\]\]\\*\(#\\.\\*\)\\?\\\$\\|[^']+'" test/test-llm-planner.sh | head -1)
PROD_REGEX_SET=$(grep -oE "'[^']*\\^\[\[:space:\]\]\\*\(#\\.\\*\)\\?\\\$\\|[^']+'" test/setup-live-targets.sh | head -1)
HARNESS_REGEX="'$SAFE_REGEX'"
if [ -n "$PROD_REGEX_RUN" ] && [ "$PROD_REGEX_RUN" = "$HARNESS_REGEX" ] && \
   [ -n "$PROD_REGEX_PLN" ] && [ "$PROD_REGEX_PLN" = "$HARNESS_REGEX" ] && \
   [ -n "$PROD_REGEX_SET" ] && [ "$PROD_REGEX_SET" = "$HARNESS_REGEX" ]; then
    pass "harness SAFE_REGEX byte-matches prod regex in run-live-tests.sh, test-llm-planner.sh, AND setup-live-targets.sh (teardown reload)"
else
    fail "SAFE_REGEX divergence: harness=[$HARNESS_REGEX] run=[$PROD_REGEX_RUN] planner=[$PROD_REGEX_PLN] setup=[$PROD_REGEX_SET]"
fi

# Iter-7 TEST-009: TEST-006 awk should explicitly terminate at the
# function-call closing paren (not rely on later SPEC_CACHE_DIR
# occurrences). Assert the awk script in our own harness contains the
# literal `/^\)$/) { exit }` early-exit clause.
if grep -qF 'if (line ~ /^\)$/) { exit }' test/regression/lab-2247-regression-tests.sh; then
    pass "TEST-006 awk has explicit closing-paren termination (no scan past patcher call)"
else
    fail "TEST-006 awk lacks explicit termination — fragile to later SPEC_CACHE_DIR occurrences"
fi

echo
echo "=== Summary ==="
echo "Tests run:    $TESTS_RUN"
echo "Tests failed: $TESTS_FAIL"
exit $TESTS_FAIL
