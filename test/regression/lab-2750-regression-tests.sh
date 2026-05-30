#!/usr/bin/env bash
# =============================================================================
# lab-2750-regression-tests.sh
#
# Regression harness for LAB-2750
# (https://linear.app/praetorianlabs/issue/LAB-2750).
#
# LAB-2750 replaced the two Docker-based live-test targets (crAPI, DVGA) with
# in-house Go binaries (test/vulnerable-rest-complex, test/vulnerable-graphql)
# so the full suite runs in a fresh devcontainer with no Docker daemon.
#
# This harness asserts the **shape** of that change without booting anything:
#   1. No Docker / crAPI-clone references survive in the two harness scripts.
#   2. The old crapi/ and dvga/ directories are gone.
#   3. The four in-house Go targets exist and are wired into the defaults.
#   4. The generic port helpers (relocated to test/lib/port-helpers.sh)
#      still behave correctly — these survived the crAPI removal because every
#      Go target shares them.
#   5. .live-test-config still matches the quoted-value safety regex.
#
# This is the "LAB-2247 re-evaluation" the ticket calls for: the LAB-2247
# regression harness tested crAPI compose-patching, crAPI user provisioning,
# and Docker teardown — all removed by LAB-2750 — so it was retired and the
# still-relevant generic port-helper assertions were carried over here.
#
# Usage (from repo root):
#     bash test/regression/lab-2750-regression-tests.sh
#
# Exits 0 on full pass, non-zero on any failure.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAFE_REGEX='^[[:space:]]*(#.*)?$|^[A-Za-z_][A-Za-z0-9_]*="[A-Za-z0-9_./:@,+ -]*"$'
TESTS_RUN=0
TESTS_FAIL=0

pass() { echo "  PASS: $1"; TESTS_RUN=$((TESTS_RUN+1)); }
fail() { echo "  FAIL: $1"; TESTS_RUN=$((TESTS_RUN+1)); TESTS_FAIL=$((TESTS_FAIL+1)); }

guard_mktemp_d() {
    local v
    v=$(mktemp -d "$@") || { fail "FATAL: mktemp -d failed"; exit 1; }
    [ -n "$v" ] && [ -d "$v" ] || { fail "FATAL: mktemp -d produced unusable path: $v"; exit 1; }
    echo "$v"
}

cd "$ROOT" || { echo "FATAL: cannot cd to $ROOT" >&2; exit 1; }

echo "=== LAB-2750: no Docker references remain in the harness scripts ==="
for f in test/setup-live-targets.sh test/run-live-tests.sh; do
    if grep -qiE 'docker|docker compose|docker-compose' "$f"; then
        fail "$f still references Docker"
        grep -niE 'docker' "$f" | head
    else
        pass "$f has no Docker references"
    fi
done

echo
echo "=== LAB-2750: no crapi/dvga/.crapi-repo clone references remain ==="
for f in test/setup-live-targets.sh test/run-live-tests.sh; do
    if grep -qiE 'crapi|dvga|\.crapi-repo|OWASP/crAPI|dolevf/dvga|git clone' "$f"; then
        fail "$f still references crapi/dvga/clone logic"
        grep -niE 'crapi|dvga|git clone' "$f" | head
    else
        pass "$f free of crapi/dvga/clone references"
    fi
done

echo
echo "=== LAB-2750: old Docker target directories are removed ==="
for d in test/crapi test/dvga test/.crapi-repo; do
    if [ -e "$d" ]; then
        fail "$d still exists (should be removed)"
    else
        pass "$d removed"
    fi
done

echo
echo "=== LAB-2750: four in-house Go targets exist with their own go.mod ==="
for t in vulnerable-api vulnerable-graphql grpc-server vulnerable-rest-complex; do
    if [ -f "test/$t/go.mod" ] && [ -f "test/$t/main.go" ]; then
        pass "test/$t is a self-contained Go target"
    else
        fail "test/$t is missing go.mod or main.go"
    fi
done

echo
echo "=== LAB-2750: harness defaults list the four Go targets ==="
EXPECTED='vulnerable-api,vulnerable-graphql,grpc,vulnerable-rest-complex'
for f in test/setup-live-targets.sh test/run-live-tests.sh; do
    if grep -qF "TARGETS=\"$EXPECTED\"" "$f"; then
        pass "$f default TARGETS is the four Go targets"
    else
        fail "$f default TARGETS is not '$EXPECTED'"
    fi
done

echo
echo "=== LAB-2750: vulnerable-graphql runs WITHOUT --skip-builtin-checks ==="
# The in-house GraphQL target deliberately enables introspection and applies
# no depth/alias limits so the built-in checks (introspection, alias-DoS,
# field duplication) fire. The old DVGA flow skipped them.
# Scope the scan to the run_hadrian "vulnerable-graphql" invocation block only
# (a backslash-continued command), so a --skip-builtin-checks added to a later
# target can't be mis-attributed to the graphql check.
if awk '
    /run_hadrian "vulnerable-graphql"/ { inblock=1 }
    inblock && /--skip-builtin-checks/ { found=1 }
    inblock && !/\\[[:space:]]*$/ { inblock=0 }
    END { exit found ? 1 : 0 }
' test/run-live-tests.sh; then
    pass "graphql target invocation does not pass --skip-builtin-checks"
else
    fail "graphql target still passes --skip-builtin-checks (built-in checks suppressed)"
fi

echo
echo "=== LAB-2750: generic port helpers relocated to test/lib/port-helpers.sh ==="
if [ -f test/lib/port-helpers.sh ]; then
    pass "test/lib/port-helpers.sh exists"
else
    fail "test/lib/port-helpers.sh missing"
fi
if grep -q 'lib/port-helpers.sh' test/setup-live-targets.sh; then
    pass "setup-live-targets.sh sources test/lib/port-helpers.sh"
else
    fail "setup-live-targets.sh does NOT source test/lib/port-helpers.sh"
fi
# The crAPI-specific compose patcher must NOT have come along for the ride.
if grep -q 'patch_crapi_compose_port' test/lib/port-helpers.sh; then
    fail "test/lib/port-helpers.sh still defines patch_crapi_compose_port (crAPI-specific)"
else
    pass "test/lib/port-helpers.sh dropped the crAPI compose patcher"
fi

echo
echo "=== LAB-2750: relocated port helpers still behave correctly ==="
# log_* stubs so the sourced helpers don't pollute output.
# shellcheck disable=SC2317
log_info()  { :; }
# shellcheck disable=SC2317
log_ok()    { :; }
# shellcheck disable=SC2317
log_warn()  { :; }
# shellcheck disable=SC2317
log_fail()  { :; }

# shellcheck source=test/lib/port-helpers.sh
. test/lib/port-helpers.sh

for fn in port_in_use _port_excluded find_available_port resolve_target_port; do
    if declare -F "$fn" >/dev/null; then
        pass "port-helpers exports $fn"
    else
        fail "port-helpers missing $fn"
    fi
done

# find_available_port skips ports already claimed in this run.
port_in_use() { [ "$1" = "8888" ]; }   # simulate something holding 8888
claimed=()
v=$(find_available_port 9889 "${claimed[@]+${claimed[@]}}")
claimed+=("$v")
c=$(find_available_port 8888 "${claimed[@]+${claimed[@]}}")
claimed+=("$c")
if [ -n "$v" ] && [ -n "$c" ] && [ "$v" != "$c" ]; then
    pass "find_available_port hands out distinct ports ($v, $c) with 8888 simulated taken"
else
    fail "port collision: a=$v b=$c"
fi

# resolve_target_port honors a free override.
out=$(resolve_target_port 9999 8888 "test" "${claimed[@]+${claimed[@]}}")
if [ "$out" = "9999" ]; then
    pass "resolve_target_port honors a free, unclaimed override"
else
    fail "resolve_target_port did not honor free override (got: $out)"
fi

# resolve_target_port rejects an OS-busy override.
log_fail_msg=""
log_fail() { log_fail_msg="$*"; }
if ! resolve_target_port 8888 9999 "test" "${claimed[@]+${claimed[@]}}" >/dev/null 2>&1; then
    if echo "$log_fail_msg" | grep -q "already in use"; then
        pass "resolve_target_port rejects an override that's in use on the host"
    else
        fail "resolve_target_port rejected busy override but message unexpected: $log_fail_msg"
    fi
else
    fail "resolve_target_port silently accepted a busy override port"
fi
# shellcheck disable=SC2317
log_fail() { :; }
unset log_fail_msg
unset -f port_in_use

# find_available_port walk-forward exhaustion.
port_in_use() { return 0; }   # everything "busy"
out=$(find_available_port 8888)
rc=$?
unset -f port_in_use
if [ -z "$out" ] && [ "$rc" -ne 0 ]; then
    pass "find_available_port returns empty + non-zero when the 20-port walk exhausts"
else
    fail "find_available_port exhaustion mismatch: rc=$rc out=[$out]"
fi

# port_in_use ss flag (when ss is the available probe) covers all states.
if grep -qE 'ss -atn \| grep -q' test/lib/port-helpers.sh && \
   ! grep -qE 'ss -[lt]+n[[:space:]]*\| grep' test/lib/port-helpers.sh; then
    pass "port_in_use uses ss -atn (covers LISTEN + non-LISTEN, matches lsof)"
else
    fail "port_in_use ss flag regressed; expected -atn"
fi

echo
echo "=== LAB-2750: *_PORT_OVERRIDE env vars are honored by setup ==="
if grep -qE 'VULN_API_PORT_OVERRIDE|VULN_GRAPHQL_PORT_OVERRIDE|VULN_REST_COMPLEX_PORT_OVERRIDE' test/setup-live-targets.sh; then
    pass "setup recognizes the new *_PORT_OVERRIDE env vars"
else
    fail "setup does not implement the *_PORT_OVERRIDE env vars"
fi

echo
echo "=== LAB-2750 (carried from LAB-2247): vulnerable-api default port is 9889 ==="
if grep -q 'port = "9889"' test/vulnerable-api/main.go; then
    pass "vulnerable-api/main.go default is 9889"
else
    fail "vulnerable-api/main.go default is not 9889"
fi
if grep -q 'localhost:9889' test/vulnerable-api/openapi.yaml; then
    pass "vulnerable-api openapi.yaml advertises 9889"
else
    fail "vulnerable-api openapi.yaml does not advertise 9889"
fi

echo
echo "=== LAB-2750: .live-test-config (new var set) matches safety regex ==="
TMP=$(guard_mktemp_d)
cat > "$TMP/config" <<'EOF'
# Auto-generated by setup-live-targets.sh on 2026-05-28T00:00:00Z
VULN_API_PORT="9889"
VULN_GRAPHQL_PORT="5013"
GRPC_PORT="50051"
VULN_REST_COMPLEX_PORT="8888"
EOF
if grep -qvE "$SAFE_REGEX" "$TMP/config"; then
    fail ".live-test-config has lines that fail the safety regex"
    grep -vE "$SAFE_REGEX" "$TMP/config"
else
    pass ".live-test-config (quoted format) passes safety regex"
fi
# Unquoted value with a space must still be rejected (injection guard).
echo 'VULN_API_PORT=99 89' > "$TMP/bad"
if grep -qvE "$SAFE_REGEX" "$TMP/bad"; then
    pass "unquoted value with a space is rejected (injection guard intact)"
else
    fail "safety regex accepts an unquoted value with a space — injection guard broken"
fi
rm -rf "$TMP"

echo
echo "=== Summary ==="
echo "  Ran:    $TESTS_RUN"
echo "  Failed: $TESTS_FAIL"
if [ "$TESTS_FAIL" -gt 0 ]; then
    exit 1
fi
echo "  All LAB-2750 regression checks passed."
