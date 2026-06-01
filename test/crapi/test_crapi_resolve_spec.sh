#!/usr/bin/env bash
# Unit test for crapi_resolve_spec. Sources the helper directly; no framework.
# Run with: ./test/crapi/test_crapi_resolve_spec.sh
#
# Covers six scenarios for the three branches of crapi_resolve_spec:
#   S1: CRAPI_SPEC_FILE unset           → must re-patch
#   S2: CRAPI_SPEC_FILE set but missing → must re-patch
#   S3: cached spec, port matches       → echo cached path (no copy)
#   S4: substring-match guard: port=889 must NOT accept localhost:8895
#   S5: cached spec, port matches (idempotent: call twice, same path)
#   S6: crapi_patch_openapi_spec fails (missing source) → non-zero exit
set -u  # NOT -e: we want to catch failed assertions and keep going.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=crapi-helpers.sh
. "${SCRIPT_DIR}/crapi-helpers.sh"

TMPDIR_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/test_crapi_resolve_spec.XXXXXX")
trap 'rm -rf "$TMPDIR_ROOT"' EXIT

pass=0; fail=0

assert_eq() {  # assert_eq <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "  PASS: $1"
        pass=$((pass + 1))
    else
        echo "  FAIL: $1 — expected [$2], got [$3]"
        fail=$((fail + 1))
    fi
}

assert_nonzero() {  # assert_nonzero <label> <exit_code>
    if [ "$2" -ne 0 ]; then
        echo "  PASS: $1"
        pass=$((pass + 1))
    else
        echo "  FAIL: $1 — expected non-zero exit, got 0"
        fail=$((fail + 1))
    fi
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
SRC_SPEC="${TMPDIR_ROOT}/spec-default.json"
CACHED_8888="${TMPDIR_ROOT}/cached-8888.json"
CACHED_8895="${TMPDIR_ROOT}/cached-8895.json"

printf '{"servers":[{"url":"http://localhost:8888"}]}' > "$SRC_SPEC"
printf '{"servers":[{"url":"http://localhost:8888"}]}' > "$CACHED_8888"
printf '{"servers":[{"url":"http://localhost:8895"}]}' > "$CACHED_8895"

# ---------------------------------------------------------------------------
# S1: CRAPI_SPEC_FILE unset → must re-patch into cache
# ---------------------------------------------------------------------------
echo "S1: CRAPI_SPEC_FILE unset → re-patch"
unset CRAPI_SPEC_FILE
out=$(crapi_resolve_spec "$SRC_SPEC" 9999 "${TMPDIR_ROOT}/cache-s1" 2>/dev/null); rc=$?
assert_eq    "S1 exit 0"             "0"                                          "$rc"
assert_eq    "S1 echoes patched path" "${TMPDIR_ROOT}/cache-s1/crapi-openapi-spec.json" "$out"
# Path-only assertions can't catch a resolver that returns the right path but a
# wrongly-patched (or unpatched) file — assert the spec content carries the port.
assert_eq    "S1 spec patched to port 9999" "localhost:9999" "$(grep -oE 'localhost:[0-9]+' "$out" | head -1)"

# ---------------------------------------------------------------------------
# S2: CRAPI_SPEC_FILE set but file missing → must re-patch
# ---------------------------------------------------------------------------
echo "S2: CRAPI_SPEC_FILE set but missing on disk → re-patch"
export CRAPI_SPEC_FILE="${TMPDIR_ROOT}/does-not-exist.json"
out=$(crapi_resolve_spec "$SRC_SPEC" 9999 "${TMPDIR_ROOT}/cache-s2" 2>/dev/null); rc=$?
assert_eq    "S2 exit 0"             "0"                                          "$rc"
assert_eq    "S2 echoes patched path" "${TMPDIR_ROOT}/cache-s2/crapi-openapi-spec.json" "$out"
assert_eq    "S2 spec patched to port 9999" "localhost:9999" "$(grep -oE 'localhost:[0-9]+' "$out" | head -1)"

# ---------------------------------------------------------------------------
# S3: cached spec exists and port matches exactly → echo cached path unchanged
# ---------------------------------------------------------------------------
echo "S3: cached spec matches port → echo cached path (no copy)"
export CRAPI_SPEC_FILE="$CACHED_8888"
out=$(crapi_resolve_spec "$SRC_SPEC" 8888 "${TMPDIR_ROOT}/cache-s3" 2>/dev/null); rc=$?
assert_eq    "S3 exit 0"             "0"             "$rc"
assert_eq    "S3 echoes cached path" "$CACHED_8888"  "$out"

# ---------------------------------------------------------------------------
# S4: port=889 must NOT accept a stale spec pinned to localhost:8895
#     This is the ([^0-9]|$) anchor regression test.
# ---------------------------------------------------------------------------
echo "S4: substring guard — port=889 must not accept localhost:8895"
export CRAPI_SPEC_FILE="$CACHED_8895"
out=$(crapi_resolve_spec "$SRC_SPEC" 889 "${TMPDIR_ROOT}/cache-s4" 2>/dev/null); rc=$?
assert_eq    "S4 exit 0"             "0"            "$rc"
assert_eq    "S4 echoes patched path" "${TMPDIR_ROOT}/cache-s4/crapi-openapi-spec.json" "$out"
# Re-patched to 889 from the SRC spec (8888), NOT the stale cached 8895.
assert_eq    "S4 spec patched to port 889" "localhost:889" "$(grep -oE 'localhost:[0-9]+' "$out" | head -1)"

# ---------------------------------------------------------------------------
# S5: cached spec, port matches → idempotent (call twice, same path returned)
# ---------------------------------------------------------------------------
echo "S5: idempotent — call twice with matching port, same path each time"
export CRAPI_SPEC_FILE="$CACHED_8888"
out1=$(crapi_resolve_spec "$SRC_SPEC" 8888 "${TMPDIR_ROOT}/cache-s5" 2>/dev/null)
out2=$(crapi_resolve_spec "$SRC_SPEC" 8888 "${TMPDIR_ROOT}/cache-s5" 2>/dev/null)
assert_eq    "S5 first call echoes cached"  "$CACHED_8888" "$out1"
assert_eq    "S5 second call same path"     "$out1"        "$out2"

# ---------------------------------------------------------------------------
# S6: crapi_patch_openapi_spec fails (missing source spec) → non-zero exit
# ---------------------------------------------------------------------------
echo "S6: missing source spec → non-zero exit"
unset CRAPI_SPEC_FILE
out=$(crapi_resolve_spec "${TMPDIR_ROOT}/nonexistent-src.json" 9999 "${TMPDIR_ROOT}/cache-s6" 2>/dev/null); rc=$?
assert_nonzero "S6 missing source returns non-zero" "$rc"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit $(( fail > 0 ? 1 : 0 ))
