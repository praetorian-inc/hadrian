#!/usr/bin/env bash
# Unit test for crapi_patch_openapi_spec. Sources the helper directly; no framework.
# Run with: ./test/crapi/test_crapi_patch_openapi_spec.sh
#
# Covers four scenarios for crapi_patch_openapi_spec:
#   A1: target_port == default port → echoes src path unchanged, no copy written
#   A2: target_port != default port → writes patched copy at dest_dir/crapi-openapi-spec.json
#       with localhost:<default> replaced by localhost:<target>
#   A3: source spec missing the localhost:<default> token → returns non-zero
#       AND removes the partial copy
#   A4: source spec file does not exist → returns non-zero (early guard)
set -u  # NOT -e: we want to catch failed assertions and keep going.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=crapi-helpers.sh
. "${SCRIPT_DIR}/crapi-helpers.sh"

TMPDIR_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/test_crapi_patch_openapi_spec.XXXXXX")
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

assert_file_absent() {  # assert_file_absent <label> <path>
    if [ ! -f "$2" ]; then
        echo "  PASS: $1"
        pass=$((pass + 1))
    else
        echo "  FAIL: $1 — expected file to be absent: $2"
        fail=$((fail + 1))
    fi
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
DEFAULT_PORT="$CRAPI_OPENAPI_SPEC_DEFAULT_PORT"  # 8888
NONDEFAULT_PORT="9999"

# Spec containing the default port token (normal case).
SRC_DEFAULT="${TMPDIR_ROOT}/spec-default.json"
printf '{"servers":[{"url":"http://localhost:%s"}]}' "$DEFAULT_PORT" > "$SRC_DEFAULT"

# Spec that does NOT contain the default port token (broken upstream case).
SRC_NO_TOKEN="${TMPDIR_ROOT}/spec-no-token.json"
printf '{"servers":[{"url":"http://example.com"}]}' > "$SRC_NO_TOKEN"

# ---------------------------------------------------------------------------
# A1: target_port == default → echoes src path unchanged, no copy
# ---------------------------------------------------------------------------
echo "A1: target_port == default → echo src unchanged, no dest written"
dest_a1="${TMPDIR_ROOT}/dest-a1"
out=$(crapi_patch_openapi_spec "$SRC_DEFAULT" "$DEFAULT_PORT" "$dest_a1" 2>/dev/null); rc=$?
assert_eq    "A1 exit 0"          "0"          "$rc"
assert_eq    "A1 echoes src path" "$SRC_DEFAULT" "$out"
assert_file_absent "A1 no copy written" "${dest_a1}/crapi-openapi-spec.json"
assert_eq "A1 no dest_dir created" "false" "$([ -e "$dest_a1" ] && echo true || echo false)"

# ---------------------------------------------------------------------------
# A2: target_port != default → patched copy at dest_dir/crapi-openapi-spec.json
#     with the substitution applied
# ---------------------------------------------------------------------------
echo "A2: target_port != default → write patched copy with correct port"
dest_a2="${TMPDIR_ROOT}/dest-a2"
out=$(crapi_patch_openapi_spec "$SRC_DEFAULT" "$NONDEFAULT_PORT" "$dest_a2" 2>/dev/null); rc=$?
expected_dst="${dest_a2}/crapi-openapi-spec.json"
assert_eq "A2 exit 0"              "0"            "$rc"
assert_eq "A2 echoes dest path"    "$expected_dst" "$out"
# Confirm the substitution landed in the file.
if grep -q "localhost:${NONDEFAULT_PORT}" "$expected_dst" 2>/dev/null; then
    echo "  PASS: A2 patched port present in dest"
    pass=$((pass + 1))
else
    echo "  FAIL: A2 patched port NOT found in dest"
    fail=$((fail + 1))
fi
# Confirm the old port is gone.
if ! grep -q "localhost:${DEFAULT_PORT}" "$expected_dst" 2>/dev/null; then
    echo "  PASS: A2 default port absent from dest"
    pass=$((pass + 1))
else
    echo "  FAIL: A2 default port still present in dest"
    fail=$((fail + 1))
fi

# ---------------------------------------------------------------------------
# A3: source spec missing localhost:<default> token → non-zero AND no partial copy
# ---------------------------------------------------------------------------
echo "A3: source spec missing default-port token → non-zero, partial copy removed"
dest_a3="${TMPDIR_ROOT}/dest-a3"
out=$(crapi_patch_openapi_spec "$SRC_NO_TOKEN" "$NONDEFAULT_PORT" "$dest_a3" 2>/dev/null); rc=$?
assert_nonzero "A3 returns non-zero"          "$rc"
assert_file_absent "A3 partial copy removed" "${dest_a3}/crapi-openapi-spec.json"

# ---------------------------------------------------------------------------
# A4: source spec file does not exist → non-zero (early guard)
# ---------------------------------------------------------------------------
echo "A4: source spec does not exist → non-zero"
dest_a4="${TMPDIR_ROOT}/dest-a4"
out=$(crapi_patch_openapi_spec "${TMPDIR_ROOT}/nonexistent.json" "$NONDEFAULT_PORT" "$dest_a4" 2>/dev/null); rc=$?
assert_nonzero "A4 missing src returns non-zero" "$rc"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit $(( fail > 0 ? 1 : 0 ))
