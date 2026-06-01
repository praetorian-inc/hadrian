#!/usr/bin/env bash
# Unit test for crapi_planner_inputs_ready. Sources the helper directly; no
# framework. Run with: ./test/crapi/test_crapi_planner_inputs.sh
#
# crapi_planner_inputs_ready gates the crapi-planner SKIP decision in
# run-live-tests.sh. It returns 0 (ready) iff the crapi target PASSed AND both
# the auth file and the spec file exist on disk. Covers every branch:
#   G1: PASS + both files exist            → ready (0)
#   G2: status != PASS (SKIP)              → not ready (1)
#   G3: status != PASS (ERROR)             → not ready (1)
#   G4: PASS but auth file empty path      → not ready (1)
#   G5: PASS but auth file missing on disk → not ready (1)
#   G6: PASS but spec file empty path      → not ready (1)
#   G7: PASS but spec file missing on disk → not ready (1)
set -u  # NOT -e: we want to catch failed assertions and keep going.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=crapi-helpers.sh
. "${SCRIPT_DIR}/crapi-helpers.sh"

TMPDIR_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/test_crapi_planner_inputs.XXXXXX")
trap 'rm -rf "$TMPDIR_ROOT"' EXIT

pass=0; fail=0

assert_ready() {  # assert_ready <label> — expects the following call to return 0
    if "$@"; then
        echo "  PASS: $LABEL"
        pass=$((pass + 1))
    else
        echo "  FAIL: $LABEL — expected ready (exit 0), got $?"
        fail=$((fail + 1))
    fi
}

assert_not_ready() {  # runs the predicate, expects non-zero
    if "$@"; then
        echo "  FAIL: $LABEL — expected not-ready (non-zero), got 0"
        fail=$((fail + 1))
    else
        echo "  PASS: $LABEL"
        pass=$((pass + 1))
    fi
}

# Fixtures: a real auth file and spec file on disk.
AUTH="${TMPDIR_ROOT}/auth.yaml"; : > "$AUTH"
SPEC="${TMPDIR_ROOT}/spec.json"; : > "$SPEC"
MISSING="${TMPDIR_ROOT}/nope.json"

echo "G1: PASS + both files exist → ready"
LABEL="G1 ready when crapi PASSed and files present"
assert_ready     crapi_planner_inputs_ready "PASS" "$AUTH" "$SPEC"

echo "G2: status SKIP → not ready"
LABEL="G2 not ready when crapi SKIPped"
assert_not_ready crapi_planner_inputs_ready "SKIP" "$AUTH" "$SPEC"

echo "G3: status ERROR → not ready"
LABEL="G3 not ready when crapi ERRORed"
assert_not_ready crapi_planner_inputs_ready "ERROR" "$AUTH" "$SPEC"

echo "G4: PASS but empty auth path → not ready"
LABEL="G4 not ready when auth path empty"
assert_not_ready crapi_planner_inputs_ready "PASS" "" "$SPEC"

echo "G5: PASS but auth file missing → not ready"
LABEL="G5 not ready when auth file missing on disk"
assert_not_ready crapi_planner_inputs_ready "PASS" "$MISSING" "$SPEC"

echo "G6: PASS but empty spec path → not ready"
LABEL="G6 not ready when spec path empty"
assert_not_ready crapi_planner_inputs_ready "PASS" "$AUTH" ""

echo "G7: PASS but spec file missing → not ready"
LABEL="G7 not ready when spec file missing on disk"
assert_not_ready crapi_planner_inputs_ready "PASS" "$AUTH" "$MISSING"

echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit $(( fail > 0 ? 1 : 0 ))
